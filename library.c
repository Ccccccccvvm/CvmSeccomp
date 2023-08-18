#include "library.h"

#include <stdio.h>
#include <android/log.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/signal.h>
#include <unistd.h>
#include <linux/prctl.h>
#include <sys/prctl.h>

#define SECMAGIC 0xE8D4A50FFF
#define TAG "CvmSeccomp"

void hello(void) {
    printf("Hello, World!\n");
}

uint64_t
OriSyscall(uint64_t num, uint64_t SYSARG_1, uint64_t SYSARG_2, uint64_t SYSARG_3,
           uint64_t SYSARG_4, uint64_t SYSARG_5,
           uint64_t SYSARG_6) {
    uint64_t x0;
    __asm__ volatile (
            "mov x8, %1\n\t"
            "mov x0, %2\n\t"
            "mov x1, %3\n\t"
            "mov x2, %4\n\t"
            "mov x3, %5\n\t"
            "mov x4, %6\n\t"
            "mov x5, %7\n\t"
            "svc #0\n\t"
            "mov %0, x0\n\t"
            :"=r"(x0)
            :"r"(num), "r"(SYSARG_1), "r"(SYSARG_2), "r"(SYSARG_3), "r"(SYSARG_4), "r"(SYSARG_5), "r"(SYSARG_6)
            :"x8", "x0", "x1", "x2", "x3", "x4", "x4", "x5"
            );
    return x0;

}

void sig_handler(int signo, siginfo_t *info, void *data) {
    int my_signo = info->si_signo;
    unsigned long syscall_number = ((ucontext_t *) data)->uc_mcontext.regs[8];
    unsigned long SYSARG_1 = ((ucontext_t *) data)->uc_mcontext.regs[0];
    unsigned long SYSARG_2 = ((ucontext_t *) data)->uc_mcontext.regs[1];
    unsigned long SYSARG_3 = ((ucontext_t *) data)->uc_mcontext.regs[2];
    unsigned long SYSARG_4 = ((ucontext_t *) data)->uc_mcontext.regs[3];
    unsigned long SYSARG_5 = ((ucontext_t *) data)->uc_mcontext.regs[4];
    unsigned long SYSARG_6 = ((ucontext_t *) data)->uc_mcontext.regs[5];
    switch (syscall_number) {
        default:
            break;

        case __NR_openat: {
            char *path = (char *) SYSARG_2;
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "__NR_openat path = %s", path);
            ((ucontext_t *) data)->uc_mcontext.regs[0] = OriSyscall(__NR_openat, SYSARG_1, SYSARG_2, SYSARG_3, SYSARG_4,
                                                                    SECMAGIC, SECMAGIC);
            break;
        }

        case __NR_fstat: {
            char TmePath[PATH_MAX];
            snprintf(TmePath, sizeof(TmePath), "/proc/self/fd/%d", SYSARG_1);
            readlink(TmePath, TmePath, PATH_MAX);
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "__NR_fstat path = %s", TmePath);
            ((ucontext_t *) data)->uc_mcontext.regs[0] = OriSyscall(__NR_fstat, SYSARG_1, SYSARG_2, SECMAGIC, SECMAGIC,
                                                                    SECMAGIC, SECMAGIC);

            break;
        }


    }

}

__attribute__((__constructor__)) void InitCvmSeccomp() {
    struct sock_filter filter[] = {
//            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
//            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_newfstatat, 0, 2),
//            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[5])),
//            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECMAGIC, 16, 17),
//
//            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
//            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_statfs, 0, 2),
//            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4])),
//            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECMAGIC, 12, 13),
//
//            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
//            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_faccessat, 0, 2),
//            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4])),
//            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECMAGIC, 8, 9),

            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fstat, 0, 2),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECMAGIC, 4, 5), //判断args[2] 是否等于 SECMAGIC 等于则不拦截 跳到 SECCOMP_RET_ALLOW

            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 2),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4])),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECMAGIC, 0, 1),//判断args[4] 是否等于 SECMAGIC 等于则不拦截 跳到 SECCOMP_RET_ALLOW

            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP)// Results in the kernel sending a SIGSYS signal
    };
    struct sock_fprog prog;
    prog.filter = filter;
    prog.len = (unsigned short) (sizeof(filter) / sizeof(filter[0]));
    struct sigaction sa;
    sigset_t sigset;
    sigfillset(&sigset);
    sa.sa_sigaction = sig_handler;
    sa.sa_mask = sigset;
    sa.sa_flags = SA_SIGINFO;

    if (sigaction(SIGSYS, &sa, NULL) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "InitCvmSeccomp Fail");
        return;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "InitCvmSeccomp Fail");
        return;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "InitCvmSeccomp Fail");
        return;
    }
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "InitCvmSeccomp Successes");
}