cmake_minimum_required(VERSION 3.26)
# 设置交叉编译工具链
set(ANDROID_NDK C:/Users/Ccccccccvm/AppData/Local/Android/Sdk/ndk/25.1.8937393)
set(CMAKE_TOOLCHAIN_FILE ${ANDROID_NDK}/build/cmake/android.toolchain.cmake)

set(ANDROID_ABI "arm64-v8a")
set(ANDROID_PLATFORM 29)

add_definitions(-DHAVE_SECCOMP_FILTER)

project(CvmSeccomp C)

set(CMAKE_C_STANDARD 11)

add_library(CvmSeccomp SHARED library.c)
find_library(log-lib log)
target_link_libraries(CvmSeccomp ${log-lib})