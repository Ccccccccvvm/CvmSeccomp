cmake_minimum_required(VERSION 3.26)
project(CvmSeccomp C)

set(CMAKE_C_STANDARD 11)

add_library(CvmSeccomp SHARED library.c)
