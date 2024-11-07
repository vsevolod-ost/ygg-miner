cmake_minimum_required(VERSION 3.5.0)
project(ygg-miner VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_COMPILER "clang")

add_executable(ygg-miner main.c)
target_compile_options(ygg-miner PUBLIC -xc -std=c17 -fopenmp -Ofast)
target_link_options(ygg-miner PUBLIC -flto=full -Ofast -s -fopenmp -lsodium -lm)
