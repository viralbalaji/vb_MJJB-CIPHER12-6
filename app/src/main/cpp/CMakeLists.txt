cmake_minimum_required(VERSION 3.22.1)

project("mjjbcipher")

add_library(
    mjjbcipher
    SHARED
    mjjb_cipher.cpp
)

find_library(log-lib log)

target_link_libraries(
    mjjbcipher
    ${log-lib}
)

target_compile_options(mjjbcipher PRIVATE -std=c++17 -O2)
