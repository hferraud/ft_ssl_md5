cmake_minimum_required(VERSION 3.22.1)

project(ft_ssl C)

set(CMAKE_C_STANDARD 23)

add_executable(ft_ssl
        src/md5/crypto.c
        src/md5/crypto.h
)

target_sources(ft_ssl PRIVATE
        src/main.c
        src/md5/md5.c
        src/md5/parser.c
        src/sha256/sha256.c
        src/sha256/parser.c
        src/sha256/crypto.c
)

target_include_directories(ft_ssl PRIVATE
        include
)

target_compile_options(ft_ssl PUBLIC
        -Wall
        -Werror
        -Wextra
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(ft_ssl PRIVATE
            -g3
    )
endif()
