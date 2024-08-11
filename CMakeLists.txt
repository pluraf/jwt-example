cmake_minimum_required(VERSION 3.30)

project(jwt)

set(CMAKE_C_STANDARD 99)

set(SOURCE_DIR "${CMAKE_SOURCE_DIR}/src")

file(GLOB_RECURSE SOURCES "${SOURCE_DIR}/*.c")

find_package(OpenSSL REQUIRED)

include_directories(${SOURCE_DIR})

# "openssl/include/internal" "openssl/include" "openssl/crypto/bn" "openssl/crypto"

add_definitions(-DWITH_SHA256)
add_definitions(-DTHIRTYTWO_BIT_PROCESSOR)
add_definitions(-DSECP256R1)

add_executable(jwt ${SOURCES})

target_link_libraries(jwt OpenSSL::SSL OpenSSL::Crypto)