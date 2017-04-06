# need 3.0 for multiple line strings
cmake_minimum_required(VERSION 3.0)
project(mbedtls_sgx)

set(SGX_SDK /opt/intel/sgxsdk)
set(SGX_ARCH x64)
set(SGX_MODE SIM) # SGX mode: sim, hw
# build mode: debug OR prerelease (NOT BOTH)
set(SGX_DEBUG FALSE)
set(SGX_PRERELEASE TRUE)

include (cmake/Init.cmake)
include (cmake/ConfigSGX.cmake)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(src)
add_subdirectory(untrusted)

add_subdirectory(example/linux)