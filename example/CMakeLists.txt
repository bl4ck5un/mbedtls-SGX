# need 3.0 for multiple line strings
#cmake_minimum_required(VERSION 3.0)

#set(SGX_SDK /opt/intel/sgxsdk)
#set(SGX_ARCH x64)
#set(SGX_MODE SIM) # SGX mode: sim, hw
# build mode: debug OR prerelease (NOT BOTH)
#set(SGX_DEBUG TRUE)
#set(SGX_PRERELEASE FALSE)

#include (../../cmake/Init.cmake)
#include (../../cmake/ConfigSGX.cmake)

#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
#set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

get_filename_component(MBEDTLS_SGX_ROOT_DIR ".." REALPATH BASE_DIR "${CMAKE_BINARY_DIR}")

add_subdirectory(tls)
add_subdirectory(enclave)
