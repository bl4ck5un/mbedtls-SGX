# need 3.0 for multiple line strings
cmake_minimum_required(VERSION 3.0)
project(mbedtls_SGX "C" "CXX")

set(MBEDTLS_VERSION 2.6.0)

set(SGX_SDK /opt/intel/sgxsdk)
set(SGX_ARCH x64)
set(SGX_MODE SIM CACHE STRING "SGX mode: SIM or HW") # SGX mode: sim, hw
set(COMPILE_EXAMPLES NO CACHE BOOL "Build examples")
set(SGX_BUILD DEBUG CACHE STRING "Build: DEBUG, PRERELEASE or RELEASE")

include (cmake/Init.cmake)
include (cmake/ConfigSGX.cmake)

set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/${PROJECT_NAME}-${MBEDTLS_VERSION})

set(MBEDTLS_LIB_DIR ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})

add_subdirectory(trusted)
add_subdirectory(ocall)

if (COMPILE_EXAMPLES)
    add_subdirectory(example)
endif()
