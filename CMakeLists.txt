# need 3.0 for multiple line strings
cmake_minimum_required(VERSION 3.0)
project(mbedtls_SGX "C" "CXX")

set(MBEDTLS_VERSION 2.17.0)

set(SGX_SDK /opt/intel/sgxsdk)
set(SGX_ARCH x64)
set(SGX_MODE SIM CACHE STRING "SGX mode: SIM or HW") # SGX mode: sim, hw
set(COMPILE_EXAMPLES NO CACHE BOOL "Build examples")
set(SGX_BUILD DEBUG CACHE STRING "Build: DEBUG, PRERELEASE or RELEASE")

include (cmake/Init.cmake)
include (cmake/ConfigSGX.cmake)

set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/${PROJECT_NAME}-${MBEDTLS_VERSION})

set(MBEDTLS_LIB_DIR ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})

# Create a symbolic link from ${base_name} in the binary directory
# to the corresponding path in the source directory.
function(link_to_source base_name)
    # Get OS dependent path to use in `execute_process`
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_BINARY_DIR}/${base_name}" link)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/${base_name}" target)

    if (NOT EXISTS ${link})
        if (CMAKE_HOST_UNIX)
            set(command ln -s ${target} ${link})
        else()
            if (IS_DIRECTORY ${target})
                set(command cmd.exe /c mklink /j ${link} ${target})
            else()
                set(command cmd.exe /c mklink /h ${link} ${target})
            endif()
        endif()

        execute_process(COMMAND ${command}
            RESULT_VARIABLE result
            ERROR_VARIABLE output)

        if (NOT ${result} EQUAL 0)
            message(FATAL_ERROR "Could not create symbolic link for: ${target} --> ${output}")
        endif()
    endif()
endfunction(link_to_source)

add_subdirectory(trusted)
add_subdirectory(ocall)

if (COMPILE_EXAMPLES)
    add_subdirectory(example)
endif()
