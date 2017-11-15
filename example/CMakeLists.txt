get_filename_component(MBEDTLS_SGX_ROOT_DIR ".." REALPATH BASE_DIR "${CMAKE_BINARY_DIR}")

add_subdirectory(untrusted)
add_subdirectory(enclave)
