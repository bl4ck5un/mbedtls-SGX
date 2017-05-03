set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11")

set_directory_properties(PROPERTIES
        ADDITIONAL_MAKE_CLEAN_FILES "Enclave_u.c; Enclave_u.h")

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.c
        COMMAND ${SGX_EDGER8R} --untrusted Enclave.edl
        --search-path ../enclave/ # enclave.edl
        --search-path ${SGX_SDK}/include
        --search-path ${MBEDTLS_SGX_ROOT_DIR}/lib # mbedtls_sgx.edl
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(hkeygen hkeygen.cpp hybrid_cipher.cpp base64.cpp hexdump.c)
add_executable(henc henc.cpp hybrid_cipher.cpp base64.cpp hexdump.c)
add_executable(hdec hdec.cpp hybrid_cipher.cpp base64.cpp hexdump.c)

target_link_libraries(hkeygen -lmbedtls -lmbedx509 -lmbedcrypto)
target_link_libraries(henc -lmbedtls -lmbedx509 -lmbedcrypto)
target_link_libraries(hdec -lmbedtls -lmbedx509 -lmbedcrypto)

set(LIB_MBEDTLS_PATH "${MBEDTLS_LIB_DIR}/libmbedtls_sgx_u.a")
