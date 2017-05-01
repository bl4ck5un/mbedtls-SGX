set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11")

set(CLIENT_SRC_FILES Enclave_u.c hybrid.cpp utils.cpp)

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

add_executable(enc enc.cpp)

target_include_directories(enc PRIVATE
        /home/fanz/dev/mbedtls-2.4.2/include)
target_link_libraries(enc
        -L/home/fanz/dev/mbedtls-2.4.2/library -lmbedtls -lmbedx509 -lmbedcrypto)

target_include_directories(hybrid-enc PRIVATE
        ${SGXSDK_INCLUDE_DIRS}
        ${MBEDTLS_SGX_ROOT_DIR}/include
)

set(LIB_MBEDTLS_PATH "${MBEDTLS_LIB_DIR}/libmbedtls_sgx_u.a")

target_link_libraries(hybrid-enc
        -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
        ${LIB_MBEDTLS_PATH}
        -Wl,-rpath -Wl,/usr/local/lib
        -Wl,-rpath -Wl,${SGX_LIBRARY_PATH}
        -lpthread)

add_dependencies(hybrid-enc enclave)