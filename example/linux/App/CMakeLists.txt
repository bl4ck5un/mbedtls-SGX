set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11")

set(CLIENT_SRC_FILES Enclave_u.c Main.cpp Utils.cpp)

set_directory_properties(PROPERTIES
    ADDITIONAL_MAKE_CLEAN_FILES "Enclave_u.c; Enclave_u.h")

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.c
    COMMAND ${SGX_EDGER8R} --untrusted Enclave.edl
    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../Enclave/
    --search-path ${SGX_SDK}/include
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(s_client ${CLIENT_SRC_FILES})

message(${MBEDTLS_SGX_ROOT_DIR})

include_directories(
    ${SGXSDK_INCLUDE_DIRS}
    ../App
    ${MBEDTLS_SGX_ROOT_DIR}/include
)

set(LIB_MBEDTLS_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../libmbedtls_sgx_u.a")

target_link_libraries(s_client
    -L${SGX_LIBRARY_PATH} -l${SGX_URTS_LIB} -l${SGX_USVC_LIB}
    ${LIB_MBEDTLS_PATH}
    -Wl,-rpath -Wl,/usr/local/lib
    -Wl,-rpath -Wl,${SGX_LIBRARY_PATH}
    -lpthread -ldl)