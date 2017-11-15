set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wno-attributes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11")

add_library(${PROJECT_NAME}_u STATIC net_ocalls.c std_ocalls.c)

include_directories(
        ../trusted/mbedtls-2.6.0/include
)