/*
 * (C) Copyright 2016 Fan Zhang (bl4ck5unxx@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Authors:
 *     Fan Zhang <bl4ck5unxx@gmail.com>
 * 
 * This is a glue file calling ocalls.
 */

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "mbedtls_tlib.h"
#include "sgx.h"
#include "sgx_trts.h"

// real ocall to be implemented in the Application
extern int ocall_print_string(int* ret, char *str);

int printf(const char *fmt, ...)
{
    int ret;
    va_list ap;
    char buf[BUFSIZ] = {'\0'};
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);

    ocall_print_string(&ret, buf);
    return ret;
}

// ocall for entropy collection
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen )
{
    sgx_status_t st = sgx_read_rand(output, len);
    if (st != SGX_SUCCESS) {
        printf("hardware_poll fails with %d\n", st);
        *olen = -1;
        return -1;
    }
    else {
        *olen = len;
        return 0;
    }
}