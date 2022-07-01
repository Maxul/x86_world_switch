/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#include "user_define.h"

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void ecall_sample(void) {}

void ocall_batch_test()
{
	for (int i = 0; i < N; i++) {
	    ocall_sample();
	}
}

typedef long int __suseconds_t;

struct timeval
{
	__time_t tv_sec;		/* Seconds.  */
	__suseconds_t tv_usec;	/* Microseconds.  */
};
int gettimeofday(struct timeval *tv)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_gettimeofday(&retv, tv, sizeof(struct timeval))) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		return(EXIT_FAILURE);
	}
	return retv;
}

void gettimeofday_test()
{
    struct timeval tv;
	for (int i = 0; i < GETTIME_TIMES; i++) {
	    gettimeofday(&tv);
//	    printf("sec %lu usec %lu\n", tv.tv_sec, tv.tv_usec);
	}
}

static int _deadbeaf;

void ecall_malloc_test(size_t sz)
{
    for (int i = 0; i < MALLOC_TIMES; i++) {
        unsigned char *tmp = (unsigned char *)malloc(sz);
        if (NULL == tmp) {
            printf("malloc %lu failed\n", sz); break;
        }
        free(tmp);
    }
}

void ecall_memset_test(size_t sz)
{
    unsigned char *buffer = (unsigned char *)malloc(sz);
    for (int i = 0; i < MEMSET_TIMES; i++) {
        if (NULL == buffer) {
            printf("malloc %lu failed\n", sz); break;
        }
        memset(buffer, 0xa, sz);
    }
    free(buffer);
}

void ecall_memset_plain(size_t sz, void *pOutside)
{
//    printf("outside %p\n", pOutside);
    for (int i = 0; i < MEMSET_TIMES; i++) {
        if (NULL == pOutside) {
            printf("malloc %lu failed\n", sz); break;
        }
        memset(pOutside, 0xa, sz);
    }
}

#define BUFLEN (1<<12)	// Max length of buffer
void ecall_sendto_test(int fd, void *addr, unsigned int addrlen)
{
    int s = fd;
    char message[BUFLEN];
	int retv;
	sgx_status_t sgx_retv;
	
	memset(message, 'A', sizeof(message));
    
	for (int i = 0; i < SENDTO_TIMES; ++i) {
        if ((sgx_retv = ocall_sendto(&retv, s, message, strlen(message) , 0 , addr, addrlen)) != SGX_SUCCESS)
        {
            printf("sendto() failed\n");
            return;
        }
    }
}

void ecall_sendto_nocopy_test(int fd, void *buf, int buflen, void *addr, unsigned int addrlen)
{
    int s = fd;
	int retv;
	sgx_status_t sgx_retv;
	
    memset(buf, 'A', buflen);
    
	for (int i = 0; i < SENDTO_TIMES; ++i) {
        if ((sgx_retv = ocall_do_sendto(&retv, s, buf, buflen, 0, addr, addrlen)) != SGX_SUCCESS)
        {
            printf("sendto() failed\n");
            return;
        }
    }
}

void ecall_concurrent_sendto(void *buf, int buflen, uint64_t cpu_mhz)
{
	long long unsigned int ticks, diff;

    Triones *t = (Triones *)buf;
//printf("Triones_buffer %p %p\n", buf, t->data);
    memset(t->data, 'T', buflen);

    rdtscllp(&ticks);
	for (int i = 0; i < SENDTO_TIMES; ++i) {
	    t->isReady = true;
        while (1) {__asm __volatile("pause");
            if (false == t->isReady)
                break;
        }
    }
    rdtscllp(&diff);
    diff -= ticks;
    printf("ENCLAVE: concurrent sendto took \t%lu cycles == %lu us\n", diff, diff / cpu_mhz);
}


