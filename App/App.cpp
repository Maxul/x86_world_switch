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

#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


#include "user_define.h"

#include <iostream>
#include <thread>

#include <pthread.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

using namespace std;

static inline
void synch_tsc(void)
{
	asm volatile("cpuid" : : : "%rax", "%rbx", "%rcx", "%rdx");
}

unsigned long long rdtscllp(void)
{
	long long r;

#ifdef __x86_64__
	unsigned a, d;

	asm volatile ("rdtscp" : "=a"(a), "=d"(d));
	r = a | ((long long)d << 32);
#else
	asm volatile ("rdtscp" : "=A"(r));
#endif
	return r;
}

#define NS 1000000000

static uint64_t get_cycle_count(void)
{

    int i = 0;
    uint64_t old_tsc, new_tsc;
    unsigned int delayms = 1000;
    for (i = 0; i < 3; i++)
    {
        old_tsc = rdtscllp();
        usleep(delayms * 1000);
        new_tsc = rdtscllp();
        printf("CPU runs at %lu MHz\n", (new_tsc - old_tsc)/(delayms*1000));
    }
    return (new_tsc - old_tsc) / (delayms*1000);
}

static inline unsigned long measure_tsc_overhead(void)
{
	unsigned long t0, t1, overhead = ~0UL;
	int i;

	for (i = 0; i < N; i++) {
		t0 = rdtscllp();
		asm volatile("");
		t1 = rdtscllp();
		if (t1 - t0 < overhead)
			overhead = t1 - t0;
	}

	return overhead;
}

static inline void syscall(void)
{
    asm volatile("syscall");
}

static inline void vmcall(void)
{
    asm volatile("vmcall");
}

#define PORT_SMI_CMD 0x00b2
static inline void smcall(void)
{
    outb(0x00, PORT_SMI_CMD);
}

void ocall_sample(void) {}

int ocall_sgx_gettimeofday(void *tv, size_t tv_size)
{
    (void)(tv_size);
	return gettimeofday((struct timeval *)tv, NULL);
}

int ocall_sendto(int sockfd, const void *buf, size_t len, int flags, const void *dest_addr_cast, unsigned int addrlen)
{
	const struct sockaddr *dest_addr = (const struct sockaddr *)dest_addr_cast;
	return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

int ocall_do_sendto(int sockfd, const void *buf, size_t len, int flags, const void *dest_addr_cast, unsigned int addrlen)
{
	const struct sockaddr *dest_addr = (const struct sockaddr *)dest_addr_cast;
	return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

////////////////////////////////////////////////////////////////////////////////

uint64_t cpu_mhz;

unsigned long overhead;

static void benchamark_glibc_malloc()
{
	size_t sz;
	unsigned long ticks, diff;

    puts("\nbench glibc malloc");
    for (sz = 1<<12; sz < (1<<28); sz <<= 2) {
	    ticks = rdtscllp();
	    for (int i = 0; i < MALLOC_TIMES; i++) {
	        unsigned char *tmp = (unsigned char *)malloc(sz);
	        free(tmp);
	    }
	    diff = (rdtscllp() - ticks - overhead) / MALLOC_TIMES;
	    printf("malloc size %luKB\t took %lu cycles == %lu us\n", sz>>10, diff, diff / cpu_mhz);
    }
    puts("bench glibc malloc done\n");
}

static void benchamark_sgxsdk_malloc()
{
	size_t sz;
	unsigned long ticks, diff;

    puts("\nbench sgxsdk malloc");
    for (sz = 1<<12; sz < (1<<28); sz <<= 2) {
	    ticks = rdtscllp();
	    ecall_malloc_test(global_eid, sz);
	    diff = (rdtscllp() - ticks - overhead) / MALLOC_TIMES;
	    printf("malloc size %luKB\t took %lu cycles == %lu us\n", sz>>10, diff, diff / cpu_mhz);
    }
    puts("bench sgxsdk malloc done\n");
}

static void benchamark_glibc_memset()
{
	size_t sz;
	unsigned long ticks, diff;

    puts("\nbench glibc memset");
    for (sz = 1<<10; sz < (1<<28); sz <<= 1) {
        unsigned char *buffer = (unsigned char *)malloc(sz);
	    ticks = rdtscllp();
	    for (int i = 0; i < MEMSET_TIMES; i++) {
	        memset(buffer, 0xa, sz);
	    }
	    diff = (rdtscllp() - ticks - overhead) / MEMSET_TIMES;
	    printf("memset size %luKB\ttook %lu cycles == %lu us\n", sz>>10, diff, diff / cpu_mhz);
	    free(buffer);
    }
    puts("bench glibc memset done\n");
}

static void benchamark_sgxsdk_memset()
{
	size_t sz;
	unsigned long ticks, diff;

    puts("\nbench sgxsdk memset");
    for (sz = 1<<10; sz < (1<<28); sz <<= 1) {
	    ticks = rdtscllp();
	    ecall_memset_test(global_eid, sz);
	    diff = (rdtscllp() - ticks - overhead) / MEMSET_TIMES;
	    printf("memset size %luKB\ttook %lu cycles == %lu us\n", sz>>10, diff, diff / cpu_mhz);
    }
    puts("bench sgxsdk memset done\n");
}

static void benchamark_enclave_memset_regular()
{
	size_t sz;
	unsigned long ticks, diff;

    puts("\nbench enclave memset on regular RAM");
    for (sz = 1<<10; sz < (1<<28); sz <<= 1) {
        unsigned char *buffer = (unsigned char *)malloc(sz);
//        printf("%p\n", buffer);
	    ticks = rdtscllp();
	    ecall_memset_plain(global_eid, sz, buffer);
	    diff = (rdtscllp() - ticks - overhead) / MEMSET_TIMES;
	    printf("memset size %luKB\ttook %lu cycles == %lu us\n", sz>>10, diff, diff / cpu_mhz);
	    free(buffer);
    }
    puts("bench enclave memset on regular done\n");
}

#define SERVER "127.0.0.1"
#define BUFLEN (1<<12)	// Max length of buffer
#define PORT 19999	// The port on which to send data

unsigned char Triones_buffer[1<<20];

static void enclave_thread(void)
{
	unsigned long ticks, diff;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    int rc = pthread_setaffinity_np(pthread_self(),
                                    sizeof(cpu_set_t), &cpuset);
    if (rc != 0) {
      cerr << "Error calling pthread_setaffinity_np: " << rc << "\n";
    }
    cout << "Enclave Thread on CPU " << sched_getcpu() << "\n";
    //printf("Triones_buffer %p\n", Triones_buffer);

	ticks = rdtscllp();
    ecall_concurrent_sendto(global_eid, Triones_buffer, sizeof Triones_buffer, cpu_mhz);
    diff = (rdtscllp() - ticks - overhead);

    printf("APP: concurrent sendto took \t%lu cycles == %lu us\n", diff, diff / cpu_mhz);
}

static void benchmark_ocall_sendto(void)
{
    char message[BUFLEN];
    struct sockaddr_in si_other;
    int i, s;
    unsigned int slen = sizeof(si_other);
	unsigned long ticks, diff;

	memset(message, 'A', sizeof(message));

    if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
		printf("socket() failed\n");
		exit(1);
    }
	memset((char *) &si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(PORT);

	if (inet_aton(SERVER , &si_other.sin_addr) == 0)
	{
		printf("inet_aton() failed\n");
		exit(1);
	}

	ticks = rdtscllp();
	for (i = 0; i < SENDTO_TIMES; ++i) {
        if (sendto(s, message, strlen(message) , 0 , (struct sockaddr *) &si_other, slen)==-1)
        {
            printf("sendto() failed\n");
            exit(-1);
        }
    }
    diff = (rdtscllp() - ticks - overhead);
    printf("native sendto took \t%lu cycles == %lu us\n", diff, diff / cpu_mhz);

	ticks = rdtscllp();
    ecall_sendto_test(global_eid, s, &si_other, slen);
    diff = (rdtscllp() - ticks - overhead);
    printf("ENCLAVE ocall sendto took \t%lu cycles == %lu us\n", diff, diff / cpu_mhz);

	ticks = rdtscllp();
    ecall_sendto_nocopy_test(global_eid, s, message, sizeof message, &si_other, slen);
    diff = (rdtscllp() - ticks - overhead);
    printf("ENCLAVE ocall sendto NOCOPY took \t%lu cycles == %lu us\n", diff, diff / cpu_mhz);

    memset(Triones_buffer, 0xFF, sizeof Triones_buffer);
    Triones *t = (Triones *)Triones_buffer;
    t->isReady = false;
    ticks = rdtscllp();
    std::thread thread_enclave(enclave_thread);
    for (i = 0; i < SENDTO_TIMES; ++i) {
        while (1) {__asm __volatile("pause");
            if (true == t->isReady)
            break;
        }
        if (sendto(s, t->data, 1<<12, 0, (struct sockaddr *) &si_other, slen)==-1)
        {
            printf("sendto() failed\n");
            exit(-1);
        }
	    t->isReady = false;
    }
    thread_enclave.join();
    diff = (rdtscllp() - ticks - overhead);
    printf("APP: overall sendto took \t%lu cycles == %lu us\n", diff, diff / cpu_mhz);

    close(s);
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

	int i;
	unsigned long ticks, diff;
	
    printf("Test CPU frequency:\n");
    cpu_mhz = get_cycle_count();
    
    // print benchmark information
    printf("\nBenchmark runs %d round(s):\n", N);

    // get the maximum overhead of RDTSCP instruction
    synch_tsc();
	overhead = measure_tsc_overhead();
	printf("RDTSC instruction overhead is %lu cycles\n", overhead);

    printf("\nTest basic mode switch overhead:\n");
    // calculate the SYSCALL microbench overhead
	ticks = rdtscllp();
	for (i = 0; i < N; i++) {
	    syscall();
	}
	diff = (rdtscllp() - ticks - overhead) / N;
	printf("SYSCALL took %lu cycles == %lu us\n", diff, diff / cpu_mhz);

#ifdef VMM_TEST
    // calculate the VMCALL microbench overhead
	ticks = rdtscllp();
	for (i = 0; i < N; i++) {
	    vmcall();
	}
	diff = (rdtscllp() - ticks - overhead) / N;
	printf("VMCALL took %lu cycles == %lu us\n", diff, diff / cpu_mhz);
#endif

#ifdef SMM_TEST
    // obtain I/O port access
    if (0 != ioperm(PORT_SMI_CMD, 1, 1))
        err(EXIT_FAILURE, "ioperm");

    // calculate the SMCALL microbench overhead
	ticks = rdtscllp();
	for (i = 0; i < N; i++) {
	    smcall();
	}
	diff = (rdtscllp() - ticks - overhead) / N;
	printf("SMCALL took %lu cycles == %lu us\n", diff, diff / cpu_mhz);
#endif

#ifdef SGX_TEST
    puts("\nCreating Enclave...");

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("initialize_enclave failed\n");
        return -1;
    }

    // calculate the ECALL microbench overhead
	ticks = rdtscllp();
	for (i = 0; i < N; i++) {
	    ecall_sample(global_eid);
	}
	diff = (rdtscllp() - ticks - overhead) / N;
	printf("ECALL took %lu cycles == %lu us\n", diff, diff / cpu_mhz);

    // calculate the OCALL microbench overhead
	ticks = rdtscllp();
    ocall_batch_test(global_eid);
	diff = (rdtscllp() - ticks - overhead) / N;
	printf("OCALL took %lu cycles == %lu us\n", diff, diff / cpu_mhz);

#if 1
    benchamark_glibc_malloc();
    benchamark_sgxsdk_malloc();

    benchamark_glibc_memset();
    benchamark_enclave_memset_regular();
    benchamark_sgxsdk_memset();
#endif

    printf("\nTest normal and enclave time latency:\n");
    
	ticks = rdtscllp();
	for (i = 0; i < GETTIME_TIMES; i++) {
	    struct timeval tv;
	    gettimeofday(&tv, NULL);
	}
	diff = (rdtscllp() - ticks - overhead) / GETTIME_TIMES;
	printf("gettimeofday took %lu cycles == %lu us\n", diff, diff / cpu_mhz);

	ticks = rdtscllp();
    gettimeofday_test(global_eid);
	diff = (rdtscllp() - ticks - overhead) / GETTIME_TIMES;
	printf("ENCLAVE gettimeofday took %lu cycles == %lu us\n", diff, diff / cpu_mhz);


    printf("\nTest normal and enclave thread cooperation throughput:\n");
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    int rc = pthread_setaffinity_np(pthread_self(),
                                    sizeof(cpu_set_t), &cpuset);
    if (rc != 0) {
      cerr << "Error calling pthread_setaffinity_np: " << rc << "\n";
    }
    cout << "Main Thread on CPU " << sched_getcpu() << "\n";
    benchmark_ocall_sendto();

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
#endif

    return 0;
}

