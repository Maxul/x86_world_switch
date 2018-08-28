#define N 20000

#define SHMCPY_TIME 1000
#define MALLOC_TIMES 5000
#define MEMSET_TIMES 2000
#define SENDTO_TIMES (1<<16)

#define GETTIME_TIMES (50000)

#define VIRT
#define SMM
#define SGX

typedef struct {
    bool            isReady;
    char            data[];
} Triones;


