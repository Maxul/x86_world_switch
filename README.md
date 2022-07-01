## Intel x86 World Switch Benchmark

This project is applicable on Intel x86 CPU architectures.
It has been tested on Ubuntu 20.04 LTS.

### Features

The tested world switches include:
1. `syscall`: ring 3 to ring 0
2. `hypercall`: VMX non-root to VMX root
3. `SGX ecall`: ring3 to ring3 SGX mode
4. `smcall`: ring 0 to ring -2 (system management mode, SMM)

### Get Started

To enable particular test features, please read and modify the corresponding parameters in `Include/user_define.h`:
1. To enable x86-64 `vmcall` (or `hypercall`), you need to run this project in VMX non-root mode (using a guest VM);
2. To enable x86-64 `smcall` (trap the CPU to SMM mode), please grant **sudo** priviledge;
3. To enable Intel SGX `ecall` and `ocall`, please make sure you have SGX driver and SDK/PSW installed.

### QEMU-SGX

To virtualize SGX-capable environments, use the following command:
`
qemu-sgx/x86_64-softmmu/qemu-system-x86_64 -m 1G -sgx epc=64MB -enable-kvm -cpu host -smp 2,sockets=1,cores=2 -machine kernel_irqchip=split
`

To test co-operation speedup for sgx threads as in [HotCalls](http://doi.acm.org/10.1145/3079856.3080208), you need at least 2 logical processors available.

### Testsuite Summary

1. Context Switch Overhead: `syscall`, `hypercall`, `smcall`, and `ecall`/`ocall`;
2. `malloc` and `memset` overhead in pure glibc, pure SGX SDK, and from outside to inside (EPC);
3. **Synchronous** in-enclave syscall and **Asynchronous** in-enclave syscall.

