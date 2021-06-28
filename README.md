## x86_world_switch

This project is only available on 6th or higher Intel x86 CPU architectures.
It has been tested on Ubuntu 16.04 LTS.

To enable particular test features, please read and modify Include/user_define.h:
1. You can enable x86-64 `vmcall` (or `hypercall`) if you run the benchmark in VMX non-root mode;
2. To test x86-64 `smcall` (trap the CPU to SMM mode), please grant **sudo** priviledge;
3. To test Intel SGX `ecall` and `ocall`, please make sure you have SGX driver and SDK/PSW installed.


### QEMU-SGX

To virtualize SGX-capable environments, use the following command:
`
qemu-sgx/x86_64-softmmu/qemu-system-x86_64 -m 1G -sgx epc=64MB -enable-kvm -cpu host -smp 2,sockets=1,cores=2 -machine kernel_irqchip=split
`

To test co-operation speedup for sgx threads as in [HotCalls](http://doi.acm.org/10.1145/3079856.3080208), you need at least 2 logical processors available.

### Testsuite

1. Context Switch Overhead: `syscall`, `hypercall`, `smcall`, and `ecall`/`ocall`;
2. `malloc` and `memset` overhead in pure glibc, pure SGX SDK, and from outside to inside (EPC);
3. **Synchronous** in-enclave syscall and **Asynchronous** in-enclave syscall.

