# x86_world_switch

This project is only available on 6th or higher Intel x86 CPU architectures. It has been tested on Ubuntu 16.04 LTS.

To enable particular test features, please read and modify Include/user_define.h:
1. You can enable vmcall if you run the benchmark in guest mode;
2. To enable to test smcall, please grant **sudo** priviledge;
3. To test sgx ecall/ocall, please make sure you have sgx driver and sdk/psw installed.

To virtualize SGX-capable environments, use the following command:
`
qemu-sgx/x86_64-softmmu/qemu-system-x86_64 -m 1G -sgx epc=64MB -enable-kvm -cpu host -smp 2,sockets=1,cores=2 -machine kernel_irqchip=split
`

To test co-operation speedup for sgx thread as in [HotCalls](http://doi.acm.org/10.1145/3079856.3080208), you need at least 2 logical processors available.

