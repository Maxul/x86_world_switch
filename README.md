# x86_world_switch

Please -see Include/user_define.h:
1. enable vmcall when within vm
2. grant sudo priviledge to test smcall

To test sgx ecall/ocall, please make sure you have sgx driver and sdk/psw installed.

In virtualization environments, use the following command:

qemu-sgx/x86_64-softmmu/qemu-system-x86_64 -m 1G -sgx epc=64MB -enable-kvm -cpu host -smp 2,sockets=1,cores=2 -machine kernel_irqchip=split

To test co-operation speedup for sgx thread, you need at least 2 logical processors available.

