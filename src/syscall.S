#ifdef __ARM__

.text
.globl _lambchop_syscall
_lambchop_syscall:
str x0, [sp, #8]
ldr x16, [x0]
mov x0, x1
mov x1, x2
mov x2, x3
mov x3, x4
mov x4, x5
mov x5, x6
svc #128
ldr x1, [sp, #8]
str x0, [x1]
movz x0, #0
ret

#else

.text
_lambchop_syscall_trap:
movq %rcx, %r10
syscall
retq

.text
.globl _lambchop_syscall
_lambchop_syscall:
pushq %rbp
movq %rsp, %rbp
pushq %rdi
movq (%rdi), %rax
movq %rsi, %rdi
movq %rdx, %rsi
movq %rcx, %rdx
movq %r8, %rcx
movq %r9, %r8
movq 0x10(%rbp), %r9
call _lambchop_syscall_trap
popq %rdi
popq %rbp
movq %rax, (%rdi)
pushfq
popq %rax
retq

#endif
