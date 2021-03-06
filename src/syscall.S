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
subq $0x50, %rsp
movq %rdi, 0x48(%rsp)
movq (%rdi), %rax
movq %rsi, %rdi
movq %rdx, %rsi
movq %rcx, %rdx
movq %r8, %rcx
movq %r9, %r8
movq 0x10(%rbp), %r9
movq 0x18(%rbp), %r10
movq %r10, 0x00(%rsp)
movq 0x20(%rbp), %r10
movq %r10, 0x08(%rsp)
movq 0x28(%rbp), %r10
movq %r10, 0x10(%rsp)
movq 0x30(%rbp), %r10
movq %r10, 0x18(%rsp)
call _lambchop_syscall_trap
movq 0x48(%rsp), %rdi
movq %rbp, %rsp
popq %rbp
movq %rax, (%rdi)
pushfq
popq %rax
retq

#endif
