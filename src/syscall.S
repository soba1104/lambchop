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
.globl _lambchop_syscall
_lambchop_syscall:
push %rbp
movq %rsp, %rbp
subq $0x30, %rsp
movq %rdi, 0x28(%rsp)
movq %rbx, 0x20(%rsp)
movq (%rdi), %rax
movq %rsi, %rdi
movq %rdx, %rsi
movq %rcx, %rdx
movq %r8, %r10
movq %r9, %r8
movq 0x10(%rbp), %r9
movq 0x18(%rbp), %rbx
movq %rbx, 0x00(%rsp)
movq 0x20(%rbp), %rbx
movq %rbx, 0x08(%rsp)
movq 0x28(%rbp), %rbx
movq %rbx, 0x10(%rsp)
movq 0x30(%rbp), %rbx
movq %rbx, 0x18(%rsp)
syscall
movq 0x20(%rsp), %rbx
movq 0x28(%rsp), %rdi
addq $0x30, %rsp
popq %rbp
movq %rax, (%rdi)
pushfq
popq %rax
ret

#endif
