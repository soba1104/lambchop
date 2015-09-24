.text
.globl _lambchop_syscall
_lambchop_syscall:
pushq %rdi
movq (%rdi), %rax
movq %rsi, %rdi
movq %rdx, %rsi
movq %rcx, %rdx
movq %r8, %rcx
movq %r9, %r8
movq %r10, %r9
movq %rcx, %r10
syscall
popq %rdi
movq %rax, (%rdi)
pushfq
popq %rax
ret
