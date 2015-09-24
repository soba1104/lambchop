.text
.globl _lambchop_syscall
_lambchop_syscall:
pushq %rdi
movq (%rdi), %rax
movq %rsi, %rdi
movq %rdx, %rsi
movq %rcx, %rdx
movq %r8, %r10
movq %r9, %r8
movq 0x10(%rsp), %r9
syscall
popq %rdi
movq %rax, (%rdi)
pushfq
popq %rax
ret
