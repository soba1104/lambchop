#include "lambchop.h"

#define ERR(...) lambchop_err(logger, __VA_ARGS__)
#define INFO(...) lambchop_info(logger, __VA_ARGS__)
#define DEBUG(...) lambchop_debug(logger, __VA_ARGS__)

#include <x86i.h>
#include <stdlib.h>
#include <assert.h>
int vm_main(void *mainfunc, lambchop_logger *logger) {
  uint8_t *stack;
  uint16_t opcode;
  void *cpu, *insn;
  uint64_t rip, rax;
  int r;

  INFO("start\n");
  r = posix_memalign((void**)&stack, 0x1000, 0x1000000);
  assert(r >= 0);
  cpu = alloc_cpu();
  set_stack(cpu, stack + 0x1000000 - 8);
  set_rip(cpu, (uint64_t)mainfunc);
  insn = alloc_insn();
  while(true) {
    rip = get_rip(cpu);
    clear_insn(insn);
    decode64(cpu, insn);
    opcode = get_opcode(insn);
    DEBUG("0x%llx: %x(%s)\n", rip, opcode, get_opcode_name(insn));
    if (opcode == 0x40e) { // syscall
      rax = get_rax(cpu);
      DEBUG("syscal: rax = 0x%llx\n", rax);
    }
    step(cpu, insn);
  }
  free_insn(insn);
  free_cpu(cpu);
  free(stack);
  return 0;
}

static void dumpstate(void *cpu, void *insn, uint64_t rip, lambchop_logger *logger) {
  DEBUG("0x%llx,%s,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx\n",
      rip,
      get_opcode_name(insn),
      get_rax(cpu),
      get_rbx(cpu),
      get_rcx(cpu),
      get_rdx(cpu),
      get_rdi(cpu),
      get_rsi(cpu),
      get_rbp(cpu),
      get_rsp(cpu),
      get_r8(cpu),
      get_r9(cpu),
      get_r10(cpu),
      get_r11(cpu),
      get_r12(cpu),
      get_r13(cpu),
      get_r14(cpu),
      get_r15(cpu),
      get_rflags(cpu)
      );
}

#define SYSCALL_CLASS_MASK (0xff << 24)
#define SYSCALL_CLASS_MACH (0x01 << 24)
#define SYSCALL_CLASS_UNIX (0x02 << 24)
#define SYSCALL_CLASS_MDEP (0x03 << 24)
#define UNIX_SYSCALL(name, id) #name,
#define UNIX_OLD_SYSCALL(name, id) #name,
#define UNIX_ERROR_SYSCALL(id) NULL,
#define UNIX_SYSCALL_NUM ((sizeof(unix_syscalls) / sizeof(char*)) - 1)
static const char *unix_syscalls[] = {
#include "unix_syscalls.h"
  NULL
};

void handle_syscall(void *cpu, lambchop_logger *logger) {
  uint64_t rax = get_rax(cpu);
  uint64_t id = rax;
  uint64_t a0 = get_rdi(cpu);
  uint64_t a1 = get_rsi(cpu);
  uint64_t a2 = get_rdx(cpu);
  uint64_t a3 = get_r10(cpu);
  uint64_t a4 = get_r8(cpu);
  uint64_t a5 = get_r9(cpu);
  uint64_t rflags, idx = id & ~SYSCALL_CLASS_MASK;
  const char *name = NULL;

  switch (id & SYSCALL_CLASS_MASK) {
    case SYSCALL_CLASS_MACH:
      break;
    case SYSCALL_CLASS_UNIX:
      if (idx >= UNIX_SYSCALL_NUM) {
        assert(false);
      }
      name = unix_syscalls[idx];
      assert(name);
      break;
    case SYSCALL_CLASS_MDEP:
      break;
    default:
      assert(false);
  }
  rflags = lambchop_syscall(&rax, a0, a1, a2, a3, a4, a5);
  DEBUG("SYSCALL: %s(0x%llx)(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx) = 0x%llx, 0x%llx\n",
        name, id, a0, a1, a2, a3, a4, a5, rax, rflags);
  set_rax(cpu, rax);
  set_oszapc(cpu, (uint32_t)(rflags & 0xffffffffUL));
}

int lambchop_vm_call(void *func, int argc, uint64_t *argv, lambchop_logger *logger) {
  uint8_t *stack;
  uint16_t opcode;
  void *cpu, *insn;
  uint64_t rip, rax;
  int r;

  INFO("start\n");
  r = posix_memalign((void**)&stack, 0x1000, 0x1000000);
  assert(r >= 0);
  cpu = alloc_cpu();
  set_stack(cpu, stack + 0x1000000 - 8);
  set_rip(cpu, (uint64_t)func);
  set_rdi(cpu, argv[0]);
  set_rsi(cpu, argv[1]);
  set_rdx(cpu, argv[2]);
  set_rcx(cpu, argv[3]);
  set_r8(cpu, argv[4]);
  set_r9(cpu, argv[5]);
  insn = alloc_insn();
  while(true) {
    rip = get_rip(cpu);
    clear_insn(insn);
    decode64(cpu, insn);
    // TODO lock prefix がついているかどうか確認 & 全vmで共通のロックをとって排他制御
    opcode = get_opcode(insn);
    dumpstate(cpu, insn, rip, logger);
    if (opcode == 0x40e) { // syscall
      handle_syscall(cpu, logger);
    } else if (opcode == 0xb8) {
      uint64_t id = get_rax(cpu);
      DEBUG("int3: id = 0x%llx\n", id);
      assert(false);
    } else {
      step(cpu, insn);
    }
  }
  free_insn(insn);
  free_cpu(cpu);
  free(stack);
  return 0;
}

int lambchop_vm_run(void *mainfunc, lambchop_logger *logger) {
  // TODO 引数を扱えるようにする。
  /*return ((int(*)(void))mainfunc)();*/
  /*return lambchop_vm_main(mainfunc, 1024 * 1024, logger);*/
  return vm_main(mainfunc, logger);
}
