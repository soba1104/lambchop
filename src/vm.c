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
    DEBUG("0x%llx: %x(%s)\n", rip, opcode, get_opcode_name(insn));
    if (opcode == 0x40e) { // syscall
      uint64_t id = get_rax(cpu);
      uint64_t a0 = get_rdi(cpu);
      uint64_t a1 = get_rsi(cpu);
      uint64_t a2 = get_rdx(cpu);
      uint64_t a3 = get_rcx(cpu);
      uint64_t a4 = get_r8(cpu);
      uint64_t res;
      DEBUG("syscall: id = 0x%llx\n", id);
      res = lambchop_syscall(id, a0, a1, a2, a3, a4);
      DEBUG("syscall: id = 0x%llx, result = 0x%llx\n", id, res);
      set_rax(cpu, res);
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
