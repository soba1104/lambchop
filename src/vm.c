#include "lambchop.h"

#define ERR(...) lambchop_err(logger, __VA_ARGS__)
#define INFO(...) lambchop_info(logger, __VA_ARGS__)
#define DEBUG(...) lambchop_debug(logger, __VA_ARGS__)

#include <x86i.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

static void dumpstate(void *cpu, void *insn, uint64_t rip, lambchop_logger *logger) {
  static int count = 0;
  if ((count++) <= 11000000) {
  /*if ((count++) <= 7500000) {*/
    return;
  }
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

struct __syscall_entry;
typedef void (*syscall_callback)(const struct __syscall_entry *syscall, void *cpu, lambchop_logger *logger);

typedef struct __syscall_entry {
  uint64_t id;
  uint64_t class;
  const char *name;
  syscall_callback func;
} syscall_entry;

static uint64_t convert_syscall_id(const syscall_entry *syscall) {
  uint64_t id = syscall->id;
  switch (syscall->class) {
    case SYSCALL_CLASS_MACH:
#ifdef __ARM__
      return id - 1;
#else
      return SYSCALL_CLASS_MACH | id;
#endif
    case SYSCALL_CLASS_UNIX:
#ifdef __ARM__
      return id;
#else
      return SYSCALL_CLASS_UNIX | id;
#endif
    case SYSCALL_CLASS_MDEP:
      assert(false); // TODO
    default:
      assert(false);
  }
}

static void syscall_callback_set_cthread_self(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t self = get_rdi(cpu);
  DEBUG("SYSCALL: set_cthread_self(0x%llx)\n", self);
  set_gs_base(cpu, self);
  clear_cf(cpu);
  set_rax(cpu, 0x0f);
}

static void syscall_callback_passthrough(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t id = convert_syscall_id(syscall);
  uint64_t a0 = get_rdi(cpu);
  uint64_t a1 = get_rsi(cpu);
  uint64_t a2 = get_rdx(cpu);
  uint64_t a3 = get_r10(cpu);
  uint64_t a4 = get_r8(cpu);
  uint64_t a5 = get_r9(cpu);
  uint64_t rflags, idret;

  idret = id;
  rflags = lambchop_syscall(&idret, a0, a1, a2, a3, a4, a5);
  set_oszapc(cpu, (uint32_t)(rflags & 0xffffffffUL));
  set_rax(cpu, idret);
  DEBUG("SYSCALL PASSTHROUGH: %s(0x%llx)(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx) = 0x%llx, 0x%llx\n",
        syscall->name, id, a0, a1, a2, a3, a4, a5, idret, rflags);
}

static void syscall_callback_todo(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  DEBUG("SYSCALL TODO: %s\n", syscall->name);
  assert(false);
}

#define UNIX_SYSCALL(name, id, func) {id, SYSCALL_CLASS_UNIX, #name, syscall_callback_##func},
#define UNIX_OLD_SYSCALL(name, id) {id, SYSCALL_CLASS_UNIX, #name, syscall_callback_todo},
#define UNIX_ERROR_SYSCALL(id) {id, SYSCALL_CLASS_UNIX, NULL, NULL},
#define UNIX_SYSCALL_NUM ((sizeof(unix_syscalls) / sizeof(syscall_entry)) - 1)
static const syscall_entry unix_syscalls[] = {
#include "unix_syscalls.h"
  {-1, SYSCALL_CLASS_UNIX, NULL, NULL}
};

#define MACH_SYSCALL(name, argc, id, func) {id, SYSCALL_CLASS_MACH, #name, syscall_callback_##func},
#define MACH_ERROR_SYSCALL(id) {id, SYSCALL_CLASS_MACH, NULL, NULL},
#define MACH_SYSCALL_NUM ((sizeof(mach_syscalls) / sizeof(syscall_entry)) - 1)
static const syscall_entry mach_syscalls[] = {
#include "mach_syscalls.h"
  {-1, SYSCALL_CLASS_MACH, NULL, NULL}
};

static void handle_syscall(void *cpu, lambchop_logger *logger) {
  uint64_t rax = get_rax(cpu);
  uint64_t id = rax;
  uint64_t idx = id & ~SYSCALL_CLASS_MASK;
  const syscall_entry *syscall = NULL;
  const char *name = NULL;
  bool trapped = false;

  switch (id & SYSCALL_CLASS_MASK) {
    case SYSCALL_CLASS_MACH:
      if (idx >= MACH_SYSCALL_NUM) {
        assert(false);
      }
      syscall = &mach_syscalls[idx];
      name = syscall->name;
#ifdef __ARM__
      rax = idx - 1;
#endif
      assert(name);
      break;
    case SYSCALL_CLASS_UNIX:
      if (idx >= UNIX_SYSCALL_NUM) {
        assert(false);
      }
      syscall = &unix_syscalls[idx];
      name = syscall->name;
#ifdef __ARM__
      rax = idx;
#endif
      assert(name);
      break;
    case SYSCALL_CLASS_MDEP:
      assert(idx == 0x03); // set cthread self
      syscall_callback_set_cthread_self(NULL, cpu, logger); // FIXME
      trapped = true;
      break;
    default:
      assert(false);
  }
  if (!trapped) {
    assert(syscall);
    assert(syscall->func);
    syscall->func(syscall, cpu, logger);
  }
}

uint64_t lambchop_vm_call(lambchop_vm_t *vm, void *func, int argc, uint64_t *argv, lambchop_logger *logger) {
  uint8_t *stack;
  uint16_t opcode;
  void *cpu = vm->cpu, *insn = vm->insn;
  uint64_t rip, rax;
  int r;

  INFO("lambchop_vm_call start: func = %llx\n", func);
  r = posix_memalign((void**)&stack, 0x1000, 0x1000000);
  assert(r >= 0);
  memset(stack, 0, 0x1000000);
  set_stack(cpu, stack + 0x1000000 - 8);
  set_rip(cpu, (uint64_t)func);
  if (argc > 0) set_rdi(cpu, argv[0]);
  if (argc > 1) set_rsi(cpu, argv[1]);
  if (argc > 2) set_rdx(cpu, argv[2]);
  if (argc > 3) set_rcx(cpu, argv[3]);
  if (argc > 4) set_r8(cpu, argv[4]);
  if (argc > 5) set_r9(cpu, argv[5]);
  assert(argc <= 6);
  while(true) {
    rip = get_rip(cpu);
    if (rip == 0) {
      break;
    }
    clear_insn(insn);
    r = decode64(cpu, insn);
    assert(r >= 0);
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
  rax = get_rax(cpu);
  free(stack);
  INFO("lambchop_vm_call finish: ret = %llx\n", rax);
  return rax;
}

int lambchop_vm_run(lambchop_vm_t *vm, void *mainfunc, lambchop_logger *logger) {
  // TODO 引数を扱えるようにする。
  /*return ((int(*)(void))mainfunc)();*/
  return lambchop_vm_call(vm, mainfunc, 0, NULL, logger);
}

lambchop_vm_t *lambchop_vm_alloc(void) {
  lambchop_vm_t *vm = malloc(sizeof(lambchop_vm_t));
  void *cpu = alloc_cpu();
  void *insn = alloc_insn();
  assert(vm);
  assert(cpu);
  assert(insn);
  vm->cpu = cpu;
  vm->insn = insn;
  return vm;
}

void lambchop_vm_free(lambchop_vm_t *vm) {
  free_insn(vm->insn);
  free_cpu(vm->cpu);
  free(vm);
}
