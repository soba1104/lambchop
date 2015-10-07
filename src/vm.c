#include "lambchop.h"

#define ERR(...) lambchop_err(logger, __VA_ARGS__)
#define INFO(...) lambchop_info(logger, __VA_ARGS__)
#define DEBUG(...) lambchop_debug(logger, __VA_ARGS__)

#include <x86i.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>

static void dumpstate(void *cpu, void *insn, uint64_t rip, lambchop_logger *logger) {
  static int count = 0;
  if ((count++) <= 175000000) {
  /*if ((count++) <= 175280000) {*/
  /*if ((count++) <= 200000000) {*/
  /*if ((count++) <= 10450000) {*/
  /*if ((count++) <= 10401000) {*/
  /*if ((count++) <= 10200000 || count >= 10265000) {*/
  /*if ((count++) <= 7500000) {*/
    return;
  }
  DEBUG("(0x%llx)0x%llx,%s,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx\n",
      cpu,
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
  uint64_t rsp = get_rsp(cpu);
  uint64_t a0 = get_rdi(cpu);
  uint64_t a1 = get_rsi(cpu);
  uint64_t a2 = get_rdx(cpu);
  uint64_t a3 = get_r10(cpu);
  uint64_t a4 = get_r8(cpu);
  uint64_t a5 = get_r9(cpu);
  uint64_t a6 = *((uint64_t*)(rsp + 0x08));
  uint64_t a7 = *((uint64_t*)(rsp + 0x10));
  uint64_t a8 = *((uint64_t*)(rsp + 0x18));
  uint64_t a9 = *((uint64_t*)(rsp + 0x20));
  uint64_t rflags, idret;

  idret = id;
  rflags = lambchop_syscall(&idret, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
  set_oszapc(cpu, (uint32_t)(rflags & 0xffffffffUL));
  set_rax(cpu, idret);
  DEBUG("SYSCALL PASSTHROUGH: %s(0x%llx)(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx) = 0x%llx, 0x%llx\n",
        syscall->name, id, a0, a1, a2, a3, a4, a5, idret, rflags);
}

static void syscall_callback_open(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t path = get_rdi(cpu);
  uint32_t flags = get_rsi(cpu);
  // TODO アドレス変換をかませる場合は path の取得を cpu を通して行う。
  DEBUG("SYSCALL: open(%s, 0x%x)\n", (char*)path, flags);
  if ((flags & O_ACCMODE) == O_RDONLY) {
    // TODO path の書き換え
  }
  syscall_callback_passthrough(syscall, cpu, logger);
}

static void syscall_callback_open_nocancel(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t path = get_rdi(cpu);
  uint32_t flags = get_rsi(cpu);
  DEBUG("SYSCALL: open_nocancel(%s, 0x%x)\n", (char*)path, flags);
  syscall_callback_passthrough(syscall, cpu, logger);
}

static void syscall_callback_access(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t path = get_rdi(cpu);
  uint32_t mode = get_rsi(cpu);
  DEBUG("SYSCALL: access(%s, 0x%x)\n", (char*)path, mode);
  syscall_callback_passthrough(syscall, cpu, logger);
}

static void syscall_callback_stat64(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t path = get_rdi(cpu);
  DEBUG("SYSCALL: stat64(%s, 0x%x)\n", (char*)path);
  syscall_callback_passthrough(syscall, cpu, logger);
}

static void syscall_callback_getattrlist(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t path = get_rdi(cpu);
  DEBUG("SYSCALL: getattrlist(%s, 0x%x)\n", (char*)path);
  syscall_callback_passthrough(syscall, cpu, logger);
}

static void syscall_callback_shm_open(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t path = get_rdi(cpu);
  uint32_t flags = get_rsi(cpu);
  DEBUG("SYSCALL: shm_open(%s, 0x%x)\n", (char*)path, flags);
  syscall_callback_passthrough(syscall, cpu, logger);
}

static void syscall_callback_mmap(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t addr = get_rdi(cpu);
  uint64_t len = get_rsi(cpu);
  uint64_t prot = get_rdx(cpu);
  uint64_t flags = get_r10(cpu);
  uint64_t fd = get_r8(cpu);
  uint64_t offset = get_r9(cpu);
  DEBUG("SYSCALL: mmap(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx)\n",
        addr, len, prot, flags, fd, offset);
  syscall_callback_passthrough(syscall, cpu, logger);
}

static void sigaction_handler(int num, siginfo_t *info, void *context) {
  fprintf(stderr, "--------- SIGACTION HANDLER %d ---------\n", num);
  assert(false);
}

static void syscall_callback_sigaction(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t signum = get_rdi(cpu);
  uint64_t actp = get_rsi(cpu);
  uint64_t oldactp = get_rdx(cpu);
  struct sigaction *act = (struct sigaction*)actp;
  struct sigaction *oldact = (struct sigaction*)oldactp;
  assert(act->sa_flags == 0x03); // SA_ONSTACK & SA_RESTART
  DEBUG("SYSCALL: sigaction(%llu, {0x%llx, 0x%x, 0x%x}, 0x%llx)\n",
        signum, act->sa_handler, act->sa_mask, act->sa_flags, oldact);
#if 0
  syscall_callback_passthrough(syscall, cpu, logger);
#else
  {
    struct sigaction a;
    int ret;
    a.sa_flags = SA_SIGINFO;
    a.sa_mask = act->sa_mask;
    a.sa_sigaction = sigaction_handler;
    // TODO lambchop_syscall で直接システムコールを呼び出す
    ret = sigaction(signum, &a, oldact);
    assert(ret >= 0);
    clear_cf(cpu);
    set_rax(cpu, 0);
  }
#endif
}

typedef struct {
  uint64_t orig_func;
  uint64_t orig_func_arg;
  uint64_t orig_stack;
  uint64_t orig_pthread;
  uint32_t orig_flags;
  void *tls;
  lambchop_logger *logger;
} bsdthread_arg;

static uint64_t bsdthread_start;

// flags の下位ビットは policy と importance になっている。
// policy はスケジュールの方針で importance は多分優先度。
// 上位ビットは以下のマクロのようなフィールドを持っている。
// 以下は libpthread から持ってきたマクロ
#define PTHREAD_START_CUSTOM  0x01000000
#define PTHREAD_START_SETSCHED  0x02000000
#define PTHREAD_START_DETACHED  0x04000000
#define PTHREAD_START_QOSCLASS  0x08000000
// PTHREAD_START_QOSCLASS はあんまり気にしなくてよさそう
// PTHREAD_START_SETSCHED と PTHREAD_START_DETACHED は意味がよくわかっていないので非対応。
// PTHREAD_START_DETACHED は detach 済みで join 対象にならないスレッドを作成する。気にしなくてよさそう。
// PTHREAD_START_CUSTOM だと pthread や stack の扱いが変わるんだけどそれに未対応

static void bsdthread_handler(bsdthread_arg *arg) {
  uint64_t orig_func = arg->orig_func;
  uint64_t orig_func_arg = arg->orig_func_arg;
  uint64_t argv[6];
  pthread_t self = pthread_self();
  lambchop_logger *logger = arg->logger;
  lambchop_vm_t *vm = lambchop_vm_alloc(); // TODO stack size の設定

  // PTHREAD_START_CUSTOM が無効化だった場合は以下のとおり。
  // -: stack はこちら側で割り当ててよい。
  // -: TLS はこちら側で割り当ててよい。
  // stack にスタック領域を、pthread に TLS 領域を入れて thread_start を呼び出す。

  // pthread は pthread_self で取得可能。
  // port は pthread_mach_thread_np で取得可能。
  // _pthread_start(pthread_t self, mach_port_t kport, void *(*fun)(void *), void *arg, size_t stacksize, unsigned int pflags)
  DEBUG("------------- bsdthread handler start --------------\n");
  DEBUG("orig_func = 0x%llx, orig_func_arg = 0x%llx\n", orig_func, orig_func_arg);
  assert(vm);
  assert(bsdthread_start);
  assert(!(arg->orig_flags & PTHREAD_START_CUSTOM));
  argv[0] = (uint64_t)arg->tls;
  argv[1] = (uint64_t)pthread_mach_thread_np(self);
  argv[2] = orig_func;
  argv[3] = orig_func_arg;
  argv[4] = arg->orig_stack;
  argv[5] = arg->orig_flags;
  // libpthread のほうで set cthread self を呼んでくれるようなので、
  // ここで gs を上書きする必要は無い。
  lambchop_vm_call(vm, LAMBCHOP_VM_PTHREAD_STACK_ADJUST, (void*)bsdthread_start, 6, argv, logger);
  lambchop_vm_free(vm);
  free(arg->tls);
  free(arg);
  DEBUG("------------- bsdthread handler end --------------\n");
}

static void syscall_callback_bsdthread_create(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t func = get_rdi(cpu);
  uint64_t func_arg = get_rsi(cpu);
  uint64_t stack = get_rdx(cpu); // stack size
  uint64_t pthread = get_r10(cpu); // ???
  uint32_t flags = (uint32_t)get_r8(cpu);
  void *tls;
  bsdthread_arg *arg = malloc(sizeof(bsdthread_arg)); // 解放は生成したスレッドで行う。

  assert(arg);
  assert(!(flags & PTHREAD_START_SETSCHED));
  DEBUG("SYSCALL: bsdthread_create(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%x)\n",
        func, func_arg, stack, pthread, flags);

#define TLS_SIZE 0x100000
  if (!(flags & PTHREAD_START_CUSTOM)) {
    int r = posix_memalign(&tls, 0x4000, TLS_SIZE); // 解放は生成したスレッドで行う。
    assert(r >= 0);
  } else {
    assert(false);
  }

  assert(pthread == 0);
  assert(bsdthread_start);
  arg->orig_func = func;
  arg->orig_func_arg = func_arg;
  arg->orig_stack = stack;
  arg->orig_pthread = pthread;
  arg->orig_flags = flags;
  arg->tls = tls;
  arg->logger = logger;
  memset(tls, 0, TLS_SIZE);

  // pthread っていう引数の意味はよくわかってないけど、
  // PTHREAD_START_CUSTOM が無効化されている場合の処理を見たところ、
  // stack と guard 領域の隣を指すようになっていたので、
  // TLS のアドレスを指しているもののような気がする。
  //
  // その認識であっているならば、PTHREAD_START_CUSTOM が有効の場合はここで値を書き換えないと、
  // lambchop の TLS と動作させたいアプリケーションの TLS が衝突してしまうはず。
  // PTHREAD_START_CUSTOM が無効だった場合、TLS っぽい値は libpthread 側で割り当ててくれるので、
  // flags から PTHREAD_START_CUSTOM をクリアするだけでよさそう。
  //
  // 実装を見た感じ、PTHREAD_START_CUSTOM の場合、ここで渡した pthread という値は無視されるっぽいので
  // 何を渡してもいいはずなんだけど、もし問題があった時に分かりやすいように 0 を渡しておく。
  set_rdi(cpu, (uint64_t)bsdthread_handler);
  set_rsi(cpu, (uint64_t)arg);
  set_rdx(cpu, 0x4000UL); // TODO 定数に置き換える
  set_r10(cpu, 0);
  set_r8(cpu, flags & ~PTHREAD_START_CUSTOM);
  syscall_callback_passthrough(syscall, cpu, logger);
  set_rdi(cpu, func);
  set_rsi(cpu, func_arg);
  set_rdx(cpu, stack);
  set_r10(cpu, pthread);
  set_r8(cpu, flags);
  {
    // bsdthread_create は返り値に pthread_self の値(兼 TLS 領域)を返すので差し替える。
    assert(get_rax(cpu) >= 0);
    set_rax(cpu, (uint64_t)tls);
    // ここから抜けて pthread_create に戻って処理を進めるまでの間に
    // 生成したスレッドが動き出しても問題なさそうだった。
    // 排他制御を libpthread がかけていた。
  }
}

int _pthread_workqueue_supported();
static void syscall_callback_bsdthread_register(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t threadstart = get_rdi(cpu);
  uint64_t wqthread = get_rsi(cpu);
  int pthsize = (int)get_rdx(cpu);
  uint64_t pthread_init_data = get_r10(cpu);
  uint64_t targetconc_ptr = get_r8(cpu);
  uint64_t dispatchqueue_offset = get_r9(cpu);

  assert(!bsdthread_start);
  bsdthread_start = threadstart;
  DEBUG("SYSCALL: bsdthread_register(0x%llx, 0x%llx, 0x%x, 0x%llx, 0x%llx, 0x%llx)\n",
        threadstart, wqthread, pthsize, pthread_init_data, targetconc_ptr, dispatchqueue_offset);
  // 2度目以降の register は無視されるので passthrough する意味が無い。
  /*syscall_callback_passthrough(syscall, cpu, logger);*/
  clear_cf(cpu);
  set_rax(cpu, (uint64_t)_pthread_workqueue_supported());
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
  uint64_t id = get_rax(cpu);
  uint64_t idx = id & ~SYSCALL_CLASS_MASK;
  const syscall_entry *syscall = NULL;
  bool trapped = false;

  switch (id & SYSCALL_CLASS_MASK) {
    case SYSCALL_CLASS_MACH:
      if (idx >= MACH_SYSCALL_NUM) {
        assert(false);
      }
      syscall = &mach_syscalls[idx];
      break;
    case SYSCALL_CLASS_UNIX:
      if (idx >= UNIX_SYSCALL_NUM) {
        assert(false);
      }
      syscall = &unix_syscalls[idx];
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
    assert(syscall->name);
    syscall->func(syscall, cpu, logger);
  }
}

uint64_t lambchop_vm_call(lambchop_vm_t *vm, uint64_t stack_adjust, void *func, int argc, uint64_t *argv, lambchop_logger *logger) {
  uint8_t *stack;
  uint16_t opcode;
  void *cpu = vm->cpu, *insn = vm->insn;
  uint64_t rip, rax;
  int r;

  INFO("lambchop_vm_call start: func = %llx\n", func);
  r = posix_memalign((void**)&stack, 0x4000, 0x100000);
  assert(r >= 0);
  memset(stack, 0, 0x100000);
  set_stack(cpu, stack + 0x100000 - stack_adjust);
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
    } else if (opcode == 0x2b4) {
      DEBUG("ud2\n"); // invalid opcode(SIGILL)を発生させる。
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
  return lambchop_vm_call(vm, LAMBCHOP_VM_DEFAULT_STACK_ADJUST, mainfunc, 0, NULL, logger);
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
