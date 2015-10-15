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
  /*if ((count++) <= 175000000) {*/
  if ((count++) <= 400000000) {
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
  if (strcmp(syscall->name, "thread_switch") != 0) {
    // thread_switch は大量に吐かれるのでログ出力しない。
    DEBUG("SYSCALL PASSTHROUGH: %s(0x%llx)(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx) = 0x%llx, 0x%llx\n",
          syscall->name, id, a0, a1, a2, a3, a4, a5, idret, rflags);
  }
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

static void syscall_callback_sigaltstack(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  stack_t *ss = (stack_t*)get_rdi(cpu);
  stack_t *oss = (stack_t*)get_rsi(cpu);
  DEBUG("SYSCALL: sigaltstack(");
  if (ss) {
    DEBUG("{0x%p, 0x%llx, 0x%x}", ss->ss_sp, ss->ss_size, ss->ss_flags);
  } else {
    DEBUG("NULL");
  }
  DEBUG(", ");
  if (oss) {
    DEBUG("{0x%p, 0x%llx, 0x%x}", oss->ss_sp, oss->ss_size, oss->ss_flags);
  } else {
    DEBUG("NULL");
  }
  DEBUG(")\n");

  // TODO シグナル発生時のスタックを置き換える。
  clear_cf(cpu);
  set_rax(cpu, 0);
}

typedef struct {
  uint64_t orig_func;
  uint64_t orig_func_arg;
  uint64_t orig_stack;
  uint64_t orig_pthread;
  uint32_t orig_flags;
  void *tls;
  void *stack;
  uint64_t stack_size;
  lambchop_logger *logger;
} bsdthread_arg;

static uint64_t bsdthread_start;
static uint64_t wqthread_start;

// TLS_SIZE は自分で適当に定めた値。とりあえず1MBにしておいた。
#define TLS_SIZE 0x100000

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
  lambchop_vm_t *vm = lambchop_vm_alloc(arg->stack, arg->stack_size);

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
  // stack と tls は vm が解放するので個別に free を呼び出す必要はない。
  lambchop_vm_call(vm, LAMBCHOP_VM_PTHREAD_STACK_ADJUST, (void*)bsdthread_start, 6, argv, logger);
  lambchop_vm_free(vm);
  free(arg);
  DEBUG("------------- bsdthread handler end --------------\n");
}

int _pthread_workqueue_supported();
static void wqthread_handler(int priority) {
// libpthread の private/qos_private.h から持ってきたマクロ
#define _PTHREAD_PRIORITY_FLAGS_MASK    (~0xffffff)
#define _PTHREAD_PRIORITY_QOS_CLASS_MASK  0x00ffff00
#define _PTHREAD_PRIORITY_QOS_CLASS_SHIFT (8ull)
#define _PTHREAD_PRIORITY_PRIORITY_MASK   0x000000ff
#define _PTHREAD_PRIORITY_PRIORITY_SHIFT  (0)

#define _PTHREAD_PRIORITY_OVERCOMMIT_FLAG 0x80000000
#define _PTHREAD_PRIORITY_INHERIT_FLAG    0x40000000
#define _PTHREAD_PRIORITY_ROOTQUEUE_FLAG  0x20000000
#define _PTHREAD_PRIORITY_ENFORCE_FLAG    0x10000000
#define _PTHREAD_PRIORITY_OVERRIDE_FLAG   0x08000000

// libpthread の kern/workqueue_internal.h から持ってきたマクロ
#define WQ_FLAG_THREAD_PRIOMASK   0x0000ffff
#define WQ_FLAG_THREAD_PRIOSHIFT  (8ull)
#define WQ_FLAG_THREAD_OVERCOMMIT 0x00010000
#define WQ_FLAG_THREAD_REUSE      0x00020000
#define WQ_FLAG_THREAD_NEWSPI     0x00040000

#define __PTHREAD_PRIORITY_CBIT_USER_INTERACTIVE 0x20
#define __PTHREAD_PRIORITY_CBIT_USER_INITIATED 0x10
#define __PTHREAD_PRIORITY_CBIT_DEFAULT 0x8
#define __PTHREAD_PRIORITY_CBIT_UTILITY 0x4
#define __PTHREAD_PRIORITY_CBIT_BACKGROUND 0x2
#define __PTHREAD_PRIORITY_CBIT_MAINTENANCE 0x1
#define __PTHREAD_PRIORITY_CBIT_UNSPECIFIED 0x0

// ibpthread の kern/kern_internal.h から持ってきたマクロ
#define PTHREAD_FEATURE_DISPATCHFUNC    0x01
#define PTHREAD_FEATURE_FINEPRIO        0x02
#define PTHREAD_FEATURE_BSDTHREADCTL    0x04
#define PTHREAD_FEATURE_SETSELF         0x08
#define PTHREAD_FEATURE_QOS_MAINTENANCE 0x10
#define PTHREAD_FEATURE_QOS_DEFAULT     0x40000000

  // flags に対し、overcommit, reuse, newspi の3項目と、class というものを設定する必要がある。
  int features = _pthread_workqueue_supported();
  int flags = 0;

  assert(features & PTHREAD_FEATURE_QOS_MAINTENANCE); // これによって priority の計算方法が変わる
  assert(features & PTHREAD_FEATURE_FINEPRIO); // これによってコールバックの引数が変わる。

  // assert で WQ_FLAG_THREAD_NEWSPI が常に on になっていることを期待していたのでそれに従う。
  flags |= WQ_FLAG_THREAD_NEWSPI;

  // thread の初期化処理を走らせたいので reuse は常に off にする。
  flags &= ~WQ_FLAG_THREAD_REUSE;

  // overcommit の有無は priority に埋め込まれている。
  if (priority & _PTHREAD_PRIORITY_OVERCOMMIT_FLAG) {
    flags |= WQ_FLAG_THREAD_OVERCOMMIT;
  }

  // class も同様に priority に埋め込まれている。
  {
    int class = (priority & _PTHREAD_PRIORITY_QOS_CLASS_MASK) >> _PTHREAD_PRIORITY_QOS_CLASS_SHIFT;
    switch(class) {
      case __PTHREAD_PRIORITY_CBIT_USER_INTERACTIVE:
        flags |= QOS_CLASS_USER_INTERACTIVE;
        break;
      case __PTHREAD_PRIORITY_CBIT_USER_INITIATED:
        flags |= QOS_CLASS_USER_INITIATED;
        break;
      case __PTHREAD_PRIORITY_CBIT_DEFAULT:
        flags |= QOS_CLASS_DEFAULT;
        break;
      case __PTHREAD_PRIORITY_CBIT_UTILITY:
        flags |= QOS_CLASS_UTILITY;
        break;
      case __PTHREAD_PRIORITY_CBIT_BACKGROUND:
        flags |= QOS_CLASS_BACKGROUND;
        break;
#if 0
        // /usr/include/pthread.h から参照できないので除外した。
      case __PTHREAD_PRIORITY_CBIT_MAINTENANCE:
        flags |= QOS_CLASS_MAINTENANCE;
        break;
#endif
      case __PTHREAD_PRIORITY_CBIT_UNSPECIFIED:
        flags |= QOS_CLASS_UNSPECIFIED;
        break;
      default:
        assert(false);
    }
  }

  {
    lambchop_logger __logger;
    lambchop_logger *logger = &__logger;
    lambchop_vm_t *vm;
    uint64_t guard_size = 0; // FIXME
    uint64_t stack_size = 0x100000; // 適当に 1MB 割り当てる。
    uint64_t tls_size = TLS_SIZE;
    uint8_t *p, *guard, *stack, *tls;
    uint64_t argv[5];
    int r;

    if (!lambchop_logger_init(logger)) {
      assert(false);
    }

    // TODO 以下のスタックや TLS 割り当てまわりの処理を bsdthread_create のコールバックと共通化する。
    // TODO mprotect を使ってスタックオーバーフローを検出できるようにする。
    // TODO ガード領域を設定する。

    // (low) guard -> stack -> tls (high)
    r = posix_memalign((void**)&p, 0x4000, guard_size + stack_size + tls_size);
    assert(r >= 0);
    memset(p, 0, guard_size + stack_size + tls_size);
    guard = p;
    stack = p + guard_size;
    tls = p + guard_size + stack_size;

    // TODO guard == 0 じゃないと free でコケるのでどうにかする。
    vm = lambchop_vm_alloc(stack, stack_size);
    assert(vm);

    argv[0] = (uint64_t)tls;
    argv[1] = (uint64_t)pthread_mach_thread_np(pthread_self());
    argv[2] = (uint64_t)stack;
    argv[3] = 0; // unused
    argv[4] = flags;

    lambchop_vm_call(vm, LAMBCHOP_VM_PTHREAD_STACK_ADJUST, (void*)wqthread_start, 5, argv, logger);
    lambchop_vm_free(vm);
  }
}

static void syscall_callback_bsdthread_create(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t orig_func = get_rdi(cpu);
  uint64_t orig_func_arg = get_rsi(cpu);
  uint64_t orig_stack = get_rdx(cpu); // stack size
  uint64_t orig_pthread = get_r10(cpu); // ???
  uint32_t orig_flags = (uint32_t)get_r8(cpu);
  uint64_t stack_size;
  void *tls, *stack;
  int r;
  bsdthread_arg *arg = malloc(sizeof(bsdthread_arg)); // 解放は生成したスレッドで行う。

  assert(arg);
  assert(!(orig_flags & PTHREAD_START_SETSCHED));
  DEBUG("SYSCALL: bsdthread_create(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%x)\n",
        orig_func, orig_func_arg, orig_stack, orig_pthread, orig_flags);

  assert(orig_pthread == 0);
  assert(bsdthread_start);
  arg->orig_func = orig_func;
  arg->orig_func_arg = orig_func_arg;
  arg->orig_stack = orig_stack;
  arg->orig_pthread = orig_pthread;
  arg->orig_flags = orig_flags;
  arg->logger = logger;

  if (!(orig_flags & PTHREAD_START_CUSTOM)) {
    stack_size = orig_stack;
  } else {
    assert(false);
  }

  // 解放は生成したスレッドで行う。
  // stack と tls の領域は並んでいないといけないのでまとめて割り当てる。
  r = posix_memalign(&stack, 0x4000, stack_size + TLS_SIZE);
  assert(r >= 0);
  memset(stack, 0, stack_size + TLS_SIZE);
  tls = stack + stack_size;
  arg->tls = tls;
  arg->stack = stack;
  arg->stack_size = stack_size;

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
  set_r8(cpu, orig_flags & ~PTHREAD_START_CUSTOM);
  syscall_callback_passthrough(syscall, cpu, logger); // TODO pthread_create を使うか検討する。
  set_rdi(cpu, orig_func);
  set_rsi(cpu, orig_func_arg);
  set_rdx(cpu, orig_stack);
  set_r10(cpu, orig_pthread);
  set_r8(cpu, orig_flags);
  {
    // bsdthread_create は返り値に pthread_self の値(兼 TLS 領域)を返すので差し替える。
    assert(get_rax(cpu) >= 0);
    set_rax(cpu, (uint64_t)tls);
    // ここから抜けて pthread_create に戻って処理を進めるまでの間に
    // 生成したスレッドが動き出しても問題なさそうだった。
    // 排他制御を libpthread がかけていた。
  }
}

static void syscall_callback_bsdthread_terminate(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t stackaddr = get_rdi(cpu);
  size_t size = get_rsi(cpu);
  uint32_t kthport = get_rdx(cpu);
  uint32_t sem = get_r10(cpu);

  // TODO メモリの解放

  DEBUG("SYSCALL: bsdthread_terminate(0x%llx, 0x%llx, 0x%x, 0x%x)\n", stackaddr, size, kthport, sem);
  pthread_exit(NULL);
  assert(false);
}

static void syscall_callback_bsdthread_register(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  uint64_t threadstart = get_rdi(cpu);
  uint64_t wqthread = get_rsi(cpu);
  int pthsize = (int)get_rdx(cpu);
  uint64_t pthread_init_data = get_r10(cpu);
  uint64_t targetconc_ptr = get_r8(cpu);
  uint64_t dispatchqueue_offset = get_r9(cpu);

  assert(!bsdthread_start);
  bsdthread_start = threadstart;
  wqthread_start = wqthread;
  DEBUG("SYSCALL: bsdthread_register(0x%llx, 0x%llx, 0x%x, 0x%llx, 0x%llx, 0x%llx)\n",
        threadstart, wqthread, pthsize, pthread_init_data, targetconc_ptr, dispatchqueue_offset);
  // 2度目以降の register は無視されるので passthrough する意味が無い。
  /*syscall_callback_passthrough(syscall, cpu, logger);*/
  clear_cf(cpu);
  set_rax(cpu, (uint64_t)_pthread_workqueue_supported());
}

/*int pthread_workqueue_setdispatch_np(void *func); // old api*/
int _pthread_workqueue_init(void *func, int offset, int flags); // new api
static void syscall_callback_workq_kernreturn(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  // rsi に入っている引数はこのシステムコールだと無視されるので気にしない。
  uint32_t options = get_rdi(cpu);
  uint32_t arg2 = get_rdx(cpu);
  uint32_t arg3 = get_r10(cpu);

  // 以下は libpthread の kern/workqueue_internal.h から持ってきたマクロ
#define WQOPS_THREAD_RETURN 4
#define WQOPS_QUEUE_NEWSPISUPP  0x10
#define WQOPS_QUEUE_REQTHREADS  0x20
#define WQOPS_QUEUE_REQTHREADS2 0x30
  switch (options) {
    case WQOPS_QUEUE_NEWSPISUPP:
      // ここで libdispatch_offset が設定される。
      // pthread_supported_features を上書きしてよいか現状分かっていない。
      // そのような条件だと new api のほうが priority から pthread_wqthread の引数を再構築しやすいので、
      // new api が使用する _pthread_workqueue_init を使用する。
      // ちなみに、old api は pthread_workqueue_setdispatchoffset_np と pthread_workqueue_setdispatch_np を使用する。
      //
      // _pthread_workqueue_init の引数である flags と offset のうち、
      // flags は現在参照している pthread だと 0 じゃないといけないので常に 0 を指定してよい。
      // また、offset には workq_kernreturn が WQOPS_QUEUE_NEWSPISUPP で呼ばれたときの arg2 を渡せばよい。
      //
      // なお、_pthread_workqueue_init の中で、workq_kernreturn を呼び出し、
      // カーネル内部の libdispatch serialno を上書きしてしまうので、
      // workq_kernreturn を passthrough する前に lambchop がこの関数を実行する必要がある。
      // old api を使用して、pthread_workqueue_setdispatchoffset_np を使う場合も同様。
      _pthread_workqueue_init(wqthread_handler, arg2, 0);

      DEBUG("SYSCALL: workq_kernreturn(NEWSPISUPP, offset=0x%x)\n", arg2);
      break;
    case WQOPS_QUEUE_REQTHREADS:
      DEBUG("SYSCALL: workq_kernreturn(REQTHREADS, reqcount=0x%x, priority=0x%x)\n", arg2, arg3);
      break;
    case WQOPS_THREAD_RETURN:
      DEBUG("SYSCALL: workq_kernreturn(RETURN)\n");
      break;
    default:
      assert(false);
  }
  syscall_callback_passthrough(syscall, cpu, logger);
}

static void syscall_callback_syscall(const syscall_entry *syscall, void *cpu, lambchop_logger *logger) {
  int num = get_rdi(cpu);
  DEBUG("SYSCALL: syscall(%d)\n", num); // TODO 置き換え対象のシステムコールが呼ばれたかどうかの検出
  syscall_callback_passthrough(syscall, cpu, logger);
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
  uint16_t opcode;
  void *cpu = vm->cpu, *insn = vm->insn;
  uint64_t rip, rax;
  int r;

  INFO("lambchop_vm_call start: func = %llx\n", func);
  set_stack(cpu, (uint8_t*)vm->stack + vm->stack_size - stack_adjust);
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
  INFO("lambchop_vm_call finish: ret = %llx\n", rax);
  return rax;
}

int lambchop_vm_run(lambchop_vm_t *vm, void *mainfunc, lambchop_logger *logger) {
  // TODO 引数を扱えるようにする。
  /*return ((int(*)(void))mainfunc)();*/
  return lambchop_vm_call(vm, LAMBCHOP_VM_DEFAULT_STACK_ADJUST, mainfunc, 0, NULL, logger);
}

lambchop_vm_t *lambchop_vm_alloc(void *stack, uint64_t stack_size) {
  lambchop_vm_t *vm = malloc(sizeof(lambchop_vm_t));
  void *cpu = alloc_cpu();
  void *insn = alloc_insn();

  if (!stack) {
    int r = posix_memalign((void**)&stack, 0x4000, stack_size);
    assert(r >= 0);
  }
  memset(stack, 0, stack_size);

  assert(vm);
  assert(cpu);
  assert(insn);
  vm->cpu = cpu;
  vm->insn = insn;
  vm->stack = stack;
  vm->stack_size = stack_size;

  return vm;
}

void lambchop_vm_free(lambchop_vm_t *vm) {
  free_insn(vm->insn);
  free_cpu(vm->cpu);
  free(vm->stack);
  free(vm);
}
