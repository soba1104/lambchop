#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <stdbool.h>

typedef enum {
  EXITED,
  SIGNALED,
  STOPPED
} exitstatus;

static void fatal(char *errmsg) {
  fprintf(stderr, "%s", errmsg);
  exit(-1);
}

static void dumpstate(task_t port) {
	thread_act_array_t threads;
	mach_msg_type_number_t numthreads;
  x86_thread_state64_t state;
  mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;

  if (task_suspend(port)) {
    fatal("failed to suspend port\n");
  }

  if (task_threads(port, &threads, &numthreads)) {
    fatal("failed to get thread list\n");
  }

  if (thread_get_state(threads[0], x86_THREAD_STATE64, (thread_state_t)&state, &count)) {
    fatal("failed to get thread state\n");
  }

  printf("0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx\n",
         state.__rip,
         state.__rax,
         state.__rbx,
         state.__rcx,
         state.__rdx,
         state.__rdi,
         state.__rsi,
         state.__rbp,
         state.__rsp,
         state.__r8,
         state.__r9,
         state.__r10,
         state.__r11,
         state.__r12,
         state.__r13,
         state.__r14,
         state.__r15,
         state.__rflags
        );
  if (task_resume(port)) {
    fatal("failed to resume port\n");
  }
}

static int waitchild(pid_t pid, exitstatus expect) {
  int status;
  bool ok;
  waitpid(pid, &status, 0);
  switch (expect) {
    case EXITED:
      ok = WIFEXITED(status);
      break;
    case SIGNALED:
      ok = WIFSIGNALED(status);
      break;
    case STOPPED:
      ok = WIFSTOPPED(status);
      break;
    default:
      fatal("invalid exitstatus\n");
  }
  if (!ok) {
    fprintf(stderr, "exit status = %d\n", status);
    fprintf(stderr, "WEXITSTATUS = %d\n", WEXITSTATUS(status));
    fprintf(stderr, "WSTOPSIG = %d\n", WSTOPSIG(status));
    fprintf(stderr, "WIFCONTINUED = %d\n", WIFCONTINUED(status));
    fprintf(stderr, "WIFSTOPPED = %d\n", WIFSTOPPED(status));
    fprintf(stderr, "WIFEXITED = %d\n", WIFEXITED(status));
    fprintf(stderr, "WIFSIGNALED = %d\n", WIFSIGNALED(status));
    fprintf(stderr, "WTERMSIG = %d\n", WTERMSIG(status));
    fprintf(stderr, "WCOREDUMP = %d\n", WCOREDUMP(status));
    fatal("unexpected exitstatus\n");
  }
  return status;
}

static void attach(pid_t pid) {
  if (ptrace(PT_ATTACH, pid, NULL, 0) < 0) {
    perror("attach: ");
    fatal("failed to attach\n");
  }
  waitchild(pid, STOPPED);
}

static void detach(pid_t pid) {
  if (ptrace(PT_DETACH, pid, NULL, 0) < 0) {
    perror("detach: ");
    fatal("failed to detach\n");
  }
}

static void step(pid_t pid) {
  if (ptrace(PT_STEP, pid, (caddr_t)1, 0) < 0) {
    fatal("failed to step\n");
  }
  waitchild(pid, STOPPED);
}

static void traceme(void) {
  if (ptrace(PT_TRACE_ME, 0, NULL, 0) < 0) {
    fatal("failed to call ptrace(PT_TRACE_ME)\n");
  }
}

static task_t get_port(pid_t pid) {
  task_t port;
  if (task_for_pid(mach_task_self(), pid, &port)) {
    fatal("failed to get port\n");
  }
  return port;
}

static void trace() {
  pid_t pid = fork();
  if (pid) {
    int status, i;
    attach(pid);
    task_t port = get_port(pid);
    for (i = 0;; i++) {
      printf("%d ", i++);
      dumpstate(port);
      step(pid);
    }
    detach(pid);
    printf("detached\n");
    waitchild(pid, EXITED);
    exit(0);
  } else {
    sleep(1);
    printf("------- start -------\n");
  }
}

void lambchop_trace() {
  trace();
}
