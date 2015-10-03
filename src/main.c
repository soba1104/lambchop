#include "lambchop.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

void signal_handler(int num) {
  fprintf(stderr, "========================== SIGNAL %d ===========================\n", num);
}

int main(int argc, char **argv, char **envp, char **apple) {
  lambchop_logger logger;
  lambchop_vm_t *vm = NULL;
  char *app_path, *dyld_path;
  void *mainfunc;
  int ret = 0;

int i;
for (i = 0; i < 0x20; i++) {
  if (i != SIGINT) {
    signal(i, signal_handler);
  }
}

  if (argc < 3) {
    fprintf(stderr, "usage: lambchop executable_path dyld_path\n");
    goto err;
  }
  app_path = argv[1];
  dyld_path = argv[2];

  if (!lambchop_logger_init(&logger)) {
    fprintf(stderr, "failed to init logger\n");
    goto err;
  }

  if (!lambchop_macho_dump(app_path, &logger)) {
    lambchop_err(&logger, "failed to dump %s\n", app_path);
    goto err;
  }
  if (!lambchop_macho_dump(dyld_path, &logger)) {
    lambchop_err(&logger, "failed to dump %s\n", dyld_path);
    goto err;
  }

  vm = lambchop_vm_alloc();
  if (!vm) {
    lambchop_err(&logger, "failed to allocate vm\n");
    goto err;
  }
  mainfunc = lambchop_macho_load(vm, app_path, dyld_path, &logger, envp, apple);
  if (!mainfunc) {
    lambchop_err(&logger, "failed to load %s, %s\n", app_path, dyld_path);
    goto err;
  }
  ret = lambchop_vm_run(vm, mainfunc, &logger);
  goto out;

err:
  ret = -1;

out:
  if (vm) {
    lambchop_vm_free(vm);
  }

  return ret;
}
