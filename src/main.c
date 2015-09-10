#include "lambchop.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv, char **envp, char **apple) {
  lambchop_logger logger;
  char *app_path, *dyld_path;
  void *mainfunc;
  int ret = 0;

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
  mainfunc = lambchop_macho_load(app_path, dyld_path, &logger, envp, apple);
  if (!mainfunc) {
    lambchop_err(&logger, "failed to load %s, %s\n", app_path, dyld_path);
    goto err;
  }
  ret = lambchop_vm_run(mainfunc, &logger);
  goto out;

err:
  ret = -1;

out:
  return ret;
}
