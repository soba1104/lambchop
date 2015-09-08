#include "lambchop.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv, char **envp, char **apple) {
  lambchop_logger logger;
  char *path;
  int ret = 0;
  char *buf = NULL;
  size_t size;

  if (argc < 2) {
    fprintf(stderr, "usage: lambchop executable_path\n");
    goto err;
  }
  path = argv[1];

  if (!lambchop_logger_init(&logger)) {
    fprintf(stderr, "failed to init logger\n");
    goto err;
  }

  buf = lambchop_file_read_all(path, &logger);
  if (!buf) {
    lambchop_err(&logger, "failed to read file: path = %s\n", path);
    goto err;
  }

  if (!lambchop_macho_dump(buf, size, &logger)) {
    lambchop_err(&logger, "failed to dump %s\n", path);
    goto err;
  }
  if (!lambchop_macho_load(buf, size, &logger, envp, apple)) {
    lambchop_err(&logger, "failed to load %s\n", path);
    goto err;
  }

  goto out;

err:
  ret = -1;

out:
  if (buf) {
    free(buf);
  }

  return ret;
}
