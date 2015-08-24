#include "lambchop.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
  lambchop_logger logger;
  char *path;
  int fd, size, ret = 0;
  struct stat st;
  char *buf = NULL;

  if (argc < 2) {
    fprintf(stderr, "usage: lambchop executable_path\n");
    goto err;
  }
  path = argv[1];

  if (!lambchop_logger_init(&logger)) {
    fprintf(stderr, "failed to init logger\n");
    goto err;
  }

  fd = open(path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
    goto err;
  }

  if (fstat(fd, &st) < 0) {
    fprintf(stderr, "failed to get file stat: %s\n", strerror(errno));
    goto err;
  }
  size = st.st_size;

  lambchop_info(&logger, "target file = %s\n", path);
  lambchop_info(&logger, "size = %d\n", size);

  buf = malloc(size);
  if (!buf) {
    fprintf(stderr, "failed to allocate buffer: %s\n", strerror(errno));
    goto err;
  }

  goto out;

err:
  ret = -1;

out:
  if (fd >= 0) {
    close(fd);
  }
  if (buf) {
    free(buf);
  }

  return ret;
}
