#include "lambchop.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

static bool readn(int fd, char *buf, size_t size) {
  int idx = 0;

  while (idx < size) {
    int ret = read(fd, buf + idx, size - idx);
    if (ret < 0) {
      return false;
    } else if (ret == 0) {
      return false;
    }
    idx += ret;
  }
  return true;
}

bool lambchop_file_read_all(const char *path, lambchop_logger *logger, char **bufp, size_t *sizep) {
  int fd = -1;
  struct stat st;
  size_t size;
  char *buf = NULL;
  bool ret;

  fd = open(path, O_RDONLY);
  if (fd < 0) {
    lambchop_err(logger, "failed to open %s: %s\n", path, strerror(errno));
    goto err;
  }

  if (fstat(fd, &st) < 0) {
    lambchop_err(logger, "failed to get file stat: %s\n", strerror(errno));
    goto err;
  }
  size = st.st_size;

  buf = malloc(size);
  if (!buf) {
    lambchop_err(logger, "failed to allocate buffer: %s\n", strerror(errno));
    goto err;
  }

  if (!readn(fd, buf, size)) {
    lambchop_err(logger, "failed to read %zu bytes from %s: %s\n", size, path, strerror(errno));
    goto err;
  }

  *bufp = buf;
  *sizep = size;
  ret = true;

  goto out;

err:
  if (buf) {
    free(buf);
    buf = NULL;
  }
  ret = false;

out:
  if (fd >= 0) {
    close(fd);
  }

  return ret;
}
