#include "lambchop.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <math.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#define ERR(...) lambchop_err(loader->logger, __VA_ARGS__)
#define INFO(...) lambchop_info(loader->logger, __VA_ARGS__)
#define DEBUG(...) lambchop_debug(loader->logger, __VA_ARGS__)

typedef struct {
  bool is32;
  char *img;
  size_t imgsize;
  lambchop_logger *logger;
} macho_loader;

static void macho_loader_free(macho_loader *loader) {
  if (!loader) {
    return;
  }
  free(loader);
}

static macho_loader *macho_loader_alloc(void) {
  macho_loader *loader = malloc(sizeof(macho_loader));
  if (!loader) {
    return NULL;
  }
  memset(loader, 0, sizeof(macho_loader));
  return loader;
}

static bool macho_loader_prepare_lc(macho_loader *loader, char *ptr, uint32_t ncmds) {
  char *ub = loader->img + loader->imgsize;
  int i;
  for (i = 0; i < ncmds; i++) {
    struct load_command *command = (struct load_command*)ptr;
    if ((ptr + command->cmdsize)  >= ub) {
      ERR("too large lc\n");
      goto err;
    }
    switch(command->cmd) {
      default:
        ERR("illegal or unsupported load command: 0x%x\n", command->cmd);
        return false;
    }
    ptr += command->cmdsize;
  }
  return true;

err:
  ERR("failed to prepare lc\n");
  return false;
}

static bool macho_loader_prepare(macho_loader *loader) {
  char *ptr = loader->img;
  uint32_t magic = *(uint32_t*)(ptr);
  uint32_t ncmds;

  if (magic == MH_MAGIC) {
    struct mach_header *hdr = (struct mach_header*)ptr;
    loader->is32 = true;
    ncmds = hdr->ncmds;
    ptr += sizeof(struct mach_header);
  } else if (magic == MH_MAGIC_64) {
    struct mach_header_64 *hdr = (struct mach_header_64*)ptr;
    loader->is32 = false;
    ncmds = hdr->ncmds;
    ptr += sizeof(struct mach_header_64);
  } else {
    ERR("invalid magic %x\n", magic);
    return false;
  }

  DEBUG("prepare lc: ncmds = %u\n", ncmds);
  if (!macho_loader_prepare_lc(loader, ptr, ncmds)) {
    return false;
  }

  return true;
}

bool lambchop_macho_load(char *img, size_t size, lambchop_logger *logger) {
  macho_loader *loader = NULL;
  bool ret;

  loader = macho_loader_alloc();
  if (!loader) {
    lambchop_err(logger, "failed to allocate loader: %s\n", strerror(errno));
    ret = false;
    goto out;
  }
  loader->img = img;
  loader->imgsize = size;
  loader->logger = logger;

  lambchop_info(logger, "mach-o load start\n");
  ret = macho_loader_prepare(loader);

out:
  macho_loader_free(loader);
  if (ret) {
    lambchop_info(logger, "mach-o load finish\n");
  } else {
    lambchop_err(logger, "mach-o load failure\n");
  }
  return ret;
}
