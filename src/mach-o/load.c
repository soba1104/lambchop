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
  void **segments;
  uint32_t nsegs;
} macho_loader;

static void macho_loader_free(macho_loader *loader) {
  if (!loader) {
    return;
  }
  if (loader->segments) {
    free(loader->segments);
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

// TODO section の解釈
static bool macho_loader_prepare_lc_segment_64(macho_loader *loader, struct load_command *__command) {
  struct segment_command_64 *command = (struct segment_command_64*)__command;
  char *ub = ((char*)command) + command->cmdsize, *p = (char*)(command + 1);
  void *segs;
  int i;

  for (i = 0; i < command->nsects; i++) {
    struct section_64 *sections = (struct section_64*)(command+1);
    struct section_64 *section = sections + i;
    p += sizeof(struct section_64);
    if (p > ub) {
      ERR("too large section\n");
      return false;
    }
  }
  if (p != ub) {
    ERR("invalid segment_64 command\n");
    return false;
  }

  segs = realloc(loader->segments, sizeof(void*) * (loader->nsegs + 1));
  if (!segs) {
    ERR("failed to allocate segment buffer: %s\n", strerror(errno));
    return false;
  }
  loader->segments = segs;
  loader->segments[loader->nsegs] = command;
  loader->nsegs++;
  return true;
}

static bool macho_loader_prepare_lc_id_dylinker(macho_loader *loader, struct load_command *__command) {
  struct dylinker_command *command = (struct dylinker_command*)__command;
  char *ub = ((char*)command) + command->cmdsize, *p = (char*)(command + 1);

  if (p >= ub) {
    ERR("invalid id_dylinker command: invalid command size\n");
    return false;
  }

  p = ((char*)command) + command->name.offset;
  if (p >= ub) {
    ERR("invalid id_dylinker command: too long name\n");
    return false;
  }

  return true;
}

#define GENERIC_PREPARE_LC(name, type) \
static bool macho_loader_prepare_lc_##name(macho_loader *loader, struct load_command *__command) { \
  type *command = (type*)__command; \
  char *ub = ((char*)command) + command->cmdsize, *p = (char*)(command + 1); \
  if (p != ub) { \
    ERR("invalid " #name " command: invalid command size\n"); \
    return false; \
  } \
  return true; \
}

GENERIC_PREPARE_LC(symtab, struct symtab_command);
GENERIC_PREPARE_LC(dysymtab, struct dysymtab_command);
GENERIC_PREPARE_LC(uuid, struct uuid_command);

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
#define PREPARE_LC_STMT(lc, name) \
      case lc: \
        if (!macho_loader_prepare_lc_##name(loader, command)) { \
          ERR("failed to prepare " #name " command\n"); \
          return false; \
        } \
        break;
      PREPARE_LC_STMT(LC_SEGMENT_64, segment_64)
      PREPARE_LC_STMT(LC_SYMTAB, symtab)
      PREPARE_LC_STMT(LC_DYSYMTAB, dysymtab)
      PREPARE_LC_STMT(LC_ID_DYLINKER, id_dylinker)
      PREPARE_LC_STMT(LC_UUID, uuid)
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
