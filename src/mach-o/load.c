#include "lambchop.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <math.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <sys/mman.h>

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
  int64_t slide;
} macho_loader;

static int64_t macho_loader_get_dyld_slide() {
  // TODO randomize
  return -0x100000000;
}

static int64_t macho_loader_get_app_slide() {
  // TODO randomize
  return 0x200000000;
}

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
  for (i = 0; i < sizeof(command->segname) && command->segname[i]; i++);
  if (i == sizeof(command->segname)) {
    ERR("invalid segment name\n");
    return false;
  }
  DEBUG("preparing segment: %s\n", command->segname);

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

static bool macho_loader_prepare_lc_unixthread(macho_loader *loader, struct load_command *__command) {
  struct thread_command *command = (struct thread_command*)__command;
  char *ub = ((char*)command) + command->cmdsize, *p = (char*)(command + 1);

  if (p >= ub) {
    ERR("invalid unixthread command: invalid command size\n");
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
GENERIC_PREPARE_LC(version_min_macosx, struct version_min_command);
GENERIC_PREPARE_LC(source_version, struct source_version_command);
GENERIC_PREPARE_LC(segment_split_info, struct linkedit_data_command);
GENERIC_PREPARE_LC(function_starts, struct linkedit_data_command);
GENERIC_PREPARE_LC(data_in_code, struct linkedit_data_command);
GENERIC_PREPARE_LC(code_signature, struct linkedit_data_command);

static bool macho_loader_prepare_lc(macho_loader *loader, char *ptr, uint32_t ncmds, bool is_app) {
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
      PREPARE_LC_STMT(LC_UNIXTHREAD, unixthread)
      PREPARE_LC_STMT(LC_UUID, uuid)
      PREPARE_LC_STMT(LC_VERSION_MIN_MACOSX, version_min_macosx)
      PREPARE_LC_STMT(LC_SOURCE_VERSION, source_version)
      PREPARE_LC_STMT(LC_SEGMENT_SPLIT_INFO, segment_split_info)
      PREPARE_LC_STMT(LC_FUNCTION_STARTS, function_starts)
      PREPARE_LC_STMT(LC_DATA_IN_CODE, data_in_code)
      PREPARE_LC_STMT(LC_CODE_SIGNATURE, code_signature)
      default:
        // アプリケーションの場合は segment 系命令以外は全て無視していい。
        // なので、未対応の LC が来ても特にエラーは返さない。
        if (!is_app) {
          ERR("illegal or unsupported load command: 0x%x\n", command->cmd);
          return false;
        }
    }
    ptr += command->cmdsize;
  }
  return true;

err:
  ERR("failed to prepare lc\n");
  return false;
}

static bool macho_loader_prepare(macho_loader *loader, bool is_app) {
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
  if (!macho_loader_prepare_lc(loader, ptr, ncmds, is_app)) {
    return false;
  }
  if (!loader->segments) {
    ERR("no segment found\n");
    return false;
  }

  return true;
}

static bool macho_loader_load_segment(macho_loader *loader, void *segment) {
  uint64_t vmaddr, vmsize;
  uint64_t fileoff, filesize;
  int64_t slide = loader->slide;
  void *mapaddr;
  vm_prot_t maxprot, initprot;
  uint32_t nsects, flags;
  const char *segname;
  int prot = 0;

#define INIT_VARS(type) do {\
  type *s = segment; \
  vmaddr = s->vmaddr; \
  vmsize = s->vmsize; \
  fileoff = s->fileoff; \
  filesize = s->filesize; \
  maxprot = s->maxprot; \
  initprot = s->initprot; \
  nsects = s->nsects; \
  flags = s->flags; \
  segname = s->segname; \
  mapaddr = (void*)(vmaddr + slide); \
} while(0)
  if (loader->is32) {
    INIT_VARS(struct segment_command);
  } else {
    INIT_VARS(struct segment_command_64);
  }
#undef INIT_VARS
  DEBUG("-------- loading segment: %s --------\n", segname);
  DEBUG("vmaddr = 0x%llx, vmsize = 0x%llx\n", vmaddr, vmsize);
  DEBUG("mapaddr = 0x%llx, slide = 0x%llx\n", mapaddr, slide);
  DEBUG("fileoff = 0x%llx, filesize = 0x%llx\n", fileoff, filesize);

  if (initprot & VM_PROT_READ) {
    prot |= PROT_READ;
  }
  if (initprot & VM_PROT_WRITE) {
    prot |= PROT_WRITE;
  }
  if (initprot & VM_PROT_EXECUTE) {
    prot |= PROT_EXEC;
  }
  if (mapaddr != mmap(mapaddr, vmsize, prot | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0)) {
    ERR("failed to mmap: %s\n", strerror(errno));
    return false;
  }
  memcpy(mapaddr, loader->img + fileoff, filesize);
  if (mprotect(mapaddr, vmsize, prot) < 0) {
    ERR("failed to mprotect: %s\n", mprotect);
    return false;
  }

  return true;
}

static bool macho_loader_load_segments(macho_loader *loader) {
  void **segments = loader->segments;
  uint32_t nsegs = loader->nsegs, i;

  assert(segments);
  assert(nsegs > 0);

  for (i = 0; i < nsegs; i++) {
    void *segment = segments[i];
    if (!macho_loader_load_segment(loader, segment)) {
      ERR("failed to load segment\n");
      return false;
    }
  }

  return true;
}

static macho_loader *macho_loader_load(char *path, lambchop_logger *logger, bool is_app) {
  macho_loader *loader = NULL;
  char *img = NULL;
  size_t size;

  if (!lambchop_file_read_all(path, logger, &img, &size)) {
    lambchop_err(logger, "failed to read file: path = %s\n", path);
    goto err;
  }

  loader = macho_loader_alloc();
  if (!loader) {
    lambchop_err(logger, "failed to allocate loader: %s\n", strerror(errno));
    goto err;
  }
  loader->img = img;
  loader->imgsize = size;
  loader->logger = logger;
  if (is_app) {
    loader->slide = macho_loader_get_app_slide();
  } else {
    loader->slide = macho_loader_get_dyld_slide();
  }

  lambchop_info(logger, "%s load start\n", path);
  if (!macho_loader_prepare(loader, is_app)) {
    lambchop_err(logger, "failed to prepare loader\n");
    goto err;
  }
  if (!macho_loader_load_segments(loader)) {
    lambchop_err(logger, "failed to load segments\n");
    return false;
  }
  lambchop_info(logger, "%s load finish\n", path);


  return loader;

err:
  if (img) {
    free(img);
  }
  macho_loader_free(loader);

  return NULL;
}

bool lambchop_macho_load(char *app_path, char *dyld_path, lambchop_logger *logger, char **envp, char **apple) {
  macho_loader *dyld_loader = NULL, *app_loader = NULL;
  bool ret = false;

  // TODO dyld のパスを引数で受け取るようにする。
  dyld_loader = macho_loader_load(dyld_path, logger, false);
  if (!dyld_loader) {
    lambchop_err(logger, "failed to load dyld(%s)\n", dyld_path);
    goto out;
  }

  app_loader = macho_loader_load(app_path, logger, true);
  if (!app_loader) {
    lambchop_err(logger, "failed to load app(%s)\n", app_path);
    goto out;
  }

  ret = true;
  goto out;

out:
  macho_loader_free(dyld_loader);
  macho_loader_free(app_loader);

  return ret;
}
