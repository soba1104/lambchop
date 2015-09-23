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
  uint64_t hdrvm;
  uint32_t symoff;
  uint32_t nsyms;
  uint32_t stroff;
  uint32_t strsize;
  int64_t slide;
} macho_loader;

static int64_t macho_loader_get_dyld_slide(bool is32) {
  // TODO randomize
  return is32 ? 0x800000000 : -0x100000000;
}

static int64_t macho_loader_get_app_slide(bool is32) {
  // TODO randomize
  return is32 ? 0x800000000 : 0x200000000;
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

#define MACHO_LOADER_PREPARE_LC_SEGMENT_COMMON(segtype, secttype) do { \
  segtype *command = (segtype*)__command; \
  char *ub = ((char*)command) + command->cmdsize, *p = (char*)(command + 1); \
  void *segs; \
  int i; \
\
  if (p > ub) { \
    ERR("invalid segment/segment64 command: invalid command size\n"); \
    return false; \
  } \
  for (i = 0; i < command->nsects; i++) { \
    secttype *sections = (secttype*)(command+1); \
    secttype *section = sections + i; \
    p += sizeof(secttype); \
    if (p > ub) { \
      ERR("too large section info\n"); \
      return false; \
    } \
  } \
  if (p != ub) { \
    ERR("invalid segment/segment_64 command\n"); \
    return false; \
  } \
  for (i = 0; i < sizeof(command->segname) && command->segname[i]; i++); \
  if (i == sizeof(command->segname)) { \
    ERR("invalid segment name\n"); \
    return false; \
  } \
  DEBUG("preparing segment: %s\n", command->segname); \
\
  segs = realloc(loader->segments, sizeof(void*) * (loader->nsegs + 1)); \
  if (!segs) { \
    ERR("failed to allocate segment buffer: %s\n", strerror(errno)); \
    return false; \
  } \
  loader->segments = segs; \
  loader->segments[loader->nsegs] = command; \
  loader->nsegs++; \
  if (command->fileoff == 0 && command->filesize > 0) { \
    loader->hdrvm = command->vmaddr + loader->slide; \
  } \
  return true; \
} while(0)

static bool macho_loader_prepare_lc_segment(macho_loader *loader, struct load_command *__command) {
  if (!loader->is32) {
    ERR("unexpected 64bit segment\n");
    return false;
  }
  MACHO_LOADER_PREPARE_LC_SEGMENT_COMMON(struct segment_command, struct section);
}

static bool macho_loader_prepare_lc_segment_64(macho_loader *loader, struct load_command *__command) {
  if (loader->is32) {
    ERR("unexpected 32bit segment\n");
    return false;
  }
  MACHO_LOADER_PREPARE_LC_SEGMENT_COMMON(struct segment_command_64, struct section_64);
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

static ssize_t macho_loader_strlen(char *p, char *ub) {
  int i;
  for (i = 0; (p + i) < ub &&  p[i]; i++);
  return (p + i) == ub ? -1 : i;
}

static bool macho_loader_prepare_lc_symtab(macho_loader *loader, struct load_command *__command) {
  struct symtab_command *command = (struct symtab_command*)__command;
  char *ub = ((char*)command) + command->cmdsize, *p = (char*)(command + 1);
  uint64_t symsize;
  int i;

  if (p != ub) {
    ERR("invalid symtab command: invalid command size\n");
    return false;
  }
  if (loader->is32) {
    symsize = sizeof(struct nlist) * command->nsyms;
  } else {
    symsize = sizeof(struct nlist_64) * command->nsyms;
  }
  if ((command->symoff + symsize) > loader->imgsize) {
    ERR("invalid symtab command: too large symbol table\n");
    return false;
  }
  if ((command->stroff + command->strsize) > loader->imgsize) {
    ERR("invalid symtab command: too large string table\n");
    return false;
  }

  ub = loader->img + command->stroff + command->strsize;
  for (i = 0; i < command->nsyms; i++) {
    void *symbol_table = loader->img + command->symoff;
    char *string_table = loader->img + command->stroff, *sym;
    if (loader->is32) {
      struct nlist *nl = ((struct nlist*)symbol_table) + i;
      sym = nl->n_un.n_strx ? string_table + nl->n_un.n_strx : "\"\"";
    } else {
      struct nlist_64 *nl = ((struct nlist_64*)symbol_table) + i;
      sym = nl->n_un.n_strx ? string_table + nl->n_un.n_strx : "\"\"";
    }
    if (macho_loader_strlen(sym, ub) < 0) {
      ERR("invalid symtab command: invaild symbol string\n");
      return false;
    }
  }

  loader->symoff = command->symoff;
  loader->nsyms = command->nsyms;
  loader->stroff = command->stroff;
  loader->strsize = command->strsize;

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
      PREPARE_LC_STMT(LC_SEGMENT, segment)
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

  if (is_app) {
    loader->slide = macho_loader_get_app_slide(loader->is32);
  } else {
    loader->slide = macho_loader_get_dyld_slide(loader->is32);
  }

  DEBUG("prepare lc: ncmds = %u\n", ncmds);
  if (!macho_loader_prepare_lc(loader, ptr, ncmds, is_app)) {
    return false;
  }
  if (!loader->segments) {
    ERR("no segment found\n");
    return false;
  }
  if (!loader->hdrvm) {
    ERR("header segment not found\n");
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

char **macho_loader_setup_dyld_args(macho_loader *loader, char **envp, char **apple) {
  int numenv, numapple, i;
  char **args = NULL;

  for (numenv = 0; envp[numenv]; numenv++) {
    DEBUG("envp[%d] = %s\n", numenv, envp[numenv]);
  }
  numenv++;

  for (numapple = 0; apple[numapple]; numapple++) {
    DEBUG("apple[%d] = %s\n", numapple, apple[numapple]);
  }
  numapple++;

  DEBUG("numenv = %d, numapple = %d\n", numenv, numapple);
  args = malloc(sizeof(char*) * (numenv + numapple));
  if (!args) {
    ERR("failed to allocate dyld args buffer: %s\n", strerror(errno));
    return NULL;
  }

  for (i = 0; i < numenv; i++) {
    args[i] = envp[i];
  }
  for (i = 0; i < numapple; i++) {
    args[numenv + i] = apple[i];
  }

  return args;
}

static uint64_t macho_loader_find_symbol(macho_loader *loader, const char *name) {
  void *symbol_table = loader->img + loader->symoff;
  char *string_table = loader->img + loader->stroff;
  uint32_t i;

  for (i = 0; i < loader->nsyms; i++) {
    char *sym;
    uint64_t val;
    if (loader->is32) {
      struct nlist *nl = ((struct nlist*)symbol_table) + i;
      sym = nl->n_un.n_strx ? string_table + nl->n_un.n_strx : "\"\"";
      val = nl->n_value;
    } else {
      struct nlist_64 *nl = ((struct nlist_64*)symbol_table) + i;
      sym = nl->n_un.n_strx ? string_table + nl->n_un.n_strx : "\"\"";
      val = nl->n_value;
    }
    if (strcmp(sym, name) == 0) {
      return val;
    }
  }

  return 0;
}

static void *macho_loader_call_dyld(macho_loader *dyld_loader, macho_loader *app_loader, char **args) {
  lambchop_logger *logger = dyld_loader->logger;
  uintptr_t glue = 0;
  void *(*dyldfunc)(uint64_t app_hdr, int argc, char **args, intptr_t slide, uint64_t dyld_hdr, uintptr_t *glue);
  const char *dyldfunc_name = "__ZN13dyldbootstrap5startEPK12macho_headeriPPKclS2_Pm";
  uint64_t dyldfunc_addr;

  dyldfunc_addr = macho_loader_find_symbol(dyld_loader, dyldfunc_name);
  if (!dyldfunc_addr) {
    lambchop_err(logger, "failed to find dyld symbol\n");
    return NULL;
  }
  dyldfunc = (void*)(dyldfunc_addr + dyld_loader->slide);

#if 1
  {
    uint64_t dyldargv[6];
    dyldargv[0] = (uint64_t)app_loader->hdrvm;
    dyldargv[1] = 0;
    dyldargv[2] = (uint64_t)args;
    dyldargv[3] = (uint64_t)dyld_loader->slide;
    dyldargv[4] = (uint64_t)dyld_loader->hdrvm;
    dyldargv[5] = (uint64_t)&glue;
    return lambchop_vm_call(dyldfunc, 6, dyldargv, logger);
  }
#else
  /*lambchop_trace();*/
  return dyldfunc(app_loader->hdrvm, 0, args, dyld_loader->slide, dyld_loader->hdrvm, &glue);
#endif
}

void *lambchop_macho_load(char *app_path, char *dyld_path, lambchop_logger *logger, char **envp, char **apple) {
  macho_loader *dyld_loader = NULL, *app_loader = NULL;
  char **args = NULL;
  void *mainfunc = NULL;

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

  args = macho_loader_setup_dyld_args(dyld_loader, envp, apple);
  if (!args) {
    lambchop_err(logger, "failed to setup dyld args\n");
    goto out;
  }

  mainfunc = macho_loader_call_dyld(dyld_loader, app_loader, args);

out:
  macho_loader_free(dyld_loader);
  macho_loader_free(app_loader);
  if (args) {
    free(args);
  }

  return mainfunc;
}
