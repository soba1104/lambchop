#include "lambchop.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <math.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

static const char *cputype(cpu_type_t cputype) {
  if (cputype == CPU_TYPE_X86_64) {
    return "X86_64";
  } else {
    return "UNKNOWN";
  }
}

static const char *filetype(uint32_t filetype) {
  switch(filetype) {
    case MH_OBJECT:
      return "OBJECT";
    case MH_EXECUTE:
      return "EXECUTE";
    case MH_FVMLIB:
      return "FVMLIB";
    case MH_CORE:
      return "CORE";
    case MH_PRELOAD:
      return "PRELOAD";
    case MH_DYLIB:
      return "DYLIB";
    case MH_DYLINKER:
      return "DYLINKER";
    case MH_BUNDLE:
      return "BUNDLE";
    case MH_DYLIB_STUB:
      return "DYLIB_STUB";
    case MH_DSYM:
      return "DSYM";
    case MH_KEXT_BUNDLE:
      return "KEXT_BUNDLE";
    default:
      return "UNKNOWN";
  }
}

static bool lc_dump_segment_64(struct segment_command_64 *command, char *img, lambchop_logger *logger) {
  int i;
  lambchop_info(logger, "--------------------- SEGMENT COMMAND 64 ---------------------\n");
  lambchop_info(logger, "segname = %s\n", command->segname);
  lambchop_info(logger, "vmaddr = 0x%llx\n", command->vmaddr);
  lambchop_info(logger, "vmsize = %llu\n", command->vmsize);
  lambchop_info(logger, "fileoff = %llu\n", command->fileoff);
  lambchop_info(logger, "filesize = %llu\n", command->filesize);
  lambchop_info(logger, "maxprot = %u\n", command->maxprot);
  lambchop_info(logger, "initprot = %u\n", command->initprot);
  lambchop_info(logger, "nsects = %u\n", command->nsects);
  lambchop_info(logger, "flags = 0x%x\n", command->flags);
  for (i = 0; i < command->nsects; i++) {
    struct section_64 *sections = (struct section_64*)(command+1);
    struct section_64 *section = &sections[i];
    lambchop_info(logger,
                  "############### section[%d]: %s(%s) ###############\n",
                  i, section->sectname, section->segname);
    lambchop_info(logger, "addr = 0x%llx\n", section->addr);
    lambchop_info(logger, "size = %llu\n", section->size);
    lambchop_info(logger, "offset = 0x%x\n", section->offset);
    lambchop_info(logger, "align = 0x%x\n", section->align);
    lambchop_info(logger, "reloff = 0x%x\n", section->reloff);
    lambchop_info(logger, "nreloc = %u\n", section->nreloc);
    lambchop_info(logger, "flags = 0x%x\n", section->flags);
    lambchop_info(logger, "reserved1 = 0x%x\n", section->reserved1);
    lambchop_info(logger, "reserved2 = 0x%x\n", section->reserved2);
    lambchop_info(logger, "reserved3 = 0x%x\n", section->reserved3);
  }
  lambchop_info(logger, "--------------------------------------------------------------\n");
  return true;
}

static const char *rebase_type(uint8_t immediate) {
  switch(immediate) {
    case REBASE_TYPE_POINTER:
      return "REBASE_TYPE_POINTER";
    case REBASE_TYPE_TEXT_ABSOLUTE32:
      return "REBASE_TYPE_TEXT_ABSOLUTE32";
    case REBASE_TYPE_TEXT_PCREL32:
      return "REBASE_TYPE_TEXT_PCREL32";
    default:
      return NULL;
  }
}

static const char *bind_type(uint8_t immediate) {
  switch(immediate) {
    case BIND_TYPE_POINTER:
      return "BIND_TYPE_POINTER";
    case BIND_TYPE_TEXT_ABSOLUTE32:
      return "BIND_TYPE_TEXT_ABSOLUTE32";
    case BIND_TYPE_TEXT_PCREL32:
      return "BIND_TYPE_TEXT_PCREL32";
    default:
      return NULL;
  }
}

static uint64_t parse_uleb128(char **pp) {
  char *p = *pp;
  int base;
  uint64_t res = 0;
  for (base = 1;; base *= 127) {
    res += (*p & ~0x80) * base;
    p++;
    if ((*p & 0x80) == 0) {
      *pp = p;
      return res;
    }
  }
}

static int64_t parse_sleb128(char **pp) {
  char *s, *e;
  uint64_t uleb;
  int n;

  s = *pp;
  uleb = parse_uleb128(pp);
  e = *pp;
  n = e - s;
  return (int64_t)(uleb - pow(128, n));
}

static bool lc_dump_dyld_rebase_info(struct dyld_info_command *command, char *img, lambchop_logger *logger) {
  char *rebase_info = img + command->rebase_off;
  char *p = rebase_info;
  int i;
  if (!command->rebase_size) {
    return true;
  }
  while (p < (rebase_info + command->rebase_size)) {
    uint8_t opcode = *p & REBASE_OPCODE_MASK;
    uint8_t immediate = *p & REBASE_IMMEDIATE_MASK;
    uint64_t offset;
    const char *type;
    p++;
    switch(opcode) {
      case REBASE_OPCODE_DONE:
        return true;
      case REBASE_OPCODE_SET_TYPE_IMM:
        /*REBASE_TYPE_POINTER: ポインタの中身を書き換える*/
        type = rebase_type(immediate);
        if (!type) {
          lambchop_err(logger, "unsupported rebase type 0x%x\n", immediate);
          return false;
        }
        lambchop_info(logger, "rebase_info: op=REBASE_OPCODE_SET_TYPE_IMM type=%s\n", type);
        break;
      case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        /*
         * どのセグメントのどのオフセットを書き換えるかを指定する。
         * この命令ではセグメントのインデックスを immediate によって与える。
         * セグメントのインデックスは0から数える。
         * セグメントのインデックスが2だった場合は3つ目のセグメント。
         */
        offset = parse_uleb128(&p);
        lambchop_info(logger,
                      "rebase_info: op=REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, segment=%u, offset=0x%x\n",
                      immediate, offset);
        break;
      case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
        /*
         * 指定した回数 segment の offset の rebase を繰り返す。
         * 書き換えるべき値は毎回ポインタのサイズ分だけずれる(REBASE_TYPE_POINTER の場合)。
         * segment や offset には REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB などで指定された値を用いる。
         * この命令では繰り返しの回数は immediate によって与えられる。
         */
        lambchop_info(logger, "rebase_info: op=REBASE_OPCODE_DO_REBASE_IMM_TIMES, times=%d\n", immediate);
        break;
      default:
        lambchop_err(logger, "unsupported rebase info opcode 0x%x\n", opcode);
        return false;
    }
  }
  lambchop_err(logger, "REBASE_OPCODE_DONE not found\n");
  return false;
}

static bool lc_dump_dyld_bind_info(uint32_t offset, uint32_t size, char *img, lambchop_logger *logger) {
  char *bind_info = img + offset;
  char *p = bind_info;
  if (!size) {
    return true;
  }
  while (p < (bind_info + size)) {
    uint8_t opcode = *p & BIND_OPCODE_MASK;
    uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
    const char *type;
    int64_t sleb;
    uint64_t uleb;
    p++;
    switch(opcode) {
      case BIND_OPCODE_DONE:
        return true;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        lambchop_info(logger, "bind_info: op=BIND_OPCODE_SET_DYLIB_ORDINAL_IMM ordinal=%d\n", immediate);
        break;
      case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        if (immediate) {
          lambchop_err(logger, "unsupported bind flags 0x%x\n", immediate);
          return false;
        }
        lambchop_info(logger,
                      "bind_info: op=BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM flags=0x%x, symbol = %s\n",
                      immediate, p);
        p += strlen(p) + 1;
        break;
      case BIND_OPCODE_SET_TYPE_IMM:
        type = bind_type(immediate);
        if (!type) {
          lambchop_err(logger, "unsupported bind type 0x%x\n", immediate);
          return false;
        }
        lambchop_info(logger, "bind_info: op=BIND_OPCODE_SET_TYPE_IMM type=%s\n", type);
        break;
      case BIND_OPCODE_SET_ADDEND_SLEB:
        sleb = parse_sleb128(&p);
        lambchop_info(logger, "bind_info: op=BIND_OPCODE_SET_ADDEND_SLEB addend=%lld\n", sleb);
        break;
      case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        uleb = parse_uleb128(&p);
        lambchop_info(logger,
                      "bind_info: op=BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB segment=%d offset=0x%x\n",
                      immediate, uleb);
        break;
      case BIND_OPCODE_DO_BIND:
        lambchop_info(logger, "bind_info: op=BIND_OPCODE_DO_BIND\n");
        break;
      default:
        lambchop_err(logger, "unsupported bind info opcode 0x%x\n", opcode);
        return false;
    }
  }
  lambchop_err(logger, "BIND_OPCODE_DONE not found\n");
  return false;
}

static bool lc_dump_dyld_export_info(struct dyld_info_command *command, char *img, lambchop_logger *logger) {
  // TODO
  return true;
}

static bool lc_dump_dyld_info_only(struct dyld_info_command *command, char *img, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- DYLD INFO ONLY COMMAND ---------------------\n");
  lambchop_info(logger, "rebase_off = 0x%x\n", command->rebase_off);
  lambchop_info(logger, "rebase_size = %u\n", command->rebase_size);
  lambchop_info(logger, "bind_off = 0x%x\n", command->bind_off);
  lambchop_info(logger, "bind_size = %u\n", command->bind_size);
  lambchop_info(logger, "weak_bind_off = 0x%x\n", command->weak_bind_off);
  lambchop_info(logger, "weak_bind_size = %u\n", command->weak_bind_size);
  lambchop_info(logger, "lazy_bind_off = 0x%x\n", command->lazy_bind_off);
  lambchop_info(logger, "lazy_bind_size = %u\n", command->lazy_bind_size);
  lambchop_info(logger, "export_off = 0x%x\n", command->export_off);
  lambchop_info(logger, "export_size = %u\n", command->export_size);
  lambchop_info(logger, "########## REBASE INFO ##########\n");
  if (!lc_dump_dyld_rebase_info(command, img, logger)) {
    lambchop_err(logger, "failed to parse rebase info\n");
    goto err;
  }
  lambchop_info(logger, "########## BIND INFO ##########\n");
  if (!lc_dump_dyld_bind_info(command->bind_off, command->bind_size, img, logger)) {
    lambchop_err(logger, "failed to parse bind info\n");
    goto err;
  }
  lambchop_info(logger, "########## WEAK BIND INFO ##########\n");
  if (!lc_dump_dyld_bind_info(command->weak_bind_off, command->weak_bind_size, img, logger)) {
    lambchop_err(logger, "failed to parse weak bind info\n");
    goto err;
  }
  lambchop_info(logger, "########## LAZY BIND INFO ##########\n");
  if (!lc_dump_dyld_bind_info(command->lazy_bind_off, command->lazy_bind_size, img, logger)) {
    lambchop_err(logger, "failed to parse lazy bind info\n");
    goto err;
  }
  lambchop_info(logger, "########## EXPORT INFO ##########\n");
  if (!lc_dump_dyld_export_info(command, img, logger)) {
    lambchop_err(logger, "failed to parse export info\n");
    goto err;
  }
  lambchop_info(logger, "------------------------------------------------------------------\n");
  return true;
err:
  return false;
}

static bool lc_dump_symtab_64(struct symtab_command *command, char *img, lambchop_logger *logger) {
  struct nlist_64 *symbol_table = (struct nlist_64*)(img + command->symoff);
  char *string_table = img + command->stroff;
  int i;
  lambchop_info(logger, "--------------------- SYMTAB COMMAND ---------------------\n");
  lambchop_info(logger, "symoff = 0x%x\n", command->symoff);
  lambchop_info(logger, "nsyms = %u\n", command->nsyms);
  lambchop_info(logger, "stroff = 0x%x\n", command->stroff);
  lambchop_info(logger, "strsize = %u\n", command->strsize);
  for (i = 0; i < command->nsyms; i++) {
    struct nlist_64 *list = &symbol_table[i];
    char *sym = list->n_un.n_strx ? string_table + list->n_un.n_strx : "\"\"";
    uint8_t type = list->n_type;
    uint8_t sect = list->n_sect;
    uint16_t desc = list->n_desc;
    uint32_t value = list->n_value;
    lambchop_info(logger,
                  "%d: name = %s, type = 0x%x, sect = %d, desc = 0x%x, value = 0x%x\n",
                  i, sym, type, sect, desc, value);
  }
  lambchop_info(logger, "----------------------------------------------------------\n");
  return true;
}

static bool lc_dump_dysymtab(struct dysymtab_command *command, char *img, lambchop_logger *logger) {
  int i;
  lambchop_info(logger, "--------------------- DYSYMTAB COMMAND ---------------------\n");
  lambchop_info(logger, "ilocalsym = %u\n", command->ilocalsym);
  lambchop_info(logger, "nlocalsym = %u\n", command->nlocalsym);
  lambchop_info(logger, "iextdefsym = %u\n", command->iextdefsym);
  lambchop_info(logger, "nextdefsym = %u\n", command->nextdefsym);
  lambchop_info(logger, "iundefsym = %u\n", command->iundefsym);
  lambchop_info(logger, "nundefsym = %u\n", command->nundefsym);
  lambchop_info(logger, "tocoff = 0x%x\n", command->tocoff);
  lambchop_info(logger, "ntoc = %u\n", command->ntoc);
  lambchop_info(logger, "modtaboff = 0x%x\n", command->modtaboff);
  lambchop_info(logger, "nmodtab = %u\n", command->nmodtab);
  lambchop_info(logger, "extrefsymoff = 0x%x\n", command->extrefsymoff);
  lambchop_info(logger, "nextrefsyms = %u\n", command->nextrefsyms);
  lambchop_info(logger, "indirectsymoff = 0x%x\n", command->indirectsymoff);
  lambchop_info(logger, "nindirectsyms = %u\n", command->nindirectsyms);
  lambchop_info(logger, "extreloff = 0x%x\n", command->extreloff);
  lambchop_info(logger, "nextrel = %u\n", command->nextrel);
  lambchop_info(logger, "locreloff = 0x%x\n", command->locreloff);
  lambchop_info(logger, "nlocrel = %u\n", command->nlocrel);
  for (i = 0; i < command->nindirectsyms; i++) {
    uint32_t *indirect_symbol_table = (uint32_t*)(img + command->indirectsymoff);
    uint32_t entry = indirect_symbol_table[i];
    lambchop_info(logger, "indirect_symbol_table[%d] = 0x%x\n", i, entry);
  }
  lambchop_info(logger, "------------------------------------------------------------\n");
  return true;
}

bool lc_dump_load_dylinker(struct dylinker_command *command, char *img, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- LOAD DYLINKER COMMAND ---------------------\n");
  lambchop_info(logger, "name = %s\n", ((char*)command) + command->name.offset);
  lambchop_info(logger, "-----------------------------------------------------------------\n");
  return true;
}

bool lc_dump_uuid(struct uuid_command *command, char *img, lambchop_logger *logger) {
  int i;
  lambchop_info(logger, "--------------------- UUID COMMAND ---------------------\n");
  lambchop_info(logger, "uuid = ");
  for (i = 0; i < 16; i++) {
    lambchop_info(logger, "%02x", command->uuid[i]);
  }
  lambchop_info(logger, "\n");
  lambchop_info(logger, "--------------------------------------------------------\n");
  return true;
}

bool lc_dump_version_min_macosx(struct version_min_command *command, char *img, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- VERSION MIN MACOSX COMMAND ---------------------\n");
  lambchop_info(logger, "version = 0x%x\n", command->version);
  lambchop_info(logger, "sdk = 0x%x\n", command->sdk);
  lambchop_info(logger, "----------------------------------------------------------------------\n");
  return true;
}

bool lc_dump_source_version(struct source_version_command *command, char *img, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- SOURCE VERSION COMMAND ---------------------\n");
  lambchop_info(logger, "version = 0x%x\n", command->version);
  lambchop_info(logger, "------------------------------------------------------------------\n");
  return true;
}

bool lc_dump_main(struct entry_point_command *command, char *img, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- MAIN COMMAND ---------------------\n");
  lambchop_info(logger, "entryoff = 0x%llx\n", command->entryoff);
  lambchop_info(logger, "stacksize = 0x%llx\n", command->stacksize);
  lambchop_info(logger, "--------------------------------------------------------\n");
  return true;
}

bool lc_dump_load_dylib(struct dylib_command *command, char *img, lambchop_logger *logger) {
  struct dylib *dylib = &command->dylib;
  lambchop_info(logger, "--------------------- LOAD DYLIB COMMAND ---------------------\n");
  lambchop_info(logger, "name = %s\n", ((char*)command) + dylib->name.offset);
  lambchop_info(logger, "timestamp = %u\n", dylib->timestamp);
  lambchop_info(logger, "current_version = 0x%x\n", dylib->current_version);
  lambchop_info(logger, "compatibility_version = 0x%x\n", dylib->compatibility_version);
  lambchop_info(logger, "--------------------------------------------------------------\n");
  return true;
}

bool lc_dump_function_starts(struct linkedit_data_command *command, char *img, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- FUNCTION STARTS COMMAND ---------------------\n");
  lambchop_info(logger, "dataoff = 0x%x\n", command->dataoff);
  lambchop_info(logger, "datasize = %u\n", command->datasize);
  lambchop_info(logger, "-------------------------------------------------------------------\n");
  return true;
}

bool lc_dump_data_in_code(struct linkedit_data_command *command, char *img, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- DATA IN CODE COMMAND ---------------------\n");
  lambchop_info(logger, "dataoff = 0x%x\n", command->dataoff);
  lambchop_info(logger, "datasize = %u\n", command->datasize);
  lambchop_info(logger, "----------------------------------------------------------------\n");
  return true;
}

bool lc_dump_dylib_code_sign_drs(struct linkedit_data_command *command, char *img, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- DYLIB CODE SIGN DRS COMMAND ---------------------\n");
  lambchop_info(logger, "dataoff = 0x%x\n", command->dataoff);
  lambchop_info(logger, "datasize = %u\n", command->datasize);
  lambchop_info(logger, "-----------------------------------------------------------------------\n");
  return true;
}

static bool lc_dump_64(struct load_command *command, char *img, lambchop_logger *logger) {
  switch(command->cmd) {
    case LC_SEGMENT_64:
      return lc_dump_segment_64((struct segment_command_64*)command, img, logger);
    case LC_DYLD_INFO_ONLY:
      return lc_dump_dyld_info_only((struct dyld_info_command*)command, img, logger);
    case LC_SYMTAB:
      return lc_dump_symtab_64((struct symtab_command*)command, img, logger);
    case LC_DYSYMTAB:
      return lc_dump_dysymtab((struct dysymtab_command*)command, img, logger);
    case LC_LOAD_DYLINKER:
      return lc_dump_load_dylinker((struct dylinker_command*)command, img, logger);
    case LC_UUID:
      return lc_dump_uuid((struct uuid_command*)command, img, logger);
    case LC_VERSION_MIN_MACOSX:
      return lc_dump_version_min_macosx((struct version_min_command*)command, img, logger);
    case LC_SOURCE_VERSION:
      return lc_dump_source_version((struct source_version_command*)command, img, logger);
    case LC_MAIN:
      return lc_dump_main((struct entry_point_command*)command, img, logger);
    case LC_LOAD_DYLIB:
      return lc_dump_load_dylib((struct dylib_command*)command, img, logger);
    case LC_FUNCTION_STARTS:
      return lc_dump_function_starts((struct linkedit_data_command*)command, img, logger);
    case LC_DATA_IN_CODE:
      return lc_dump_data_in_code((struct linkedit_data_command*)command, img, logger);
    case LC_DYLIB_CODE_SIGN_DRS:
      return lc_dump_dylib_code_sign_drs((struct linkedit_data_command*)command, img, logger);
    default:
      lambchop_err(logger, "unexpected load command: 0x%x\n", command->cmd);
      return false;
  }
}

static bool macho_load_64(char *img, size_t size, lambchop_logger *logger) {
  char *ptr = img;
  struct mach_header_64 *hdr;
  struct load_command **commands = NULL;
  uint32_t ncmds, i;
  bool ret = true;

  hdr = (struct mach_header_64*)ptr;
  ptr += sizeof(struct mach_header_64);

  lambchop_debug(logger, "cputype = %s\n", cputype(hdr->cputype));
  lambchop_debug(logger, "cpusubtype = 0x%x\n", hdr->cpusubtype);
  lambchop_debug(logger, "filetype = %s\n", filetype(hdr->filetype));
  lambchop_debug(logger, "ncmds = %d\n", hdr->ncmds);
  lambchop_debug(logger, "sizeofcmds = %d\n", hdr->sizeofcmds);
  lambchop_debug(logger, "flags = 0x%x\n", hdr->flags);

  ncmds = hdr->ncmds;
  commands = malloc(sizeof(struct load_command) * ncmds);
  if (!commands) {
    lambchop_err(logger, "failed to allocate load commands buffer: %s\n", strerror(errno));
    goto err;
  }
  for (i = 0; i < ncmds; i++) {
    commands[i] = (struct load_command*)ptr;
    ptr += commands[i]->cmdsize;
  }
  for (i = 0; i < ncmds; i++) {
    if (!lc_dump_64(commands[i], img, logger)) {
      goto err;
    }
  }

  goto out;

err:
  ret = false;

out:
  if (commands) {
    free(commands);
  }
  return ret;
}

bool lambchop_macho_load(char *img, size_t size, lambchop_logger *logger) {
  char *ptr = img;
  uint32_t magic = *(uint32_t*)(img);

  lambchop_info(logger, "mach-o load start\n");
  if (magic == MH_MAGIC) {
    lambchop_err(logger, "cannot handle 32bit binary\n");
    goto err;
  } else if (magic == MH_MAGIC_64) {
    if (!macho_load_64(img, size, logger)) {
      goto err;
    }
  } else {
    lambchop_err(logger, "invalid magic %x\n", magic);
    goto err;
  }
  lambchop_info(logger, "mach-o load finish\n");
  return true;

err:
  lambchop_info(logger, "mach-o load failure\n");
  return false;
}
