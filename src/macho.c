#include "lambchop.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <mach-o/loader.h>

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

static bool lc_dump_segment_64(struct segment_command_64 *command, lambchop_logger *logger) {
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
  lambchop_info(logger, "--------------------------------------------------------------\n");
  return true;
}

static bool lc_dump_dyld_info_only(struct dyld_info_command *command, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- DYLD INFO ONLY COMMAND ---------------------\n");
  lambchop_info(logger, "rebase_off = %u\n", command->rebase_off);
  lambchop_info(logger, "rebase_size = %u\n", command->rebase_size);
  lambchop_info(logger, "bind_off = %u\n", command->bind_off);
  lambchop_info(logger, "bind_size = %u\n", command->bind_size);
  lambchop_info(logger, "weak_bind_off = %u\n", command->weak_bind_off);
  lambchop_info(logger, "weak_bind_size = %u\n", command->weak_bind_size);
  lambchop_info(logger, "lazy_bind_off = %u\n", command->lazy_bind_off);
  lambchop_info(logger, "lazy_bind_size = %u\n", command->lazy_bind_size);
  lambchop_info(logger, "export_off = %u\n", command->export_off);
  lambchop_info(logger, "export_size = %u\n", command->export_size);
  lambchop_info(logger, "------------------------------------------------------------------\n");
  return true;
}

static bool lc_dump_symtab(struct symtab_command *command, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- SYMTAB COMMAND ---------------------\n");
  lambchop_info(logger, "symoff = %u\n", command->symoff);
  lambchop_info(logger, "nsyms = %u\n", command->nsyms);
  lambchop_info(logger, "stroff = %u\n", command->stroff);
  lambchop_info(logger, "strsize = %u\n", command->strsize);
  lambchop_info(logger, "----------------------------------------------------------\n");
  return true;
}

static bool lc_dump_dysymtab(struct dysymtab_command *command, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- DYSYMTAB COMMAND ---------------------\n");
  lambchop_info(logger, "ilocalsym = %u\n", command->ilocalsym);
  lambchop_info(logger, "nlocalsym = %u\n", command->nlocalsym);
  lambchop_info(logger, "iextdefsym = %u\n", command->iextdefsym);
  lambchop_info(logger, "nextdefsym = %u\n", command->nextdefsym);
  lambchop_info(logger, "iundefsym = %u\n", command->iundefsym);
  lambchop_info(logger, "nundefsym = %u\n", command->nundefsym);
  lambchop_info(logger, "tocoff = %u\n", command->tocoff);
  lambchop_info(logger, "ntoc = %u\n", command->ntoc);
  lambchop_info(logger, "modtaboff = %u\n", command->modtaboff);
  lambchop_info(logger, "nmodtab = %u\n", command->nmodtab);
  lambchop_info(logger, "extrefsymoff = %u\n", command->extrefsymoff);
  lambchop_info(logger, "nextrefsyms = %u\n", command->nextrefsyms);
  lambchop_info(logger, "indirectsymoff = %u\n", command->indirectsymoff);
  lambchop_info(logger, "nindirectsyms = %u\n", command->nindirectsyms);
  lambchop_info(logger, "extreloff = %u\n", command->extreloff);
  lambchop_info(logger, "nextrel = %u\n", command->nextrel);
  lambchop_info(logger, "locreloff = %u\n", command->locreloff);
  lambchop_info(logger, "nlocrel = %u\n", command->nlocrel);
  lambchop_info(logger, "------------------------------------------------------------\n");
  return true;
}

bool lc_dump_load_dylinker(struct dylinker_command *command, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- LOAD DYLINKER COMMAND ---------------------\n");
  lambchop_info(logger, "name = %s\n", ((char*)command) + command->name.offset);
  lambchop_info(logger, "-----------------------------------------------------------------\n");
  return true;
}

bool lc_dump_uuid(struct uuid_command *command, lambchop_logger *logger) {
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

bool lc_dump_version_min_macosx(struct version_min_command *command, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- VERSION MIN MACOSX COMMAND ---------------------\n");
  lambchop_info(logger, "version = 0x%x\n", command->version);
  lambchop_info(logger, "sdk = 0x%x\n", command->sdk);
  lambchop_info(logger, "----------------------------------------------------------------------\n");
  return true;
}

bool lc_dump_source_version(struct source_version_command *command, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- SOURCE VERSION COMMAND ---------------------\n");
  lambchop_info(logger, "version = 0x%x\n", command->version);
  lambchop_info(logger, "------------------------------------------------------------------\n");
  return true;
}

bool lc_dump_main(struct entry_point_command *command, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- MAIN COMMAND ---------------------\n");
  lambchop_info(logger, "entryoff = 0x%llx\n", command->entryoff);
  lambchop_info(logger, "stacksize = 0x%llx\n", command->stacksize);
  lambchop_info(logger, "--------------------------------------------------------\n");
  return true;
}

bool lc_dump_load_dylib(struct dylib_command *command, lambchop_logger *logger) {
  struct dylib *dylib = &command->dylib;
  lambchop_info(logger, "--------------------- LOAD DYLIB COMMAND ---------------------\n");
  lambchop_info(logger, "name = %s\n", ((char*)command) + dylib->name.offset);
  lambchop_info(logger, "timestamp = %u\n", dylib->timestamp);
  lambchop_info(logger, "current_version = 0x%x\n", dylib->current_version);
  lambchop_info(logger, "compatibility_version = 0x%x\n", dylib->compatibility_version);
  lambchop_info(logger, "--------------------------------------------------------------\n");
  return true;
}

bool lc_dump_function_starts(struct linkedit_data_command *command, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- FUNCTION STARTS COMMAND ---------------------\n");
  lambchop_info(logger, "dataoff = %u\n", command->dataoff);
  lambchop_info(logger, "datasize = %u\n", command->datasize);
  lambchop_info(logger, "-------------------------------------------------------------------\n");
  return true;
}

bool lc_dump_data_in_code(struct linkedit_data_command *command, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- DATA IN CODE COMMAND ---------------------\n");
  lambchop_info(logger, "dataoff = %u\n", command->dataoff);
  lambchop_info(logger, "datasize = %u\n", command->datasize);
  lambchop_info(logger, "----------------------------------------------------------------\n");
  return true;
}

bool lc_dump_dylib_code_sign_drs(struct linkedit_data_command *command, lambchop_logger *logger) {
  lambchop_info(logger, "--------------------- DYLIB CODE SIGN DRS COMMAND ---------------------\n");
  lambchop_info(logger, "dataoff = %u\n", command->dataoff);
  lambchop_info(logger, "datasize = %u\n", command->datasize);
  lambchop_info(logger, "-----------------------------------------------------------------------\n");
  return true;
}

static bool lc_dump(struct load_command *command, lambchop_logger *logger) {
  switch(command->cmd) {
    case LC_SEGMENT_64:
      return lc_dump_segment_64((struct segment_command_64*)command, logger);
    case LC_DYLD_INFO_ONLY:
      return lc_dump_dyld_info_only((struct dyld_info_command*)command, logger);
    case LC_SYMTAB:
      return lc_dump_symtab((struct symtab_command*)command, logger);
    case LC_DYSYMTAB:
      return lc_dump_dysymtab((struct dysymtab_command*)command, logger);
    case LC_LOAD_DYLINKER:
      return lc_dump_load_dylinker((struct dylinker_command*)command, logger);
    case LC_UUID:
      return lc_dump_uuid((struct uuid_command*)command, logger);
    case LC_VERSION_MIN_MACOSX:
      return lc_dump_version_min_macosx((struct version_min_command*)command, logger);
    case LC_SOURCE_VERSION:
      return lc_dump_source_version((struct source_version_command*)command, logger);
    case LC_MAIN:
      return lc_dump_main((struct entry_point_command*)command, logger);
    case LC_LOAD_DYLIB:
      return lc_dump_load_dylib((struct dylib_command*)command, logger);
    case LC_FUNCTION_STARTS:
      return lc_dump_function_starts((struct linkedit_data_command*)command, logger);
    case LC_DATA_IN_CODE:
      return lc_dump_data_in_code((struct linkedit_data_command*)command, logger);
    case LC_DYLIB_CODE_SIGN_DRS:
      return lc_dump_dylib_code_sign_drs((struct linkedit_data_command*)command, logger);
    default:
      lambchop_err(logger, "unexpected load command: 0x%x\n", command->cmd);
      return false;
  }
}

static bool macho_load_64(char *buf, size_t size, lambchop_logger *logger) {
  char *ptr = buf;
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
    if (!lc_dump(commands[i], logger)) {
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

bool lambchop_macho_load(char *buf, size_t size, lambchop_logger *logger) {
  char *ptr = buf;
  uint32_t magic = *(uint32_t*)(buf);

  lambchop_info(logger, "mach-o load start\n");
  if (magic == MH_MAGIC) {
    lambchop_err(logger, "cannot handle 32bit binary\n");
    goto err;
  } else if (magic == MH_MAGIC_64) {
    if (!macho_load_64(buf, size, logger)) {
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
