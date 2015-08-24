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

static bool lc_dump(struct load_command *command, lambchop_logger *logger) {
  switch(command->cmd) {
    case LC_SEGMENT_64:
      return lc_dump_segment_64((struct segment_command_64*)command, logger);
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
