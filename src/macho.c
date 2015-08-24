#include "lambchop.h"

bool lambchop_macho_load(char *buf, size_t size, lambchop_logger *logger) {
  lambchop_info(logger, "mach-o load start\n");


  lambchop_info(logger, "mach-o load finish\n");
  return true;
}
