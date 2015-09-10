#include "lambchop.h"

#define ERR(...) lambchop_err(logger, __VA_ARGS__)
#define INFO(...) lambchop_info(logger, __VA_ARGS__)
#define DEBUG(...) lambchop_debug(logger, __VA_ARGS__)

static int vm_main(uint8_t *p, lambchop_logger *logger) {
  while (true) {
    switch(*p) {
      default:
        ERR("unsupported instruction 0x%x\n", *p);
        return -1;
    }
  }
}

int lambchop_vm_run(void *mainfunc, lambchop_logger *logger) {
  // TODO 引数を扱えるようにする。
  /*return ((int(*)(void))mainfunc)();*/
  return vm_main(mainfunc, logger);
}
