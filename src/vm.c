#include "lambchop.h"

int lambchop_vm_run(void *mainfunc, lambchop_logger *logger) {
  // TODO 引数を扱えるようにする。
  /*return ((int(*)(void))mainfunc)();*/
  return lambchop_vm_main(mainfunc, 1024 * 1024, logger);
}
