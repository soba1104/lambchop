#include "lambchop.h"

int lambchop_vm_run(void *mainfunc) {
  // TODO 引数を扱えるようにする。
  return ((int(*)(void))mainfunc)();
}
