#include <stdio.h>

#include "lambchop.h"

int main(int argc, char **argv) {
  lambchop_logger logger;

  if (argc < 2) {
    fprintf(stderr, "usage: lambchop executable_path\n");
    return -1;
  }
  if (!lambchop_logger_init(&logger)) {
    fprintf(stderr, "failed to init logger\n");
    return -1;
  }
  lambchop_logger_log(&logger, LAMBCHOP_LOG_INFO, "Hello Lambchop!!!\n");

  return 0;
}
