#include <stdio.h>

#include "lambchop.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: lambchop executable_path\n");
    return -1;
  }
  fprintf(stdout, "Hello Lambchop!!!\n");
  return 0;
}
