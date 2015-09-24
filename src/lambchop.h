#ifndef __LAMBCHOP_SRC_LAMBCHOP_H__
#define __LAMBCHOP_SRC_LAMBCHOP_H__

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>

#define LAMBCHOP_LOG_FATAL 0
#define LAMBCHOP_LOG_ERROR 1
#define LAMBCHOP_LOG_WARN  2
#define LAMBCHOP_LOG_INFO  3
#define LAMBCHOP_LOG_DEBUG 4
#define LAMBCHOP_LOG_TRACE 5
#define LAMBCHOP_DEFAULT_LOG_LEVEL LAMBCHOP_LOG_DEBUG
#define LAMBCHOP_DEFAULT_LOG_FD STDERR_FILENO

#define lambchop_err(logger, ...) lambchop_logger_log((logger), LAMBCHOP_LOG_ERROR, __VA_ARGS__)
#define lambchop_info(logger, ...) lambchop_logger_log((logger), LAMBCHOP_LOG_INFO, __VA_ARGS__)
#define lambchop_debug(logger, ...) lambchop_logger_log((logger), LAMBCHOP_LOG_DEBUG, __VA_ARGS__)

typedef struct {
    int level;
    int fd;
    pthread_mutex_t mutex;
} lambchop_logger;

void lambchop_logger_log(lambchop_logger *logger, int level, const char *format, ...);
void lambchop_logger_set_log_level(lambchop_logger *logger, int level);
void lambchop_logger_set_log_fd(lambchop_logger *logger, int fd);
bool lambchop_logger_init(lambchop_logger *logger);

bool lambchop_macho_dump(char *path, lambchop_logger *logger);
void *lambchop_macho_load(char *app_path, char *dyld_path, lambchop_logger *logger, char **envp, char **apple);

bool lambchop_file_read_all(const char *path, lambchop_logger *logger, char **buf, size_t *size);

int lambchop_vm_main(void *func, uint64_t stacksize, lambchop_logger *logger);
int lambchop_vm_run(void *mainfunc, lambchop_logger *logger);
int lambchop_vm_call(void *func, int argc, uint64_t *argv, lambchop_logger *logger);

uint64_t lambchop_syscall(uint64_t *rax, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);

void lambchop_trace(void);

#endif
