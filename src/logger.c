#include "lambchop.h"

#include <stdarg.h>
#include <stdio.h>

void lambchop_logger_log(lambchop_logger *logger, int level, const char *format, ...) {
    if (level <= logger->level) {
        va_list ap;
        pthread_mutex_lock(&(logger->mutex));
        va_start(ap, format);
        dprintf(logger->fd, format, ap);
        va_end(ap);
        pthread_mutex_unlock(&(logger->mutex));
    }
}

void lambchop_logger_set_log_level(lambchop_logger *logger, int level) {
    pthread_mutex_lock(&(logger->mutex));
    logger->level = level;
    pthread_mutex_unlock(&(logger->mutex));
}

void lambchop_logger_set_log_fd(lambchop_logger *logger, int fd) {
    pthread_mutex_lock(&(logger->mutex));
    logger->fd = fd;
    pthread_mutex_unlock(&(logger->mutex));
}

bool lambchop_logger_init(lambchop_logger *logger) {
    logger->level = LAMBCHOP_DEFAULT_LOG_LEVEL;
    logger->fd = LAMBCHOP_DEFAULT_LOG_FD;
    if (pthread_mutex_init(&(logger->mutex), NULL) != 0) {
        goto err;
    }
    return true;
err:
    return false;
}
