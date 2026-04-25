#ifndef _IFIRE_LOGGER_H
#define _IFIRE_LOGGER_H

typedef enum {
    LOG_INFO = 0,
    LOG_WARNING,
    LOG_ALERT,
    LOG_BLOCK
} log_level_t;

void logger_init(const char *path);
void logger_close(void);
int  logger_has_file(void);
void log_event(log_level_t level, const char *type,
               const char *src_ip, const char *dst_ip,
               int src_port, int dst_port, const char *details);

#endif
