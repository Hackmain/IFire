#include <stdio.h>
#include <time.h>
#include <string.h>
#include "logger.h"

static FILE *log_fp = NULL;

static const char *level_label[] = {"INFO", "WARNING", "ALERT", "BLOCK"};

void logger_init(const char *path) {
    if (path) {
        log_fp = fopen(path, "a");
        if (!log_fp)
            fprintf(stderr, "[IFIRE] Warning: cannot open log file %s\n", path);
    }
}

int logger_has_file(void) { return log_fp != NULL; }

void logger_close(void) {
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
}

void log_event(log_level_t level, const char *type,
               const char *src_ip, const char *dst_ip,
               int src_port, int dst_port, const char *details) {
    time_t now = time(NULL);
    struct tm *t = gmtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", t);

    /* Escape double quotes in details to keep JSON valid */
    char safe_details[512] = "";
    if (details) {
        int j = 0;
        for (int i = 0; details[i] && j < (int)sizeof(safe_details) - 2; i++) {
            if (details[i] == '"') safe_details[j++] = '\\';
            safe_details[j++] = details[i];
        }
    }

    FILE *out = log_fp ? log_fp : stdout;
    fprintf(out,
        "{\"ts\":\"%s\",\"level\":\"%s\",\"type\":\"%s\","
        "\"src\":\"%s:%d\",\"dst\":\"%s:%d\",\"info\":\"%s\"}\n",
        ts,
        level_label[level],
        type     ? type     : "-",
        src_ip   ? src_ip   : "",  src_port,
        dst_ip   ? dst_ip   : "",  dst_port,
        safe_details);

    if (log_fp) fflush(log_fp);
}
