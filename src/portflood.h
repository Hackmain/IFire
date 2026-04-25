#ifndef _IFIRE_PORTFLOOD_H
#define _IFIRE_PORTFLOOD_H

#include <stdbool.h>
#include "generic-dict.h"

typedef struct {
    unsigned long window_start;
    unsigned int  count;
} *portflood_entry_t;

typedef struct portflood_detector_ {
    HashTable     entries;
    unsigned int  watch_port;    /* dst port to monitor */
    unsigned int  threshold;     /* connections per window */
    unsigned long window_ms;
} *portflood_detector_t;

portflood_detector_t portflood_new(unsigned int port, unsigned int threshold, unsigned long window_ms);
void                 portflood_destroy(portflood_detector_t d);
/* Returns true when src_ip exceeds threshold SYNs to watch_port within window. */
bool                 portflood_process(const char *src_ip, unsigned int dst_port,
                                       bool is_syn, portflood_detector_t d);

#endif
