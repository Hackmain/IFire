#ifndef _IFIRE_PORTSCAN_H
#define _IFIRE_PORTSCAN_H

#include <stdbool.h>
#include "generic-dict.h"

/* Entry stored per source IP */
typedef struct portscan_entry_ {
    HashTable ports_seen;       /* set: port-string -> 1 */
    unsigned long window_start; /* window start in ms  */
    unsigned int  count;        /* unique ports so far */
} *portscan_entry_t;

typedef struct portscan_detector_ {
    HashTable        entries;         /* src_ip -> portscan_entry */
    unsigned int     port_threshold;  /* unique ports to trigger  */
    unsigned long    window_ms;       /* time window in ms        */
} *portscan_detector_t;

portscan_detector_t portscan_new(unsigned int threshold, unsigned long window_ms);
void                portscan_destroy(portscan_detector_t d);
bool                portscan_process(const char *src_ip, unsigned int dst_port,
                                     portscan_detector_t d);

#endif
