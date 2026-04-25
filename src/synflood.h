#ifndef _IFIRE_SYNFLOOD_H
#define _IFIRE_SYNFLOOD_H

#include <stdbool.h>
#include "generic-dict.h"

/* Entry stored per destination IP */
typedef struct synflood_entry_ {
    unsigned int  syn_count;    /* SYN-only packets in window      */
    unsigned int  synack_count; /* SYN+ACK packets in window       */
    unsigned long window_start; /* window start time in ms         */
} *synflood_entry_t;

typedef struct synflood_detector_ {
    HashTable      entries;          /* dst_ip -> synflood_entry  */
    unsigned int   syn_threshold;    /* SYN count to trigger      */
    float          ratio_threshold;  /* SYN / SYN-ACK threshold   */
    unsigned long  window_ms;        /* time window in ms         */
} *synflood_detector_t;

synflood_detector_t synflood_new(unsigned int syn_threshold,
                                  float ratio_threshold,
                                  unsigned long window_ms);
void  synflood_destroy(synflood_detector_t d);
bool  synflood_process(const char *dst_ip,
                        bool is_syn, bool is_ack,
                        synflood_detector_t d);

#endif
