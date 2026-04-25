#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include "portflood.h"

static unsigned long pf_now_ms(void) {
    struct timeval t;
    gettimeofday(&t, NULL);
    return (unsigned long)t.tv_sec * 1000 + t.tv_usec / 1000;
}

portflood_detector_t portflood_new(unsigned int port, unsigned int threshold, unsigned long window_ms) {
    portflood_detector_t d = malloc(sizeof(*d));
    if (!d) return NULL;
    d->entries    = initializeTable(32);
    d->watch_port = port;
    d->threshold  = threshold;
    d->window_ms  = window_ms;
    return d;
}

void portflood_destroy(portflood_detector_t d) {
    if (!d) return;
    DestroyTable(d->entries);
    free(d);
}

bool portflood_process(const char *src_ip, unsigned int dst_port,
                       bool is_syn, portflood_detector_t d) {
    if (!d || !src_ip) return false;
    if (!is_syn || dst_port != d->watch_port) return false;

    unsigned long ts = pf_now_ms();
    portflood_entry_t entry = NULL;

    if (keyExist((char*)src_ip, d->entries)) {
        entry = (portflood_entry_t)retrieve((char*)src_ip, d->entries);
    }

    if (!entry || (ts - entry->window_start) > d->window_ms) {
        portflood_entry_t e = malloc(sizeof(*e));
        if (!e) return false;
        e->window_start = ts;
        e->count        = 0;
        d->entries = put((char*)src_ip, (void*)e, d->entries);
        entry = e;
    }

    entry->count++;

    return entry->count >= d->threshold;
}
