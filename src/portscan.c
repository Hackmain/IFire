#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include "portscan.h"

static unsigned long ps_now_ms(void) {
    struct timeval t;
    gettimeofday(&t, NULL);
    return (unsigned long)t.tv_sec * 1000 + t.tv_usec / 1000;
}

portscan_detector_t portscan_new(unsigned int threshold, unsigned long window_ms) {
    portscan_detector_t d = malloc(sizeof(*d));
    if (!d) return NULL;
    d->entries        = initializeTable(32);
    d->port_threshold = threshold;
    d->window_ms      = window_ms;
    return d;
}

void portscan_destroy(portscan_detector_t d) {
    if (!d) return;
    DestroyTable(d->entries);
    free(d);
}

bool portscan_process(const char *src_ip, unsigned int dst_port,
                      portscan_detector_t d) {
    if (!d || !src_ip) return false;

    unsigned long ts = ps_now_ms();
    char port_key[8];
    snprintf(port_key, sizeof(port_key), "%u", dst_port);

    portscan_entry_t entry = NULL;
    if (keyExist((char*)src_ip, d->entries)) {
        entry = (portscan_entry_t)retrieve((char*)src_ip, d->entries);
    }

    /* Start a new window if no entry or window expired */
    if (!entry || (ts - entry->window_start) > d->window_ms) {
        portscan_entry_t e = malloc(sizeof(*e));
        if (!e) return false;
        e->ports_seen   = initializeTable(32);
        e->window_start = ts;
        e->count        = 0;
        d->entries = put((char*)src_ip, (void*)e, d->entries);
        entry = e;
    }

    /* Count this port if not seen yet in the current window */
    if (!keyExist(port_key, entry->ports_seen)) {
        entry->ports_seen = put(port_key, (void*)1, entry->ports_seen);
        entry->count++;
    }

    return entry->count >= d->port_threshold;
}
