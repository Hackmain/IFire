#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include "synflood.h"

static unsigned long sf_now_ms(void) {
    struct timeval t;
    gettimeofday(&t, NULL);
    return (unsigned long)t.tv_sec * 1000 + t.tv_usec / 1000;
}

synflood_detector_t synflood_new(unsigned int syn_threshold,
                                  float ratio_threshold,
                                  unsigned long window_ms) {
    synflood_detector_t d = malloc(sizeof(*d));
    if (!d) return NULL;
    d->entries         = initializeTable(32);
    d->syn_threshold   = syn_threshold;
    d->ratio_threshold = ratio_threshold;
    d->window_ms       = window_ms;
    return d;
}

void synflood_destroy(synflood_detector_t d) {
    if (!d) return;
    DestroyTable(d->entries);
    free(d);
}

bool synflood_process(const char *dst_ip,
                       bool is_syn, bool is_ack,
                       synflood_detector_t d) {
    if (!d || !dst_ip) return false;

    unsigned long ts = sf_now_ms();
    synflood_entry_t entry = NULL;

    if (keyExist((char*)dst_ip, d->entries)) {
        entry = (synflood_entry_t)retrieve((char*)dst_ip, d->entries);
    }

    if (!entry || (ts - entry->window_start) > d->window_ms) {
        synflood_entry_t e = malloc(sizeof(*e));
        if (!e) return false;
        e->syn_count    = 0;
        e->synack_count = 0;
        e->window_start = ts;
        d->entries = put((char*)dst_ip, (void*)e, d->entries);
        entry = e;
    }

    if (is_syn && !is_ack) entry->syn_count++;
    if (is_syn &&  is_ack) entry->synack_count++;

    if (entry->syn_count < d->syn_threshold) return false;

    float ratio = (entry->synack_count == 0)
                  ? (float)entry->syn_count
                  : (float)entry->syn_count / (float)entry->synack_count;

    return ratio >= d->ratio_threshold;
}
