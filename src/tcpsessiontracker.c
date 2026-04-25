#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tcpsessiontracker.h"
#include "tcpsegment.h"
#include "tcpsession.h"
#include "ipaddress.h"

char* source_ip_port(ippacket *i) {
    char *source_id = malloc(sizeof(char) * 25);
    tcpsegment *tcp = i->create_tcpsegment(i);
    ipaddress *addr = i->source_ip(i);
    char *ip_s = get_ipaddress(addr);
    snprintf(source_id, 25, "%s:%d", ip_s, (int)tcp->source_port(tcp));
    free(addr);
    free(ip_s);
    free(tcp);
    return source_id;
}

char* destination_ip_port(ippacket *i) {
    char *destination_id = malloc(sizeof(char) * 25);
    tcpsegment *tcp = i->create_tcpsegment(i);
    ipaddress *addr = i->destination_ip(i);
    char *ip_s = get_ipaddress(addr);
    snprintf(destination_id, 25, "%s:%d", ip_s, (int)tcp->destination_port(tcp));
    free(addr);
    free(ip_s);
    free(tcp);
    return destination_id;
}

void process_tcpsegment(ippacket *i, tcpsessiontracker tracker) {
    tcpsession t = NULL;
    tcpsegment *tcp = i->create_tcpsegment(i);
    char *src = source_ip_port(i);
    char *dst = destination_ip_port(i);

    char id_forward[50];
    id_forward[0] = 0;
    strcat(id_forward, src);
    strcat(id_forward, dst);
    char id_backward[50];
    id_backward[0] = 0;
    strcat(id_backward, dst);
    strcat(id_backward, src);
    char *session_id = NULL;

    if (keyExist(id_forward, tracker->tcpSessions)) {
        t = retrieve(id_forward, tracker->tcpSessions);
        session_id = id_forward;
    } else if (keyExist(id_backward, tracker->tcpSessions)) {
        t = retrieve(id_backward, tracker->tcpSessions);
        session_id = id_backward;
    } else if (tcp->flag_syn(tcp) && !tcp->flag_ack(tcp)) {
        t = new_tcpsession(src, dst);
        tracker->tcpSessions = put(id_forward, (void*)t, tracker->tcpSessions);
        session_id = id_forward;
    }

    if (t != NULL && session_id != NULL) {
        if (t->getState(t) != t->trackState(tcp, src, dst, false, t)) {
            if (t->terminated(t)) {
                printf("Total data exchanged between %s and %s = %d bytes.\n",
                       src, dst, t->getBytes(t));
                tracker->tcpSessions = removeKey(session_id, tracker->tcpSessions);
            }
        }
    }

    free(tcp);
    free(src);
    free(dst);
}

tcpsessiontracker new_tcpsessiontracker(void) {
    tcpsessiontracker tracker = malloc(sizeof(struct tcpsessiontracker_));
    tracker->tcpSessions = initializeTable(10);
    tracker->process_tcpsegment = process_tcpsegment;
    return tracker;
}

void newTCPSessionTracker(tcpsessiontracker *tracker) {
    if (*tracker == NULL) {
        *tracker = new_tcpsessiontracker();
    }
}

void destroy_tcpsessiontracker(tcpsessiontracker tracker) {
    if (tracker != NULL) {
        DestroyTable(tracker->tcpSessions);
        free(tracker);
    }
}
