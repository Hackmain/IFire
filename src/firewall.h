#ifndef _IFIRE_FIREWALL_H
#define _IFIRE_FIREWALL_H

#include <stdbool.h>
#include "generic-dict.h"

typedef struct ifire_firewall_ {
    HashTable blocked;
    HashTable whitelisted;
    bool ips_enabled;
} *firewall_t;

firewall_t  firewall_new(bool ips_enabled);
void        firewall_destroy(firewall_t fw);
bool        firewall_block(firewall_t fw, const char *ip);
void        firewall_unblock(firewall_t fw, const char *ip);
bool        firewall_is_blocked(firewall_t fw, const char *ip);
void        firewall_whitelist(firewall_t fw, const char *ip);
bool        firewall_is_whitelisted(firewall_t fw, const char *ip);
void        firewall_load_blacklist(firewall_t fw, const char *filename);
void        firewall_load_whitelist(firewall_t fw, const char *filename);
void        firewall_flush(firewall_t fw);

#endif
