#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "firewall.h"

/* Only allow digits and dots in an IPv4 address to prevent command injection */
static bool valid_ipv4(const char *ip) {
    if (!ip || strlen(ip) < 7 || strlen(ip) > 15) return false;
    for (const char *p = ip; *p; p++) {
        if (!isdigit((unsigned char)*p) && *p != '.') return false;
    }
    return true;
}

static void run_iptables(const char *action, const char *ip) {
    char cmd[160];
    snprintf(cmd, sizeof(cmd),
        "iptables -%s INPUT -s %s -j DROP 2>/dev/null", action, ip);
    system(cmd);
    snprintf(cmd, sizeof(cmd),
        "iptables -%s FORWARD -s %s -j DROP 2>/dev/null", action, ip);
    system(cmd);
}

firewall_t firewall_new(bool ips_enabled) {
    firewall_t fw = malloc(sizeof(*fw));
    if (!fw) return NULL;
    fw->blocked    = initializeTable(64);
    fw->whitelisted = initializeTable(16);
    fw->ips_enabled = ips_enabled;
    return fw;
}

void firewall_destroy(firewall_t fw) {
    if (!fw) return;
    firewall_flush(fw);
    DestroyTable(fw->whitelisted);
    free(fw);
}

bool firewall_block(firewall_t fw, const char *ip) {
    if (!fw || !valid_ipv4(ip)) return false;
    if (firewall_is_whitelisted(fw, ip)) {
        fprintf(stderr, "[IFIRE-FW] Skipping whitelisted IP: %s\n", ip);
        return false;
    }
    if (firewall_is_blocked(fw, ip)) return false;

    fw->blocked = put((char*)ip, (void*)1, fw->blocked);

    if (fw->ips_enabled) {
        run_iptables("I", ip);
        printf("[IFIRE-IPS] BLOCKED %s\n", ip);
    }
    return true;
}

void firewall_unblock(firewall_t fw, const char *ip) {
    if (!fw || !valid_ipv4(ip)) return;
    if (!firewall_is_blocked(fw, ip)) return;
    removeKey((char*)ip, fw->blocked);
    if (fw->ips_enabled) {
        run_iptables("D", ip);
        printf("[IFIRE-IPS] UNBLOCKED %s\n", ip);
    }
}

bool firewall_is_blocked(firewall_t fw, const char *ip) {
    if (!fw || !ip) return false;
    return keyExist((char*)ip, fw->blocked) != 0;
}

void firewall_whitelist(firewall_t fw, const char *ip) {
    if (!fw || !valid_ipv4(ip)) return;
    fw->whitelisted = put((char*)ip, (void*)1, fw->whitelisted);
}

bool firewall_is_whitelisted(firewall_t fw, const char *ip) {
    if (!fw || !ip) return false;
    return keyExist((char*)ip, fw->whitelisted) != 0;
}

static void load_list(firewall_t fw, const char *filename, bool is_whitelist) {
    if (!fw || !filename) return;
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "[IFIRE-FW] Cannot open %s: %s\n",
                is_whitelist ? "whitelist" : "blacklist", filename);
        return;
    }
    char line[64];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0] || line[0] == '#') continue;
        if (is_whitelist)
            firewall_whitelist(fw, line);
        else if (firewall_block(fw, line))
            count++;
    }
    fclose(f);
    if (!is_whitelist)
        printf("[IFIRE-FW] Loaded %d IPs from blacklist: %s\n", count, filename);
}

void firewall_load_blacklist(firewall_t fw, const char *filename) {
    load_list(fw, filename, false);
}

void firewall_load_whitelist(firewall_t fw, const char *filename) {
    load_list(fw, filename, true);
}

void firewall_flush(firewall_t fw) {
    if (!fw) return;
    if (fw->ips_enabled) {
        system("iptables -F INPUT 2>/dev/null");
        system("iptables -F FORWARD 2>/dev/null");
        printf("[IFIRE-IPS] Firewall rules flushed\n");
    }
    DestroyTable(fw->blocked);
    fw->blocked = initializeTable(64);
}
