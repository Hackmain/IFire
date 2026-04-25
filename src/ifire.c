/*
 * IFIRE - IDS/IPS Firewall with AI Anomaly Detection
 * Open-source network intrusion detection and prevention system.
 *
 * Built on top of libpcap for packet capture with AI-assisted threat
 * scoring via the companion Python AI engine (ai/ifire_ai.py).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <time.h>
#include <pcap.h>
#include <stdbool.h>

#include "datagram.h"
#include "ethernetframe.h"
#include "ippacket.h"
#include "arppacket.h"
#include "ipaddress.h"
#include "simple-set.h"
#include "pingflooddetector.h"
#include "tcpsessiontracker.h"
#include "tftp.h"
#include "tftpsessiontracker.h"
#include "ifire.h"
#include "firewall.h"
#include "portscan.h"
#include "synflood.h"
#include "logger.h"

/* ── global state ─────────────────────────────────────────────────────────── */
static pcap_t           *pcap_session  = NULL;
static char             *strfilter     = NULL;
static struct bpf_program binfilter;
static pcap_dumper_t    *pcap_log      = NULL;

static bool quiet_mode  = false;
static bool show_raw    = false;
static bool ips_mode    = false;
static int  detect_flags = DETECT_ALL;
static unsigned int capture_count = 0;

static char *tftpserver = NULL;

/* detectors */
static SimpleSet            arpRequests  = NULL;
static pingflooddetector    pingFloods   = NULL;
static tcpsessiontracker    tcpSessions  = NULL;
static tftpsessiontracker   tftpSessions = NULL;
static portscan_detector_t  portscanner  = NULL;
static synflood_detector_t  synflooder   = NULL;
static firewall_t           fw           = NULL;

/* ── banner ───────────────────────────────────────────────────────────────── */
static void print_banner(void) {
    printf("\n");
    printf("  ██╗███████╗██╗██████╗ ███████╗\n");
    printf("  ██║██╔════╝██║██╔══██╗██╔════╝\n");
    printf("  ██║█████╗  ██║██████╔╝█████╗  \n");
    printf("  ██║██╔══╝  ██║██╔══██╗██╔══╝  \n");
    printf("  ██║██║     ██║██║  ██║███████╗\n");
    printf("  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝\n");
    printf("\n");
    printf("  IDS/IPS Firewall  v%s\n", IFIRE_VERSION);
    printf("  AI-Enhanced Network Intrusion Detection & Prevention\n");
    printf("  Open Source | github.com/your-org/ifire\n");
    printf("\n");
}

/* ── helpers ──────────────────────────────────────────────────────────────── */
static void maybe_block(const char *src_ip, const char *reason) {
    if (!ips_mode || !fw || !src_ip) return;
    if (firewall_block(fw, src_ip)) {
        log_event(LOG_BLOCK, "IPS_BLOCK", src_ip, "", 0, 0, reason);
    }
}

static void alert(const char *type, const char *src_ip, const char *dst_ip,
                  int sport, int dport, const char *msg) {
    printf("\n **** IFIRE ALERT [%s] ****\n", type);
    printf("      %s\n", msg);
    if (src_ip && *src_ip) printf("      Source : %s:%d\n", src_ip, sport);
    if (dst_ip && *dst_ip) printf("      Target : %s:%d\n", dst_ip, dport);
    printf("\n");
    log_event(LOG_ALERT, type, src_ip, dst_ip, sport, dport, msg);
}

/* ── packet processor ─────────────────────────────────────────────────────── */
void process_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
    if (!quiet_mode)
        printf("Grabbed %d bytes (%d%%) on %s",
               h->caplen,
               (int)(100.0 * h->caplen / h->len),
               ctime((const time_t*)&h->ts.tv_sec));

    datagram *d = new_datagram(packet, h->caplen);
    if (show_raw && !quiet_mode) d->print_datagram(d);

    ethernetframe *e = d->create_ethernetframe(d);
    if (!quiet_mode) {
        printf("---------- Ethernet frame ----------\n");
        e->print_ethernetframe(e);
    }
    free(d);

    switch (e->ether_type(e)) {

    case et_IPv4: {
        ippacket *i = e->create_ippacket(e);
        if (!quiet_mode) {
            printf("-------- IP packet --------\n");
            i->print_ippacket(i);
        }

        const char *src_ip = get_ipaddress(i->source_ip(i));
        const char *dst_ip = get_ipaddress(i->destination_ip(i));

        /* Skip packets from blocked IPs (IPS mode) */
        if (ips_mode && fw && firewall_is_blocked(fw, src_ip)) {
            log_event(LOG_INFO, "DROPPED", src_ip, dst_ip, 0, 0, "blocked IP");
            free(i);
            break;
        }

        /* ── ICMP / Ping flood ─────────────────────────────────────────── */
        if (i->protocol(i) == ipp_icmp) {
            icmppacket *icmp = i->create_icmppacket(i);
            if (!quiet_mode) {
                printf("----- ICMP -----\n");
                icmp->print_icmppacket(icmp);
            }

            if ((detect_flags & DETECT_PINGFLOOD) &&
                pingFloods->process_ping(i->destination_ip(i), icmp, pingFloods)) {
                char msg[128];
                snprintf(msg, sizeof(msg),
                         "Ping flood: large echo requests targeting %s", dst_ip);
                alert("PING_FLOOD", src_ip, dst_ip, 0, 0, msg);
                maybe_block(src_ip, "ping flood");
            }

            log_event(LOG_INFO, "ICMP", src_ip, dst_ip, 0, 0, "icmp packet");
            free(icmp);
        }

        /* ── TCP ─────────────────────────────────────────────────────────── */
        else if (i->protocol(i) == ipp_tcp) {
            tcpsegment *tcp = i->create_tcpsegment(i);
            if (!quiet_mode) {
                printf("----- TCP -----\n");
                tcp->print_tcpsegment(tcp);
            }

            int sport = (int)tcp->source_port(tcp);
            int dport = (int)tcp->destination_port(tcp);
            bool syn = tcp->flag_syn(tcp);
            bool ack = tcp->flag_ack(tcp);

            /* TCP session tracker */
            if (detect_flags & DETECT_TCPTRACK)
                tcpSessions->process_tcpsegment(i, tcpSessions);

            /* Port scan detector (SYN packets only) */
            if ((detect_flags & DETECT_PORTSCAN) && syn && !ack) {
                if (portscan_process(src_ip, (unsigned int)dport, portscanner)) {
                    char msg[128];
                    snprintf(msg, sizeof(msg),
                             "Port scan: %u+ unique ports probed from %s",
                             portscanner->port_threshold, src_ip);
                    alert("PORT_SCAN", src_ip, dst_ip, sport, dport, msg);
                    maybe_block(src_ip, "port scan");
                }
            }

            /* SYN flood detector */
            if (detect_flags & DETECT_SYNFLOOD) {
                if (synflood_process(dst_ip, syn, ack, synflooder)) {
                    char msg[128];
                    snprintf(msg, sizeof(msg),
                             "SYN flood: %u+ SYNs with low ACK ratio targeting %s",
                             synflooder->syn_threshold, dst_ip);
                    alert("SYN_FLOOD", src_ip, dst_ip, sport, dport, msg);
                    maybe_block(src_ip, "SYN flood");
                }
            }

            log_event(LOG_INFO, "TCP", src_ip, dst_ip, sport, dport, "tcp segment");
            free(tcp);
        }

        /* ── UDP ─────────────────────────────────────────────────────────── */
        else if (i->protocol(i) == ipp_udp) {
            udpsegment *udp = i->create_udpsegment(i);
            if (!quiet_mode) {
                printf("----- UDP -----\n");
                udp->print_udpsegment(udp);
            }

            int sport = (int)udp->source_port(udp);
            int dport = (int)udp->destination_port(udp);

            if ((detect_flags & DETECT_TFTPTRACK) && tftpserver)
                tftpSessions->process_tftpmessage(i, tftpserver, tftpSessions);

            log_event(LOG_INFO, "UDP", src_ip, dst_ip, sport, dport, "udp segment");
            free(udp);
        }

        free(i);
        break;
    }

    case et_ARP: {
        arppacket *a = e->create_arppacket(e);
        if (!quiet_mode) {
            printf("--------- ARP ---------\n");
            a->print_arppacket(a);
        }

        if (detect_flags & DETECT_ARPSPOOF) {
            switch (a->operation(a)) {
            case akt_ArpRequest:
                arpRequests->add(get_ipaddress(a->destination_ip(a)), arpRequests);
                break;
            case akt_ArpReply:
                if (arpRequests->find(get_ipaddress(a->source_ip(a)), arpRequests) == -1) {
                    const char *attacker_mac = get_macaddress(a->source_mac(a));
                    const char *victim_mac   = get_macaddress(a->destination_mac(a));
                    char msg[160];
                    snprintf(msg, sizeof(msg),
                             "Unsolicited ARP reply from %s to %s",
                             attacker_mac, victim_mac);
                    alert("ARP_SPOOF", "", "", 0, 0, msg);
                    log_event(LOG_ALERT, "ARP_SPOOF", "", "", 0, 0, msg);
                } else {
                    arpRequests->removeElement(
                        get_ipaddress(a->source_ip(a)), arpRequests);
                }
                break;
            default:
                break;
            }
        }
        free(a);
        break;
    }

    default:
        break;
    }

    free(e);

    if (user)
        pcap_dump(user, h, packet);

    capture_count++;
}

/* ── lifecycle ────────────────────────────────────────────────────────────── */
static void init_detectors(void) {
    newSimpleSet(&arpRequests);
    newPingFloodDetector(&pingFloods);
    newTCPSessionTracker(&tcpSessions);
    newTFTPSessionTracker(&tftpSessions);
    portscanner = portscan_new(15, 5000);   /* 15 unique ports / 5 s  */
    synflooder  = synflood_new(100, 5.0f, 10000); /* 100 SYNs, ratio 5, 10 s */
    fw          = firewall_new(ips_mode);
}

static void shutdown_ifire(int code) {
    /* destroy detectors */
    disposeSimpleSet(arpRequests);
    destroy_pingflooddetector(pingFloods);
    destroy_tcpsessiontracker(tcpSessions);
    destroy_tftpsessiontracker(tftpSessions);
    portscan_destroy(portscanner);
    synflood_destroy(synflooder);
    firewall_destroy(fw);

    if (pcap_log)  pcap_dump_close(pcap_log);
    if (strfilter) pcap_freecode(&binfilter);
    if (pcap_session) pcap_close(pcap_session);

    logger_close();
    printf("\n[IFIRE] %u packets captured. Shutting down.\n", capture_count);
    exit(code);
}

static void handle_sigint(int sig) {
    (void)sig;
    printf("\n[IFIRE] Interrupted by user.\n");
    shutdown_ifire(0);
}

/* ── device auto-detect ───────────────────────────────────────────────────── */
static char *fetch_device(char *errbuf) {
    pcap_if_t *ift = NULL;
    char *dev = NULL;
    if (pcap_findalldevs(&ift, errbuf) == 0 && ift) {
        dev = malloc(strlen(ift->name) + 1);
        strcpy(dev, ift->name);
        pcap_freealldevs(ift);
    }
    return dev;
}

/* ── usage ────────────────────────────────────────────────────────────────── */
static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("  Capture & Detection\n");
    printf("    -d <dev>    Network device to capture (default: auto)\n");
    printf("    -i <file>   Read packets from pcap file\n");
    printf("    -f <bpf>    BPF filter expression\n");
    printf("    -n <count>  Stop after N packets\n");
    printf("    -p          Enable promiscuous mode\n");
    printf("    -q          Quiet mode (alerts only)\n");
    printf("    -r          Show raw packet bytes\n\n");
    printf("  Logging\n");
    printf("    -l <file>   Write captured packets to pcap file\n");
    printf("    -j <file>   Write JSON event log to file\n\n");
    printf("  Detection (-s <mode>, repeatable)\n");
    printf("    -s arpspoof   ARP spoofing detection\n");
    printf("    -s pingflood  Ping flood detection\n");
    printf("    -s portscan   Port scan detection\n");
    printf("    -s synflood   SYN flood detection\n");
    printf("    -s tcptrack   TCP session tracking\n");
    printf("    -s tftptrack  TFTP session tracking\n");
    printf("    -s all        All detections (default)\n");
    printf("    -S <ip>       TFTP server IP to monitor\n\n");
    printf("  IPS / Firewall\n");
    printf("    -B            Enable IPS blocking mode (requires root)\n");
    printf("    -b <file>     Load IP blacklist from file\n");
    printf("    -w <ip>       Whitelist an IP address\n");
    printf("    -W <file>     Load IP whitelist from file\n\n");
    printf("  AI\n");
    printf("    Use ai/ifire_ai.py to train and run anomaly detection\n");
    printf("    on the JSON log produced by -j.\n\n");
    printf("  Other\n");
    printf("    -h            Show this help\n\n");
}

/* ── main ─────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    char *device     = NULL;
    char *rlogfname  = NULL;
    char *wlogfname  = NULL;
    char *jsonlog    = NULL;
    char *blistfile  = NULL;
    char *wlistfile  = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int  siz         = 65535;
    int  promisc     = 0;
    int  cnt         = -1;
    int  argch;

    /* Start with no detections; -s flags OR 's all' enable them */
    detect_flags = DETECT_NONE;

    /* Install Ctrl+C handler */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);

    while ((argch = getopt(argc, argv, "hpqrBd:f:i:j:l:n:s:S:b:w:W:")) != EOF) {
        switch (argch) {
        case 'd': device    = optarg; break;
        case 'f': strfilter = optarg; break;
        case 'i': rlogfname = optarg; break;
        case 'l': wlogfname = optarg; break;
        case 'j': jsonlog   = optarg; break;
        case 'n': cnt       = atoi(optarg); break;
        case 'p': promisc   = 1; break;
        case 'r': show_raw  = true; break;
        case 'q': quiet_mode = true; break;
        case 'B': ips_mode  = true; break;
        case 'b': blistfile = optarg; break;
        case 'w':
            /* inline whitelist entry handled after init_detectors */
            /* store in wlistfile only if not a file; handled specially */
            /* We'll handle this after fw is created */
            break;
        case 'W': wlistfile = optarg; break;
        case 'S': tftpserver = optarg; break;
        case 's':
            if (!strcmp(optarg, "all")) {
                detect_flags = DETECT_ALL;
            } else if (!strcmp(optarg, "arpspoof")) {
                detect_flags |= DETECT_ARPSPOOF;
            } else if (!strcmp(optarg, "pingflood")) {
                detect_flags |= DETECT_PINGFLOOD;
            } else if (!strcmp(optarg, "tcptrack")) {
                detect_flags |= DETECT_TCPTRACK;
            } else if (!strcmp(optarg, "tftptrack")) {
                detect_flags |= DETECT_TFTPTRACK;
            } else if (!strcmp(optarg, "portscan")) {
                detect_flags |= DETECT_PORTSCAN;
            } else if (!strcmp(optarg, "synflood")) {
                detect_flags |= DETECT_SYNFLOOD;
            } else {
                fprintf(stderr, "[IFIRE] Unknown detection mode: %s\n", optarg);
                return -1;
            }
            break;
        case 'h':
            print_banner();
            print_usage(argv[0]);
            return 0;
        default:
            break;
        }
    }

    /* Default: enable all detections if none specified */
    if (detect_flags == DETECT_NONE) detect_flags = DETECT_ALL;

    /* Mutual exclusions */
    if (device && rlogfname) {
        fprintf(stderr, "[IFIRE] Error: -d and -i are mutually exclusive\n");
        return -1;
    }
    if (tftpserver && !(detect_flags & DETECT_TFTPTRACK)) {
        fprintf(stderr, "[IFIRE] Error: -S requires -s tftptrack\n");
        return -1;
    }
    if ((detect_flags & DETECT_TFTPTRACK) && !tftpserver) {
        fprintf(stderr, "[IFIRE] Error: tftptrack requires -S <server-ip>\n");
        return -1;
    }

    print_banner();

    /* JSON log */
    if (jsonlog) logger_init(jsonlog);

    /* Init detectors & firewall */
    init_detectors();

    /* Load blacklist / whitelist after firewall is created */
    if (blistfile) firewall_load_blacklist(fw, blistfile);
    if (wlistfile) firewall_load_whitelist(fw, wlistfile);

    /* Re-parse argv for -w <ip> entries (getopt already consumed them above,
     * but we need fw to exist; simplest fix: parse argc/argv manually here) */
    for (int k = 1; k < argc - 1; k++) {
        if (!strcmp(argv[k], "-w") && argv[k+1]) {
            firewall_whitelist(fw, argv[k+1]);
            printf("[IFIRE-FW] Whitelisted: %s\n", argv[k+1]);
        }
    }

    /* Auto-detect device */
    if (!device && !rlogfname) {
        device = fetch_device(errbuf);
        if (!device) {
            fprintf(stderr, "[IFIRE] Cannot find device: %s\n", errbuf);
            shutdown_ifire(-1);
        }
    }

    if (rlogfname)
        printf("[IFIRE] Reading from file: %s\n", rlogfname);
    else
        printf("[IFIRE] Device : %s%s\n", device, promisc ? " (promiscuous)" : "");

    /* Network info */
    bpf_u_int32 netp, maskp;
    if (!rlogfname) {
        if (pcap_lookupnet(device, &netp, &maskp, errbuf) == -1) {
            fprintf(stderr, "[IFIRE] Warning: %s\n", errbuf);
            netp = maskp = 0;
        } else {
            struct in_addr addr;
            addr.s_addr = netp;  printf("[IFIRE] Network: %s", inet_ntoa(addr));
            addr.s_addr = maskp; printf(" / %s\n", inet_ntoa(addr));
        }
    } else {
        maskp = 0;
    }

    /* Open pcap session */
    if (!rlogfname) {
        pcap_session = pcap_open_live(device, siz, promisc, 1000, errbuf);
        if (!pcap_session) {
            fprintf(stderr, "[IFIRE] pcap_open_live: %s\n", errbuf);
            shutdown_ifire(-1);
        }
    } else {
        pcap_session = pcap_open_offline(rlogfname, errbuf);
        if (!pcap_session) {
            fprintf(stderr, "[IFIRE] pcap_open_offline: %s\n", errbuf);
            shutdown_ifire(-1);
        }
    }

    /* BPF filter */
    if (strfilter) {
        if (pcap_compile(pcap_session, &binfilter, strfilter, 1, maskp) < 0 ||
            pcap_setfilter(pcap_session, &binfilter) < 0) {
            fprintf(stderr, "[IFIRE] Filter error: %s\n",
                    pcap_geterr(pcap_session));
            shutdown_ifire(-1);
        }
        printf("[IFIRE] BPF filter: %s\n", strfilter);
    }

    /* Pcap log */
    if (wlogfname) {
        pcap_log = pcap_dump_open(pcap_session, wlogfname);
        if (!pcap_log) {
            fprintf(stderr, "[IFIRE] pcap_dump_open: %s\n",
                    pcap_geterr(pcap_session));
            shutdown_ifire(-1);
        }
    }

    /* Print active detection modes */
    printf("[IFIRE] Detection:");
    if (detect_flags & DETECT_ARPSPOOF)  printf(" ARP-spoof");
    if (detect_flags & DETECT_PINGFLOOD) printf(" Ping-flood");
    if (detect_flags & DETECT_PORTSCAN)  printf(" Port-scan");
    if (detect_flags & DETECT_SYNFLOOD)  printf(" SYN-flood");
    if (detect_flags & DETECT_TCPTRACK)  printf(" TCP-track");
    if (detect_flags & DETECT_TFTPTRACK) printf(" TFTP-track");
    printf("\n");

    if (ips_mode) printf("[IFIRE] IPS mode ENABLED - attackers will be auto-blocked\n");
    if (jsonlog)  printf("[IFIRE] JSON log: %s\n", jsonlog);

    printf("[IFIRE] Capturing... (Ctrl+C to stop)\n\n");

    log_event(LOG_INFO, "STARTUP", "", "", 0, 0,
              ips_mode ? "IPS+IDS mode active" : "IDS mode active");

    pcap_loop(pcap_session, cnt, process_packet, (u_char *)pcap_log);
    shutdown_ifire(0);
    return 0;
}
