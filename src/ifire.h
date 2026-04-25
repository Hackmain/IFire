#ifndef _IFIRE_H
#define _IFIRE_H

/* Detection flags bitmask */
#define DETECT_NONE      0
#define DETECT_ARPSPOOF  (1 << 0)
#define DETECT_PINGFLOOD (1 << 1)
#define DETECT_TCPTRACK  (1 << 2)
#define DETECT_TFTPTRACK (1 << 3)
#define DETECT_PORTSCAN  (1 << 4)
#define DETECT_SYNFLOOD  (1 << 5)
#define DETECT_ALL       0x3F

#define IFIRE_VERSION "1.0.0"

#endif
