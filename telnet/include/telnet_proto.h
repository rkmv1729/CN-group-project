/* Telnet protocol constants (RFC 854, 855, 857, 858, 1073, 1091). */
#ifndef TELNET_PROTO_H
#define TELNET_PROTO_H

#include <stdint.h>

#define TN_VERSION "1.0.0"
#define TN_DEFAULT_PORT 2323

/* Commands */
enum {
    TN_SE   = 240, TN_NOP  = 241, TN_DM   = 242, TN_BRK  = 243,
    TN_IP   = 244, TN_AO   = 245, TN_AYT  = 246, TN_EC   = 247,
    TN_EL   = 248, TN_GA   = 249, TN_SB   = 250, TN_WILL = 251,
    TN_WONT = 252, TN_DO   = 253, TN_DONT = 254, TN_IAC  = 255
};

/* Options */
enum {
    TNO_BINARY = 0,
    TNO_ECHO   = 1,
    TNO_SGA    = 3,
    TNO_TTYPE  = 24,
    TNO_NAWS   = 31
};

/* Subnegotiation qualifiers (TERMINAL-TYPE) */
#define TNSB_IS   0
#define TNSB_SEND 1

const char *tn_cmd_name(uint8_t cmd);
const char *tn_opt_name(uint8_t opt);

#endif
