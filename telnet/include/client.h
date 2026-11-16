#ifndef CLIENT_H
#define CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include "client_config.h"
#include "telnet_codec.h"
#include "telnet_opts.h"

typedef struct client {
    const client_config *cfg;
    int        sock;
    tn_parser *parser;
    tn_encoder enc;
    tn_opts    opts;
    bool       local_echo;     /* on until the server takes over echoing */
    bool       stdin_tty;
    bool       stdin_open;
    bool       quit;
    bool       peer_closed;
    char       term[64];
} client;

int  client_run(const client_config *cfg);                 /* process exit code */
void client_send_cmd(client *c, uint8_t cmd);              /* IAC <cmd> */
void client_debug(const client *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void ui_command_mode(client *c);                           /* the "telnet>" prompt */

#endif
