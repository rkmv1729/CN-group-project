/* One connected Telnet client and its PTY-backed shell. */
#ifndef SESSION_H
#define SESSION_H

#include <poll.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>
#include "buffer.h"
#include "server_config.h"
#include "telnet_codec.h"
#include "telnet_opts.h"

typedef struct session {
    int        sock;
    int        pty;                 /* PTY master, -1 until the shell is spawned */
    pid_t      pid;
    tn_parser *parser;
    tn_encoder enc;
    tn_opts    opts;
    ring_buf   to_client;           /* pending bytes for the socket */
    ring_buf   to_pty;              /* pending bytes for the shell  */
    uint16_t   cols, rows;
    char       term[64];
    char       peer[64];
    time_t     created, last_activity;
    bool       got_ttype, got_naws;
    bool       spawned;
    bool       closing;             /* flush output, then close */
    bool       dead;                /* remove from the server   */
    const server_config *cfg;
    struct session *next;
} session;

session *session_new(int sock, const char *peer, const server_config *cfg);
void     session_free(session *s);

short session_sock_events(const session *s);
short session_pty_events(const session *s);          /* 0 = do not poll */
void  session_handle_sock(session *s, short revents);
void  session_handle_pty(session *s, short revents);
void  session_tick(session *s, time_t now);          /* timers, spawn, closing */

#endif
