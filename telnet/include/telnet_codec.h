/* Stream-safe Telnet parser and encoder. */
#ifndef TELNET_CODEC_H
#define TELNET_CODEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "telnet_proto.h"

#define TN_SB_MAX 256                  /* max subnegotiation payload kept */
#define TN_ENCODE_MAX(n) ((n) * 3)     /* worst-case encoded size of n data bytes */

typedef enum {
    TN_EV_DATA,        /* plain data bytes: data/len */
    TN_EV_NEGOTIATE,   /* cmd = WILL/WONT/DO/DONT, opt */
    TN_EV_SUBNEG,      /* opt, data/len = payload */
    TN_EV_CMD          /* cmd = NOP/IP/AYT/... */
} tn_event_type;

typedef struct {
    tn_event_type  type;
    uint8_t        cmd;
    uint8_t        opt;
    const uint8_t *data;
    size_t         len;
} tn_event;

typedef void (*tn_event_cb)(const tn_event *ev, void *user);

typedef struct tn_parser tn_parser;

/* collapse_crlf: when true, "CR LF" is delivered as a single CR (used by the
 * server, whose PTY maps CR to NL). When false, CR LF is kept intact (client,
 * for display). "CR NUL" always yields CR. */
tn_parser *tn_parser_new(bool collapse_crlf);
void       tn_parser_free(tn_parser *p);

/* Feed raw bytes; the callback fires, in order, for each decoded event. */
int tn_parser_feed(tn_parser *p, const uint8_t *buf, size_t n,
                   tn_event_cb cb, void *user);

/* ---- Encoder ---- */
typedef struct { bool last_cr; } tn_encoder;

void   tn_encoder_init(tn_encoder *e);
/* Escapes IAC and turns a bare CR into CR NUL. Needs outcap >= TN_ENCODE_MAX(n),
 * otherwise returns 0. Returns bytes written. */
size_t tn_encode_data(tn_encoder *e, const uint8_t *in, size_t n,
                      uint8_t *out, size_t outcap);
size_t tn_encode_neg(uint8_t cmd, uint8_t opt, uint8_t *out);          /* 3 bytes */
size_t tn_encode_cmd(uint8_t cmd, uint8_t *out);                       /* 2 bytes */
size_t tn_encode_sb(uint8_t opt, const uint8_t *payload, size_t n,
                    uint8_t *out, size_t cap);
size_t tn_encode_naws(uint16_t cols, uint16_t rows, uint8_t *out, size_t cap);
size_t tn_encode_ttype_is(const char *term, uint8_t *out, size_t cap);
size_t tn_encode_ttype_send(uint8_t *out, size_t cap);

#endif
