#include "telnet_codec.h"
#include <stdlib.h>
#include <string.h>

enum { ST_DATA, ST_IAC, ST_NEG, ST_SB_OPT, ST_SB, ST_SB_IAC };

struct tn_parser {
    int      state;
    bool     collapse_crlf;
    bool     after_cr;
    uint8_t  neg_cmd;
    uint8_t  sb_opt;
    uint8_t  sb[TN_SB_MAX];
    size_t   sb_len;
    bool     sb_overflow;
    uint8_t  dbuf[1024];
    size_t   dlen;
};

const char *tn_cmd_name(uint8_t c)
{
    switch (c) {
    case TN_SE: return "SE";     case TN_NOP: return "NOP";   case TN_DM: return "DM";
    case TN_BRK: return "BRK";   case TN_IP: return "IP";     case TN_AO: return "AO";
    case TN_AYT: return "AYT";   case TN_EC: return "EC";     case TN_EL: return "EL";
    case TN_GA: return "GA";     case TN_SB: return "SB";     case TN_WILL: return "WILL";
    case TN_WONT: return "WONT"; case TN_DO: return "DO";     case TN_DONT: return "DONT";
    case TN_IAC: return "IAC";
    default: return "?";
    }
}

const char *tn_opt_name(uint8_t o)
{
    switch (o) {
    case TNO_BINARY: return "BINARY";
    case TNO_ECHO:   return "ECHO";
    case TNO_SGA:    return "SGA";
    case TNO_TTYPE:  return "TTYPE";
    case TNO_NAWS:   return "NAWS";
    default: return "?";
    }
}

tn_parser *tn_parser_new(bool collapse_crlf)
{
    tn_parser *p = calloc(1, sizeof *p);
    if (p) p->collapse_crlf = collapse_crlf;
    return p;
}

void tn_parser_free(tn_parser *p) { free(p); }

static void flush_data(tn_parser *p, tn_event_cb cb, void *user)
{
    if (p->dlen == 0) return;
    tn_event ev = { .type = TN_EV_DATA, .data = p->dbuf, .len = p->dlen };
    p->dlen = 0;                 /* reset first: callback must not see stale state */
    cb(&ev, user);
}

static void put_data(tn_parser *p, uint8_t b, tn_event_cb cb, void *user)
{
    if (p->dlen == sizeof p->dbuf) flush_data(p, cb, user);
    p->dbuf[p->dlen++] = b;
}

int tn_parser_feed(tn_parser *p, const uint8_t *buf, size_t n,
                   tn_event_cb cb, void *user)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t c = buf[i];
        switch (p->state) {
        case ST_DATA:
            if (c == TN_IAC) { p->state = ST_IAC; break; }
            if (p->after_cr) {
                p->after_cr = false;
                if (c == 0 || (p->collapse_crlf && c == '\n')) break;  /* swallow */
            }
            if (c == '\r') p->after_cr = true;
            put_data(p, c, cb, user);
            break;

        case ST_IAC:
            switch (c) {
            case TN_IAC:
                p->after_cr = false;
                put_data(p, 0xFF, cb, user);
                p->state = ST_DATA;
                break;
            case TN_WILL: case TN_WONT: case TN_DO: case TN_DONT:
                p->neg_cmd = c;
                p->state = ST_NEG;
                break;
            case TN_SB:
                p->state = ST_SB_OPT;
                break;
            case TN_SE:                       /* stray SE: ignore */
                p->state = ST_DATA;
                break;
            default: {
                flush_data(p, cb, user);
                tn_event ev = { .type = TN_EV_CMD, .cmd = c };
                cb(&ev, user);
                p->state = ST_DATA;
            }
            }
            break;

        case ST_NEG: {
            flush_data(p, cb, user);
            tn_event ev = { .type = TN_EV_NEGOTIATE, .cmd = p->neg_cmd, .opt = c };
            cb(&ev, user);
            p->state = ST_DATA;
            break;
        }

        case ST_SB_OPT:
            p->sb_opt = c;
            p->sb_len = 0;
            p->sb_overflow = false;
            p->state = ST_SB;
            break;

        case ST_SB:
            if (c == TN_IAC) { p->state = ST_SB_IAC; break; }
            if (p->sb_len < TN_SB_MAX) p->sb[p->sb_len++] = c;
            else p->sb_overflow = true;
            break;

        case ST_SB_IAC:
            if (c == TN_SE) {
                flush_data(p, cb, user);
                if (!p->sb_overflow) {
                    tn_event ev = { .type = TN_EV_SUBNEG, .opt = p->sb_opt,
                                    .data = p->sb, .len = p->sb_len };
                    cb(&ev, user);
                }
                p->state = ST_DATA;
            } else if (c == TN_IAC) {
                if (p->sb_len < TN_SB_MAX) p->sb[p->sb_len++] = 0xFF;
                else p->sb_overflow = true;
                p->state = ST_SB;
            } else {
                p->state = ST_DATA;           /* malformed: abandon subnegotiation */
            }
            break;
        }
    }
    flush_data(p, cb, user);
    return 0;
}

/* ---------------- Encoder ---------------- */

void tn_encoder_init(tn_encoder *e) { e->last_cr = false; }

size_t tn_encode_data(tn_encoder *e, const uint8_t *in, size_t n,
                      uint8_t *out, size_t outcap)
{
    if (outcap < TN_ENCODE_MAX(n)) return 0;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = in[i];
        if (e->last_cr) {
            if (b != '\n' && b != 0) out[o++] = 0;   /* bare CR -> CR NUL */
            e->last_cr = false;
        }
        if (b == TN_IAC) {
            out[o++] = TN_IAC;
            out[o++] = TN_IAC;
        } else {
            out[o++] = b;
            if (b == '\r') e->last_cr = true;
        }
    }
    return o;
}

size_t tn_encode_neg(uint8_t cmd, uint8_t opt, uint8_t *out)
{
    out[0] = TN_IAC; out[1] = cmd; out[2] = opt;
    return 3;
}

size_t tn_encode_cmd(uint8_t cmd, uint8_t *out)
{
    out[0] = TN_IAC; out[1] = cmd;
    return 2;
}

size_t tn_encode_sb(uint8_t opt, const uint8_t *pl, size_t n, uint8_t *out, size_t cap)
{
    if (cap < 2 * n + 5) return 0;
    size_t o = 0;
    out[o++] = TN_IAC; out[o++] = TN_SB; out[o++] = opt;
    for (size_t i = 0; i < n; i++) {
        if (pl[i] == TN_IAC) out[o++] = TN_IAC;
        out[o++] = pl[i];
    }
    out[o++] = TN_IAC; out[o++] = TN_SE;
    return o;
}

size_t tn_encode_naws(uint16_t cols, uint16_t rows, uint8_t *out, size_t cap)
{
    uint8_t pl[4] = { (uint8_t)(cols >> 8), (uint8_t)cols,
                      (uint8_t)(rows >> 8), (uint8_t)rows };
    return tn_encode_sb(TNO_NAWS, pl, sizeof pl, out, cap);
}

size_t tn_encode_ttype_is(const char *term, uint8_t *out, size_t cap)
{
    uint8_t pl[65];
    size_t n = strnlen(term, 64);
    pl[0] = TNSB_IS;
    memcpy(pl + 1, term, n);
    return tn_encode_sb(TNO_TTYPE, pl, n + 1, out, cap);
}

size_t tn_encode_ttype_send(uint8_t *out, size_t cap)
{
    uint8_t pl[1] = { TNSB_SEND };
    return tn_encode_sb(TNO_TTYPE, pl, 1, out, cap);
}
