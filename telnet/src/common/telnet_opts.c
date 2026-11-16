#include "telnet_opts.h"
#include "telnet_codec.h"
#include <string.h>

void tn_opts_init(tn_opts *o) { memset(o, 0, sizeof *o); }

void tn_opts_allow(tn_opts *o, uint8_t opt, bool allow_us, bool allow_him)
{
    o->allow_us[opt]  = allow_us;
    o->allow_him[opt] = allow_him;
}

bool tn_opts_us_on(const tn_opts *o, uint8_t opt)  { return o->us[opt]  == Q_YES; }
bool tn_opts_him_on(const tn_opts *o, uint8_t opt) { return o->him[opt] == Q_YES; }

/* The four RFC 1143 transitions are side-agnostic: "yes"/"no" are the reply
 * commands for this side (him: DO/DONT, us: WILL/WONT). */

static size_t emit(uint8_t cmd, uint8_t opt, uint8_t *out) { return tn_encode_neg(cmd, opt, out); }

/* Received WILL (him) or DO (us). */
static size_t on_enable_msg(uint8_t *q, bool allowed, uint8_t yes, uint8_t no,
                            uint8_t opt, uint8_t *out)
{
    switch (*q) {
    case Q_NO:
        if (allowed) { *q = Q_YES; return emit(yes, opt, out); }
        return emit(no, opt, out);
    case Q_YES:         return 0;
    case Q_WANTNO:      *q = Q_NO;  return 0;      /* protocol error by peer */
    case Q_WANTNO_OPP:  *q = Q_YES; return 0;      /* protocol error by peer */
    case Q_WANTYES:     *q = Q_YES; return 0;
    case Q_WANTYES_OPP: *q = Q_WANTNO; return emit(no, opt, out);
    }
    return 0;
}

/* Received WONT (him) or DONT (us). */
static size_t on_disable_msg(uint8_t *q, uint8_t yes, uint8_t no, uint8_t opt, uint8_t *out)
{
    switch (*q) {
    case Q_NO:          return 0;
    case Q_YES:         *q = Q_NO; return emit(no, opt, out);
    case Q_WANTNO:      *q = Q_NO; return 0;
    case Q_WANTNO_OPP:  *q = Q_WANTYES; return emit(yes, opt, out);
    case Q_WANTYES:     *q = Q_NO; return 0;
    case Q_WANTYES_OPP: *q = Q_NO; return 0;
    }
    return 0;
}

static size_t ask_enable(uint8_t *q, uint8_t yes, uint8_t opt, uint8_t *out)
{
    switch (*q) {
    case Q_NO:          *q = Q_WANTYES; return emit(yes, opt, out);
    case Q_YES:         return 0;
    case Q_WANTNO:      *q = Q_WANTNO_OPP; return 0;
    case Q_WANTNO_OPP:  return 0;
    case Q_WANTYES:     return 0;
    case Q_WANTYES_OPP: *q = Q_WANTYES; return 0;
    }
    return 0;
}

static size_t ask_disable(uint8_t *q, uint8_t no, uint8_t opt, uint8_t *out)
{
    switch (*q) {
    case Q_NO:          return 0;
    case Q_YES:         *q = Q_WANTNO; return emit(no, opt, out);
    case Q_WANTNO:      return 0;
    case Q_WANTNO_OPP:  *q = Q_WANTNO; return 0;
    case Q_WANTYES:     *q = Q_WANTYES_OPP; return 0;
    case Q_WANTYES_OPP: return 0;
    }
    return 0;
}

int tn_opts_recv(tn_opts *o, uint8_t cmd, uint8_t opt, uint8_t *out, size_t *outlen)
{
    uint8_t *q; bool allowed, enable; uint8_t yes, no;
    switch (cmd) {
    case TN_WILL: q = &o->him[opt]; allowed = o->allow_him[opt]; yes = TN_DO;   no = TN_DONT; enable = true;  break;
    case TN_WONT: q = &o->him[opt]; allowed = false;             yes = TN_DO;   no = TN_DONT; enable = false; break;
    case TN_DO:   q = &o->us[opt];  allowed = o->allow_us[opt];  yes = TN_WILL; no = TN_WONT; enable = true;  break;
    case TN_DONT: q = &o->us[opt];  allowed = false;             yes = TN_WILL; no = TN_WONT; enable = false; break;
    default: *outlen = 0; return 0;
    }
    bool before = (*q == Q_YES);
    *outlen = enable ? on_enable_msg(q, allowed, yes, no, opt, out)
                     : on_disable_msg(q, yes, no, opt, out);
    return before != (*q == Q_YES);
}

size_t tn_opts_ask_us(tn_opts *o, uint8_t opt, bool enable, uint8_t *out)
{
    return enable ? ask_enable(&o->us[opt], TN_WILL, opt, out)
                  : ask_disable(&o->us[opt], TN_WONT, opt, out);
}

size_t tn_opts_ask_him(tn_opts *o, uint8_t opt, bool enable, uint8_t *out)
{
    return enable ? ask_enable(&o->him[opt], TN_DO, opt, out)
                  : ask_disable(&o->him[opt], TN_DONT, opt, out);
}
