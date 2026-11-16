/* Option negotiation state machine, RFC 1143 ("Q method"). */
#ifndef TELNET_OPTS_H
#define TELNET_OPTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    Q_NO = 0, Q_YES, Q_WANTNO, Q_WANTYES, Q_WANTNO_OPP, Q_WANTYES_OPP
} tn_q;

typedef struct {
    uint8_t us[256];          /* tn_q: our side  (WILL/WONT sent by us)  */
    uint8_t him[256];         /* tn_q: remote    (DO/DONT sent by us)    */
    bool    allow_us[256];    /* policy: we agree to enable locally      */
    bool    allow_him[256];   /* policy: we agree to let peer enable     */
} tn_opts;

void tn_opts_init(tn_opts *o);
void tn_opts_allow(tn_opts *o, uint8_t opt, bool allow_us, bool allow_him);

bool tn_opts_us_on(const tn_opts *o, uint8_t opt);
bool tn_opts_him_on(const tn_opts *o, uint8_t opt);

/* Process an incoming WILL/WONT/DO/DONT. Any reply (<= 3 bytes) is written to
 * out and its length to *outlen. Returns 1 if the affected side's enabled state
 * changed, otherwise 0. */
int tn_opts_recv(tn_opts *o, uint8_t cmd, uint8_t opt, uint8_t *out, size_t *outlen);

/* Ask to enable/disable an option. Return the number of bytes to send (0..3). */
size_t tn_opts_ask_us(tn_opts *o, uint8_t opt, bool enable, uint8_t *out);   /* WILL / WONT */
size_t tn_opts_ask_him(tn_opts *o, uint8_t opt, bool enable, uint8_t *out);  /* DO / DONT   */

#endif
