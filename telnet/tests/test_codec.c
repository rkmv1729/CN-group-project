#include "telnet_codec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures, checks;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

typedef struct { char log[1024]; int in_data; } rec;

static void cb(const tn_event *ev, void *u)
{
    rec *r = u;
    char t[64];
    if (ev->type == TN_EV_DATA) {
        /* adjacent DATA events (split across feed() calls) are merged */
        if (r->in_data) r->log[strlen(r->log) - 1] = '\0';   /* drop trailing ';' */
        else strcat(r->log, "D:");
        for (size_t i = 0; i < ev->len; i++) { snprintf(t, sizeof t, "%02x", ev->data[i]); strcat(r->log, t); }
        strcat(r->log, ";");
        r->in_data = 1;
        return;
    }
    r->in_data = 0;
    switch (ev->type) {
    case TN_EV_NEGOTIATE: snprintf(t, sizeof t, "N:%u,%u;", ev->cmd, ev->opt); strcat(r->log, t); break;
    case TN_EV_CMD:       snprintf(t, sizeof t, "C:%u;", ev->cmd); strcat(r->log, t); break;
    case TN_EV_SUBNEG:
        snprintf(t, sizeof t, "S:%u:", ev->opt); strcat(r->log, t);
        for (size_t i = 0; i < ev->len; i++) { snprintf(t, sizeof t, "%02x", ev->data[i]); strcat(r->log, t); }
        strcat(r->log, ";");
        break;
    default: break;
    }
}

static void run(bool collapse, const uint8_t *in, size_t n, size_t chunk, rec *r)
{
    tn_parser *p = tn_parser_new(collapse);
    r->log[0] = '\0';
    r->in_data = 0;
    for (size_t i = 0; i < n; i += chunk)
        tn_parser_feed(p, in + i, (n - i < chunk ? n - i : chunk), cb, r);
    tn_parser_free(p);
}

static void test_basic_and_split(void)
{
    const uint8_t in[] = { 'a', 'b', TN_IAC, TN_WILL, TNO_ECHO, 'c', 'd' };
    rec r;
    /* Result must be identical regardless of how the stream is chunked. */
    for (size_t chunk = 1; chunk <= sizeof in; chunk++) {
        run(true, in, sizeof in, chunk, &r);
        CHECK(strcmp(r.log, "D:6162;N:251,1;D:6364;") == 0);
    }
}

static void test_iac_escape(void)
{
    const uint8_t in[] = { 'x', TN_IAC, TN_IAC, 'y' };
    rec r;
    for (size_t chunk = 1; chunk <= sizeof in; chunk++) {
        run(true, in, sizeof in, chunk, &r);
        CHECK(strcmp(r.log, "D:78ff79;") == 0);
    }
}

static void test_subneg(void)
{
    const uint8_t in[] = { TN_IAC, TN_SB, TNO_NAWS, 0, 80, 0, 24, TN_IAC, TN_SE, 'z' };
    rec r;
    for (size_t chunk = 1; chunk <= sizeof in; chunk++) {
        run(true, in, sizeof in, chunk, &r);
        CHECK(strcmp(r.log, "S:31:00500018;D:7a;") == 0);
    }
    /* IAC inside a subnegotiation is doubled */
    const uint8_t in2[] = { TN_IAC, TN_SB, TNO_NAWS, 0, 255, 255, 0, 24, TN_IAC, TN_SE };
    run(true, in2, sizeof in2, 3, &r);
    CHECK(strcmp(r.log, "S:31:00ff0018;") == 0);
}

static void test_commands(void)
{
    const uint8_t in[] = { 'a', TN_IAC, TN_IP, 'b', TN_IAC, TN_AYT };
    rec r;
    run(true, in, sizeof in, 2, &r);
    CHECK(strcmp(r.log, "D:61;C:244;D:62;C:246;") == 0);
}

static void test_cr_handling(void)
{
    rec r;
    const uint8_t crnul[] = { 'a', '\r', 0, 'b' };
    const uint8_t crlf[]  = { 'a', '\r', '\n', 'b' };
    const uint8_t lone[]  = { 'a', '\n', 'b' };
    run(true,  crnul, sizeof crnul, 1, &r); CHECK(strcmp(r.log, "D:610d62;") == 0);
    run(false, crnul, sizeof crnul, 2, &r); CHECK(strcmp(r.log, "D:610d62;") == 0);
    run(true,  crlf,  sizeof crlf,  1, &r); CHECK(strcmp(r.log, "D:610d62;") == 0);   /* collapsed */
    run(false, crlf,  sizeof crlf,  1, &r); CHECK(strcmp(r.log, "D:610d0a62;") == 0); /* kept */
    run(true,  lone,  sizeof lone,  1, &r); CHECK(strcmp(r.log, "D:610a62;") == 0);
}

static void test_oversized_subneg(void)
{
    uint8_t in[TN_SB_MAX + 100];
    size_t n = 0;
    in[n++] = TN_IAC; in[n++] = TN_SB; in[n++] = TNO_TTYPE;
    for (int i = 0; i < TN_SB_MAX + 50; i++) in[n++] = 'x';
    in[n++] = TN_IAC; in[n++] = TN_SE; in[n++] = 'z';
    rec r;
    run(true, in, n, 7, &r);
    CHECK(strcmp(r.log, "D:7a;") == 0);          /* dropped, parser recovered */
}

static void test_malformed_sb(void)
{
    const uint8_t in[] = { TN_IAC, TN_SB, TNO_TTYPE, 'a', TN_IAC, TN_NOP, 'q' };
    rec r;
    run(true, in, sizeof in, 1, &r);
    CHECK(strcmp(r.log, "D:71;") == 0);
}

static void test_encoder(void)
{
    tn_encoder e; tn_encoder_init(&e);
    const uint8_t in[] = { 'a', '\r', 'b', 0xFF, '\r', '\n' };
    uint8_t out[64];
    size_t n = tn_encode_data(&e, in, sizeof in, out, sizeof out);
    const uint8_t want[] = { 'a', '\r', 0, 'b', 0xFF, 0xFF, '\r', '\n' };
    CHECK(n == sizeof want && memcmp(out, want, n) == 0);

    /* CR at a chunk boundary: NUL is added at the start of the next chunk */
    tn_encoder_init(&e);
    const uint8_t c1[] = { 'x', '\r' }, c2[] = { 'y' };
    n = tn_encode_data(&e, c1, 2, out, sizeof out);
    CHECK(n == 2);
    n = tn_encode_data(&e, c2, 1, out, sizeof out);
    CHECK(n == 2 && out[0] == 0 && out[1] == 'y');

    CHECK(tn_encode_data(&e, in, sizeof in, out, 4) == 0);   /* too small */

    uint8_t b[16];
    n = tn_encode_naws(80, 24, b, sizeof b);
    const uint8_t naws[] = { TN_IAC, TN_SB, TNO_NAWS, 0, 80, 0, 24, TN_IAC, TN_SE };
    CHECK(n == sizeof naws && memcmp(b, naws, n) == 0);
    n = tn_encode_naws(255, 24, b, sizeof b);                /* 0x00FF -> IAC escaped */
    CHECK(n == 10 && b[3] == 0 && b[4] == 0xFF && b[5] == 0xFF);
}

static void test_roundtrip(void)
{
    uint8_t in[256];
    for (int i = 0; i < 256; i++) in[i] = (uint8_t)i;
    tn_encoder e; tn_encoder_init(&e);
    uint8_t enc[256 * 3];
    size_t n = tn_encode_data(&e, in, sizeof in, enc, sizeof enc);

    tn_parser *p = tn_parser_new(false);
    rec r; r.log[0] = '\0'; r.in_data = 0;
    tn_parser_feed(p, enc, n, cb, &r);
    tn_parser_free(p);

    /* rebuild expected hex from original; NUL after CR is consumed, so compare
       against the same data minus nothing: CR(13) is followed by 14, NUL was not
       inserted because the next byte (14) is not '\n'/0 -> NUL inserted & swallowed. */
    char want[1024] = "D:";
    for (int i = 0; i < 256; i++) { char t[4]; snprintf(t, sizeof t, "%02x", i); strcat(want, t); }
    strcat(want, ";");
    CHECK(strcmp(r.log, want) == 0);
}

int main(void)
{
    test_basic_and_split();
    test_iac_escape();
    test_subneg();
    test_commands();
    test_cr_handling();
    test_oversized_subneg();
    test_malformed_sb();
    test_encoder();
    test_roundtrip();
    printf("test_codec: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
