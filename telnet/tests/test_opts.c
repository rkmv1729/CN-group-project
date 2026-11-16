#include "telnet_opts.h"
#include "telnet_proto.h"
#include <stdio.h>
#include <string.h>

static int failures, checks;
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static int is_reply(const uint8_t *b, size_t n, uint8_t cmd, uint8_t opt)
{
    return n == 3 && b[0] == TN_IAC && b[1] == cmd && b[2] == opt;
}

static void test_accept_and_refuse(void)
{
    tn_opts o; tn_opts_init(&o);
    tn_opts_allow(&o, TNO_NAWS, false, true);
    uint8_t out[3]; size_t n;

    CHECK(tn_opts_recv(&o, TN_WILL, TNO_NAWS, out, &n) == 1);
    CHECK(is_reply(out, n, TN_DO, TNO_NAWS));
    CHECK(tn_opts_him_on(&o, TNO_NAWS));

    CHECK(tn_opts_recv(&o, TN_WILL, 99, out, &n) == 0);          /* not allowed */
    CHECK(is_reply(out, n, TN_DONT, 99));
    CHECK(!tn_opts_him_on(&o, 99));

    CHECK(tn_opts_recv(&o, TN_DO, TNO_ECHO, out, &n) == 0);      /* us not allowed */
    CHECK(is_reply(out, n, TN_WONT, TNO_ECHO));
}

static void test_no_loops(void)
{
    tn_opts o; tn_opts_init(&o);
    tn_opts_allow(&o, TNO_SGA, true, true);
    uint8_t out[3]; size_t n;

    CHECK(tn_opts_recv(&o, TN_WILL, TNO_SGA, out, &n) == 1 && n == 3);
    CHECK(tn_opts_recv(&o, TN_WILL, TNO_SGA, out, &n) == 0 && n == 0);   /* duplicate: silent */
    CHECK(tn_opts_recv(&o, TN_WONT, TNO_SGA, out, &n) == 1);
    CHECK(is_reply(out, n, TN_DONT, TNO_SGA));
    CHECK(tn_opts_recv(&o, TN_WONT, TNO_SGA, out, &n) == 0 && n == 0);   /* duplicate: silent */
}

static void test_ask_then_answer(void)
{
    tn_opts o; tn_opts_init(&o);
    tn_opts_allow(&o, TNO_ECHO, true, false);
    uint8_t out[3]; size_t n;

    n = tn_opts_ask_us(&o, TNO_ECHO, true, out);
    CHECK(is_reply(out, n, TN_WILL, TNO_ECHO));
    CHECK(o.us[TNO_ECHO] == Q_WANTYES);
    CHECK(tn_opts_ask_us(&o, TNO_ECHO, true, out) == 0);                 /* already asked */

    CHECK(tn_opts_recv(&o, TN_DO, TNO_ECHO, out, &n) == 1 && n == 0);    /* confirmed, no reply */
    CHECK(tn_opts_us_on(&o, TNO_ECHO));

    /* refused */
    tn_opts_allow(&o, TNO_NAWS, true, false);
    tn_opts_ask_us(&o, TNO_NAWS, true, out);
    CHECK(tn_opts_recv(&o, TN_DONT, TNO_NAWS, out, &n) == 0 && n == 0);
    CHECK(o.us[TNO_NAWS] == Q_NO);
}

static void test_opposite_queue(void)
{
    tn_opts o; tn_opts_init(&o);
    tn_opts_allow(&o, TNO_TTYPE, false, true);
    uint8_t out[3]; size_t n;

    tn_opts_ask_him(&o, TNO_TTYPE, true, out);                           /* DO sent */
    CHECK(o.him[TNO_TTYPE] == Q_WANTYES);
    CHECK(tn_opts_ask_him(&o, TNO_TTYPE, false, out) == 0);              /* changed our mind: queued */
    CHECK(o.him[TNO_TTYPE] == Q_WANTYES_OPP);

    CHECK(tn_opts_recv(&o, TN_WILL, TNO_TTYPE, out, &n) == 0);           /* enabled, then... */
    CHECK(is_reply(out, n, TN_DONT, TNO_TTYPE));                         /* ...we ask it to stop */
    CHECK(o.him[TNO_TTYPE] == Q_WANTNO);
    CHECK(tn_opts_recv(&o, TN_WONT, TNO_TTYPE, out, &n) == 0 && n == 0);
    CHECK(o.him[TNO_TTYPE] == Q_NO);
}

static void test_disable_request(void)
{
    tn_opts o; tn_opts_init(&o);
    tn_opts_allow(&o, TNO_SGA, true, true);
    uint8_t out[3]; size_t n;
    tn_opts_recv(&o, TN_DO, TNO_SGA, out, &n);
    CHECK(tn_opts_us_on(&o, TNO_SGA));
    n = tn_opts_ask_us(&o, TNO_SGA, false, out);
    CHECK(is_reply(out, n, TN_WONT, TNO_SGA) && o.us[TNO_SGA] == Q_WANTNO);
    CHECK(tn_opts_recv(&o, TN_DONT, TNO_SGA, out, &n) == 0 && n == 0);  /* already "off" since our WONT */
    CHECK(!tn_opts_us_on(&o, TNO_SGA));
}

int main(void)
{
    test_accept_and_refuse();
    test_no_loops();
    test_ask_then_answer();
    test_opposite_queue();
    test_disable_request();
    printf("test_opts: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
