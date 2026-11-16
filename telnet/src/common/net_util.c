#include "net_util.h"
#include "log.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int net_set_nonblock(int fd, bool on)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    fl = on ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK);
    return fcntl(fd, F_SETFL, fl);
}

int net_set_cloexec(int fd)
{
    int fl = fcntl(fd, F_GETFD, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
}

void net_set_nodelay(int fd)
{
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

int net_listen(const char *addr, uint16_t port, int backlog)
{
    char ps[8];
    snprintf(ps, sizeof ps, "%u", (unsigned)port);
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;
    int rc = getaddrinfo(addr, ps, &hints, &res);
    if (rc) { LOGE("getaddrinfo(%s): %s", addr ? addr : "*", gai_strerror(rc)); return -1; }

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, rp->ai_protocol);
        if (fd < 0) continue;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0 && listen(fd, backlog) == 0) break;
        LOGE("bind/listen on %s:%s: %s", addr ? addr : "*", ps, strerror(errno));
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int net_connect(const char *host, const char *port, int family, int timeout_sec)
{
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc) { LOGE("%s: %s", host, gai_strerror(rc)); return -1; }

    int fd = -1, last_err = 0;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) { last_err = errno; continue; }
        net_set_cloexec(fd);
        net_set_nonblock(fd, true);
        int r = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (r < 0 && errno == EINPROGRESS) {
            struct pollfd p = { .fd = fd, .events = POLLOUT };
            int pr;
            do { pr = poll(&p, 1, timeout_sec * 1000); } while (pr < 0 && errno == EINTR);
            if (pr == 0)      { errno = ETIMEDOUT; r = -1; }
            else if (pr < 0)  { r = -1; }
            else {
                int err = 0; socklen_t el = sizeof err;
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
                if (err) { errno = err; r = -1; } else r = 0;
            }
        }
        if (r == 0) break;
        last_err = errno;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) { LOGE("connect to %s port %s: %s", host, port, strerror(last_err)); return -1; }
    net_set_nonblock(fd, false);
    net_set_nodelay(fd);
    return fd;
}

void net_peer_name(const struct sockaddr *sa, socklen_t len, char *out, size_t cap)
{
    char h[NI_MAXHOST], s[NI_MAXSERV];
    if (getnameinfo(sa, len, h, sizeof h, s, sizeof s, NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        snprintf(out, cap, "unknown");
        return;
    }
    if (sa->sa_family == AF_INET6) snprintf(out, cap, "[%s]:%s", h, s);
    else                           snprintf(out, cap, "%s:%s", h, s);
}

int parse_long(const char *s, long min, long max, long *out)
{
    if (!s || !*s) return -1;
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || *end != '\0' || v < min || v > max) return -1;
    *out = v;
    return 0;
}
