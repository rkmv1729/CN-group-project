#ifndef NET_UTIL_H
#define NET_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/* Non-blocking, close-on-exec listening socket. Returns fd or -1. */
int  net_listen(const char *addr, uint16_t port, int backlog);
/* Connect with timeout; family AF_UNSPEC/AF_INET/AF_INET6. Returns a blocking fd or -1. */
int  net_connect(const char *host, const char *port, int family, int timeout_sec);
int  net_set_nonblock(int fd, bool on);
int  net_set_cloexec(int fd);
void net_set_nodelay(int fd);
void net_peer_name(const struct sockaddr *sa, socklen_t len, char *out, size_t cap);

/* Strict integer parse: whole string, range-checked. 0 ok, -1 error. */
int  parse_long(const char *s, long min, long max, long *out);

#endif
