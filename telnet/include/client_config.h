#ifndef CLIENT_CONFIG_H
#define CLIENT_CONFIG_H

#include <stdbool.h>

typedef struct {
    const char *host;
    const char *port;            /* string: numeric or service name */
    int         family;          /* AF_UNSPEC / AF_INET / AF_INET6  */
    int         escape;          /* escape char, -1 = disabled      */
    const char *term;            /* NULL = $TERM                    */
    int         connect_timeout; /* seconds                         */
    bool        debug;
} client_config;

/* Returns 0 = run, 1 = exit successfully (help/version), -1 = usage error. */
int client_parse_args(int argc, char **argv, client_config *cfg);

#endif
