#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include "log.h"

typedef struct {
    const char *bind_addr;     /* -b  default 127.0.0.1 */
    uint16_t    port;          /* -p  default 2323      */
    const char *shell;         /* -s  default /bin/sh   */
    int         max_clients;   /* -m  default 32        */
    int         idle_timeout;  /* -w  seconds, 0 = off  */
    log_level   log_level;     /* -L  default info      */
    const char *log_file;      /* -l  default stderr    */
    const char *banner_file;   /* -B                    */
    char       *banner_text;   /* loaded from banner_file */
    bool        allow_root;    /* -R                    */
} server_config;

/* Returns 0 = run, 1 = exit successfully (help/version), -1 = usage error. */
int  server_parse_args(int argc, char **argv, server_config *cfg);
void server_config_free(server_config *cfg);

#endif
