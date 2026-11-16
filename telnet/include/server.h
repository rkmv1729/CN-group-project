#ifndef SERVER_H
#define SERVER_H

#include "server_config.h"

int  server_run(const server_config *cfg);   /* 0 clean exit, -1 error */
void server_request_stop(void);              /* async-signal-safe */

#endif
