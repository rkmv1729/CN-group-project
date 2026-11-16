#include "client.h"
#include "client_config.h"

int main(int argc, char **argv)
{
    client_config cfg;
    int pr = client_parse_args(argc, argv, &cfg);
    if (pr != 0) return pr > 0 ? 0 : 2;
    return client_run(&cfg);
}
