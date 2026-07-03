#include "parser.h"

#include <argp.h>

#include "ft_ssl.h"

error_t parser(int key, char *arg, struct argp_state *state);

ft_ssl_status_t sha256_parser_init(int argc, char **argv) {
    static struct argp_option options[] = {
        {"yo", 'y', NULL, 0, "The yo function", 0},
        {0}
    };
    struct argp argp = {
        options,
        parser,
        NULL,
        "Extra text, where is it printed",
        NULL,
        NULL,
        NULL
    };

    argp_parse(&argp, argc, argv, 0, NULL, NULL);
    return FT_SSL_OK;
}

error_t parser(int key, char *arg, struct argp_state *state) {
    (void)key;
    (void)arg;
    (void)state;
    return 0;
}