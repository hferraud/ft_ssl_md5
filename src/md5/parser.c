#include "parser.h"

#include <argp.h>
#include <string.h>

#include "ft_ssl.h"

static error_t parser(int key, char *arg, struct argp_state *state);

ft_ssl_status_t md5_parser(int argc, char **argv, md5_options_t *md5_options) {
    static struct argp_option options[] = {
        {NULL, 'p', NULL, 0, "Print back the original message", 0},
        {"quiet", 'q', NULL, 0, "Do not print anything other than the digest", 0},
        {"reverse", 'r', NULL, 0, "Reverse the format of the output", 0},
        {"sum", 's', "MESSAGE", 0, "Print the sum of the next message", 0},
        {0}
    };
    struct argp argp = {
        options,
        parser,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    };
    argp_parse(&argp, argc, argv, 0, NULL, md5_options);
    return FT_SSL_OK;
}

static error_t parser(int key, char *arg, struct argp_state *state) {
    md5_options_t *md5_options = (md5_options_t*)state->input;
    switch (key) {
        case 'p':
            md5_options->print_back = true;
            break;
        case 'q':
            md5_options->quiet = true;
            break;
        case 'r':
            md5_options->reverse = true;
            break;
        case 's':
            md5_options->sum_input = strdup(arg);
            if (md5_options->sum_input == NULL) {
                //TODO: Handle error
                return -1;
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}