#ifndef FT_SSL_SHA256_PARSER_H
#define FT_SSL_SHA256_PARSER_H

#include <stdbool.h>
#include <stddef.h>

#include "ft_ssl.h"

typedef struct {
    bool print_back;
    bool quiet;
    bool reverse;
    char **strings;
} ft_ssl_options_t;

ft_ssl_status_t sha256_parser(int argc, char **argv, ft_ssl_options_t *ft_ssl_options);

#endif //FT_SSL_SHA256_PARSER_H