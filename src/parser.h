#ifndef FT_SSL_PARSER_H
#define FT_SSL_PARSER_H

#include <stddef.h>

#include "ft_ssl.h"

#define FT_SSL_OPTIONS_MAX_STRINGS 1024

typedef struct {
    bool print_back;
    bool quiet;
    bool reverse;
    char *strings[FT_SSL_OPTIONS_MAX_STRINGS];
    size_t string_count;
} ft_ssl_options_t;

ft_ssl_status_t ft_ssl_parser(int argc, char **argv, ft_ssl_options_t *ft_ssl_options);

#endif //FT_SSL_PARSER_H