#ifndef FT_SSL_MD5_PARSER_H
#define FT_SSL_MD5_PARSER_H

#include <stdbool.h>

#include "ft_ssl.h"

typedef struct {
    bool print_back;
    bool quiet;
    bool reverse;
    char *sum_input;
} md5_options_t;

ft_ssl_status_t md5_parser(int argc, char **argv, md5_options_t *md5_options);

#endif //FT_SSL_MD5_PARSER_H