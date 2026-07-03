#include "sha256.h"
#include "parser.h"

ft_ssl_status_t sha256(int argc, char **argv) {
    sha256_parser_init(argc, argv);
    return FT_SSL_OK;
}
