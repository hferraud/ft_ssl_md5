#include "sha256.h"

#include <string.h>

#include "parser.h"
#include "crypto.h"
#include "stdio.h"

ft_ssl_status_t sha256_handler(int argc, char **argv) {
    uint8_t digest[SHA256_DIGEST_SIZE];
    ft_ssl_options_t options = {0};

    sha256_parser(argc, argv, &options);
    if (options.strings != NULL) {
        sha256((uint8_t*)options.strings[0], strlen(options.strings[0]), digest);
    }
    printf("Digest:\n");
    for (size_t i = 0; i < SHA256_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    return FT_SSL_OK;
}
