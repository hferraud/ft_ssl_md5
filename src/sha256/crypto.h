#ifndef FT_SSL_SHA256_CRYPTO_H
#define FT_SSL_SHA256_CRYPTO_H

#define SHA256_DIGEST_SIZE 32

#include <stdint.h>
#include <stddef.h>

#include "ft_ssl.h"

ft_ssl_status_t sha256(uint8_t *message, size_t size, uint8_t digest[SHA256_DIGEST_SIZE]);

#endif //FT_SSL_SHA256_CRYPTO_H