#ifndef FT_SSL_MD5_CRYPTO_H
#define FT_SSL_MD5_CRYPTO_H

#include "ft_ssl.h"
#include <stdint.h>
#include <stddef.h>

ft_ssl_status_t md5(uint8_t *message, size_t size, uint8_t digest[16]);

#endif //FT_SSL_MD5_CRYPTO_H