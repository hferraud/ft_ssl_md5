#ifndef FT_SSL_MD5_H
#define FT_SSL_MD5_H

#include <stdint.h>
#include <stdlib.h>

#include "ft_ssl.h"

#define MD5_DIGEST_SIZE 16

ft_ssl_status_t md5(uint8_t *message, size_t size, uint8_t digest[MD5_DIGEST_SIZE]);

#endif //FT_SSL_MD5_H