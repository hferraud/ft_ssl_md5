#ifndef FT_SSL_SHA256_H
#define FT_SSL_SHA256_H

#include <stdint.h>
#include <stdlib.h>

#include "ft_ssl.h"

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

typedef struct {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
} sha256_state_t;

typedef struct {
    sha256_state_t state;
    uint64_t total_len;
    unsigned char buffer[SHA256_BLOCK_SIZE];
    size_t buffer_len;
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

void sha256_str(const char *str, uint8_t digest[SHA256_DIGEST_SIZE]);
ssize_t sha256_fd(int fd, bool print, uint8_t digest[SHA256_DIGEST_SIZE]);

#endif //FT_SSL_SHA256_H