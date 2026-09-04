#include "sha256.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ft_ssl.h"

#define PADDING_MODULO 64
#define BLOCK_SIZE_U32 16
#define SCHEDULE_SIZE_U32 64
#define SHA256_PADDING_SIZE 8

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define BSIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define SSIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

static const uint32_t g_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_get_digest(sha256_state_t *state, uint8_t digest[SHA256_DIGEST_SIZE]);
static void sha256_process_block(const uint8_t *block, sha256_state_t *state);
static void sha256_schedule(uint32_t schedule[SCHEDULE_SIZE_U32], const uint8_t block[SHA256_BLOCK_SIZE]);
static void sha256_state_rotate(sha256_state_t *state, uint32_t t1, uint32_t t2);
static void sha256_state_update(sha256_state_t *state, const sha256_state_t *old_state);
static void sha256_message_fill(sha256_ctx *ctx, bool first);
static void sha256_message_append_size(size_t size, uint8_t *ptr);

void sha256_init(sha256_ctx *ctx)
{
    ctx->state.a = 0x6a09e667;
    ctx->state.b = 0xbb67ae85;
    ctx->state.c = 0x3c6ef372;
    ctx->state.d = 0xa54ff53a;
    ctx->state.e = 0x510e527f;
    ctx->state.f = 0x9b05688c;
    ctx->state.g = 0x1f83d9ab;
    ctx->state.h = 0x5be0cd19;
    ctx->buffer_len = 0;
    ctx->total_len = 0;
}

void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    if (ctx->buffer_len != 0 && ctx->buffer_len + len > SHA256_BLOCK_SIZE)
    {
        //There are leftover data in the buffer and we can process it
        size_t offset = SHA256_BLOCK_SIZE - ctx->buffer_len;
        memcpy(ctx->buffer + ctx->buffer_len, data, offset);
        sha256_state_t old_state = ctx->state;
        sha256_process_block(ctx->buffer, &ctx->state);
        sha256_state_update(&ctx->state, &old_state);
        ctx->total_len += SHA256_BLOCK_SIZE;
        data += offset;
        len -= offset;
    }
    while (len >= SHA256_BLOCK_SIZE)
    {
        sha256_state_t old_state = ctx->state;
        sha256_process_block(data, &ctx->state);
        sha256_state_update(&ctx->state, &old_state);
        ctx->total_len += SHA256_BLOCK_SIZE;
        data += SHA256_BLOCK_SIZE;
        len -= SHA256_BLOCK_SIZE;
    }
    memcpy(ctx->buffer + ctx->buffer_len, data, len);
    ctx->buffer_len = len;
}

void sha256_final(sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE])
{
    bool padding_flag = false;
    ctx->total_len += ctx->buffer_len;
    if (ctx->buffer_len >= SHA256_BLOCK_SIZE - SHA256_PADDING_SIZE)
    {
        sha256_message_fill(ctx, true);
        sha256_state_t old_state = ctx->state;
        sha256_process_block(ctx->buffer, &ctx->state);
        sha256_state_update(&ctx->state, &old_state);
        ctx->buffer_len = 0;
        padding_flag = true;
    }
    sha256_message_fill(ctx, !padding_flag);
    sha256_message_append_size(ctx->total_len, ctx->buffer + SHA256_BLOCK_SIZE - SHA256_PADDING_SIZE);
    sha256_state_t old_state = ctx->state;
    sha256_process_block(ctx->buffer, &ctx->state);
    sha256_state_update(&ctx->state, &old_state);
    sha256_get_digest(&ctx->state, digest);
}

void sha256_str(const char *str, uint8_t digest[SHA256_DIGEST_SIZE])
{
    sha256_ctx ctx;
    size_t len = strlen(str);

    sha256_init(&ctx);
    sha256_update(&ctx, (uint8_t*)str, len);
    sha256_final(&ctx, digest);
}

ssize_t sha256_fd(int fd, bool print, uint8_t digest[SHA256_DIGEST_SIZE])
{
    sha256_ctx ctx;
    uint8_t buf[SHA256_BLOCK_SIZE];
    ssize_t buf_len;
    ssize_t total_len = 0;

    sha256_init(&ctx);
    buf_len = read(fd, buf, SHA256_BLOCK_SIZE);
    if (buf_len > 0 && print)
    {
        printf("(\"");
    }
    total_len += buf_len;
    while (buf_len > 0)
    {
        sha256_update(&ctx, buf, buf_len);
        if (print)
        {
            write(STDOUT_FILENO, buf, buf_len);
        }
        buf_len = read(fd, buf, SHA256_BLOCK_SIZE);
        total_len += buf_len;
    }
    if (print)
    {
        printf("\")");
    }
    if (buf_len == -1)
    {
        //TODO: Do sum
        return -1;
    }
    sha256_final(&ctx, digest);
    return total_len;
}

static void sha256_get_digest(sha256_state_t *state, uint8_t digest[SHA256_DIGEST_SIZE]) {
    uint32_t words[8] = {
        state->a, state->b, state->c, state->d,
        state->e, state->f, state->g, state->h
    };

    for (size_t i = 0; i < 8; i++) {
        for (size_t j = 0; j < 4; j++) {
            digest[i * 4 + j] = words[i] >> (8 * (3 - j));
        }
    }
}

static void sha256_process_block(const uint8_t *block, sha256_state_t *state) {
    uint32_t schedule[SCHEDULE_SIZE_U32];
    uint32_t t1, t2;

    sha256_schedule(schedule, block);
    for (size_t i = 0; i < 64; i++) {
        t1 = state->h + BSIG1(state->e) + CH(state->e, state->f, state->g) + g_sha256_k[i] + schedule[i];
        t2 = BSIG0(state->a) + MAJ(state->a, state->b, state->c);
        sha256_state_rotate(state, t1, t2);
    }
}

static void sha256_schedule(uint32_t schedule[SCHEDULE_SIZE_U32], const uint8_t block[SHA256_BLOCK_SIZE]) {
    //First we copy the 64 byte message block into the first 16 entry of the message schedule
for (size_t i = 0; i < 16; i++)
    {
        schedule[i] =
              ((uint32_t)block[i * 4] << 24)
            | ((uint32_t)block[i * 4 + 1] << 16)
            | ((uint32_t)block[i * 4 + 2] << 8)
            | ((uint32_t)block[i * 4 + 3]);
    }    //Then we fill the message schedule according to sha256 algorithm
    for (size_t i = BLOCK_SIZE_U32; i < SCHEDULE_SIZE_U32; i++) {
        schedule[i] = SSIG1(schedule[i - 2])
        + schedule[i - 7]
        + SSIG0(schedule[i - 15])
        + schedule[i - 16];
    }
}

static void sha256_state_rotate(sha256_state_t *state, uint32_t t1, uint32_t t2) {
    state->h = state->g;
    state->g = state->f;
    state->f = state->e;
    state->e = state->d + t1;
    state->d = state->c;
    state->c = state->b;
    state->b = state->a;
    state->a = t1 + t2;
}

static void sha256_state_update(sha256_state_t *state, const sha256_state_t *old_state) {
    state->a += old_state->a;
    state->b += old_state->b;
    state->c += old_state->c;
    state->d += old_state->d;
    state->e += old_state->e;
    state->f += old_state->f;
    state->g += old_state->g;
    state->h += old_state->h;
}

/**
 * @brief Fill the message with the sha256 padding pattern
 * @param[in] ctx sha256 context
 * @param[in] first Flag used to append a `1` bit or not
 */
static void sha256_message_fill(sha256_ctx *ctx, bool first) {
    if (first)
    {
        ctx->buffer[ctx->buffer_len] = 0x80;
        ctx->buffer_len++;
    }
    while (ctx->buffer_len != SHA256_BLOCK_SIZE)
    {
        ctx->buffer[ctx->buffer_len] = 0x00;
        ctx->buffer_len++;
    }
}

/**
 * @brief Write the old message size in bits at the specified address
 * @param size[in] The size in bytes of the original message
 * @param ptr[in] The address where the size will be written
 */
static void sha256_message_append_size(size_t size, uint8_t *ptr) {
    uint64_t bit_size;

    //We get the size of the message in bits
    bit_size = (uint64_t)size * 8;
    //Then we write it in little endian
    for (size_t i = 0; i < 8; i++) {
        ptr[i] = bit_size >> ((7 - i) * 8) & 0xFF;
    }
}
