#include "crypto.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ft_ssl.h"

#define STATE_A_INIT 0x67452301
#define STATE_B_INIT 0xefcdab89
#define STATE_C_INIT 0x98badcfe
#define STATE_D_INIT 0x10325476

#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define PADDING_MODULO 64
#define PADDING_SIZE 8
#define U32_BLOCK_SIZE 16

typedef struct {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
} md5_state_t;

typedef uint32_t (*md5_operation_t)(
    uint32_t x,
    uint32_t y,
    uint32_t z
);

typedef uint32_t (*md5_index_t)(uint32_t i);

static const uint32_t g_md5_k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint32_t g_md5_shift[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

static void md5_initialize(md5_state_t *state);

static void md5_process_message(md5_state_t *state, uint8_t *message, size_t size);
static void md5_process_block(const uint32_t *block, md5_state_t *state);
static uint32_t md5_f(uint32_t x, uint32_t y, uint32_t z);
static uint32_t md5_g(uint32_t x, uint32_t y, uint32_t z);
static uint32_t md5_h(uint32_t x, uint32_t y, uint32_t z);
static uint32_t md5_i(uint32_t x, uint32_t y, uint32_t z);
static uint32_t md5_index_f(uint32_t i);
static uint32_t md5_index_g(uint32_t i);
static uint32_t md5_index_h(uint32_t i);
static uint32_t md5_index_i(uint32_t i);
static void md5_state_rotate(md5_state_t *state);
static void md5_state_update(md5_state_t *state, const md5_state_t *old_state);

static uint8_t *md5_message_pad(uint8_t *message, size_t *size);
static uint8_t *md5_message_extend(uint8_t *message, size_t *size);
static void md5_message_fill(uint8_t *ptr, size_t padding);
static void md5_message_append_size(size_t size, uint8_t *ptr);


ft_ssl_status_t md5(uint8_t *message, size_t size, uint8_t digest[16]) {
    md5_state_t state;

    message = md5_message_pad(message, &size);
    if (message == NULL) {
        free(message);
        return FT_SSL_ERROR;
    }
    md5_initialize(&state);

    md5_process_message(&state, message, size);
    memcpy(digest, &state, sizeof(state));
    free(message);
    return FT_SSL_OK;
}

static void md5_initialize(md5_state_t *state) {
    state->a = STATE_A_INIT;
    state->b = STATE_B_INIT;
    state->c = STATE_C_INIT;
    state->d = STATE_D_INIT;
}

static void md5_process_message(md5_state_t *state, uint8_t *message, size_t size) {
    while (size > 0) {
        md5_state_t old_state = *state;
        md5_process_block((uint32_t*)message, state);
        md5_state_update(state, &old_state);
        message += PADDING_MODULO;
        size -= PADDING_MODULO;
    }
}

static void md5_process_block(const uint32_t *block, md5_state_t *state) {
    static const md5_operation_t md5_operations[4] = {
        md5_f,
        md5_g,
        md5_h,
        md5_i
    };
    static const md5_index_t md5_indexes[4] = {
        md5_index_f,
        md5_index_g,
        md5_index_h,
        md5_index_i
    };
    uint32_t round;
    uint32_t f;
    uint32_t g;

    for (size_t i = 0; i < 64; i++) {
        round = i / 16;

        f = md5_operations[round](state->b, state->c, state->d);
        g = md5_indexes[round](i);

        state->a = state->b + ROTL(
            state->a + f + block[g] + g_md5_k[i],
            g_md5_shift[i]);
        md5_state_rotate(state);
    }
}

static uint32_t md5_f(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (~x & z);
}

static uint32_t md5_g(uint32_t x, uint32_t y, uint32_t z) {
    return (x & z) | (y & ~z);
}

static uint32_t md5_h(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}

static uint32_t md5_i(uint32_t x, uint32_t y, uint32_t z) {
    return y ^ (x | ~z);
}

static uint32_t md5_index_f(uint32_t i) {
    return i;
}

static uint32_t md5_index_g(uint32_t i) {
    return (5 * i + 1) % 16;
}

static uint32_t md5_index_h(uint32_t i) {
    return (3 * i + 5) % 16;
}

static uint32_t md5_index_i(uint32_t i) {
    return (7 * i) % 16;
}

static void md5_state_rotate(md5_state_t *state) {
    uint32_t temp;

    temp = state->d;
    state->d = state->c;
    state->c = state->b;
    state->b = state->a;
    state->a = temp;
}

static void md5_state_update(md5_state_t *state, const md5_state_t *old_state) {
    state->a += old_state->a;
    state->b += old_state->b;
    state->c += old_state->c;
    state->d += old_state->d;
}

/**
 * @brief Pad the message according to md5 algorithm
 * @param[in] message The original message
 * @param[out] size The original size, contain the new size afterward
 * @return The new padded message
 */
static uint8_t *md5_message_pad(uint8_t *message, size_t *size) {
    size_t old_size;
    size_t padding;

    old_size = *size;
    message = md5_message_extend(message, size);
    padding = *size - old_size;
    if (message == NULL) {
        return NULL;
    }
    md5_message_fill(message + old_size, padding);
    md5_message_append_size(old_size, message + *size - 8);
    return message;
}

/**
 * @brief Allocate extra memory to pad the message
 * @param[in] message Byte array containing the message, needs to be allocated on
 * the heap
 * @param[out] size The size of the message, will contain the extended size at
 * exit
 * @return A pointer to the new message
 */
static uint8_t *md5_message_extend(uint8_t *message, size_t *size) {
    size_t padding;
    uint8_t *extended_message;

    padding = PADDING_MODULO + PADDING_SIZE - (*size + PADDING_SIZE) % PADDING_MODULO;
    extended_message = realloc(message, *size + padding);
    if (extended_message == NULL) {
        free(message);
        return NULL;
    }
    *size += padding;
    return extended_message;
}

/**
 * @brief Fill the message with the md5 padding pattern
 * @param[out] ptr A pointer to the end of the original message which correspond
 * to the start of the padding area.
 * @param[in] padding The size added to the original message to extend it
 */
static void md5_message_fill(uint8_t *ptr, size_t padding) {
    *ptr++ = 0x80;
    for (size_t i = 1; i < padding; i++) {
        *ptr++ = 0x00;
    }
}

/**
 * @brief Write the old message size in bits at the specified address
 * @param size[in] The size in bytes of the original message
 * @param ptr[in] The address where the size will be written
 */
static void md5_message_append_size(size_t size, uint8_t *ptr) {
    uint64_t bit_size;

    //We get the size of the message in bits
    bit_size = (uint64_t)size * 8;
    //Then we write it in little endian
    for (size_t i = 0; i < 8; i++) {
        ptr[i] = bit_size >> (i * 8) & 0xFF;
    }
}