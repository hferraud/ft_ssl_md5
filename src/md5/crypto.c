#include "crypto.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ft_ssl.h"

#define STATE_A_INIT 0x67452301
#define STATE_B_INIT 0xefcdab89
#define STATE_C_INIT 0x98badcfe
#define STATE_D_INIT 0x10325476

#define PADDING_MODULO 64
#define PADDING_SIZE 8

uint8_t *md5_pad(uint8_t *message, size_t *size);

typedef struct {
    uint32_t state_a;
    uint32_t state_b;
    uint32_t state_c;
    uint32_t state_d;
} md5_state_t;

#include <stdio.h>

ft_ssl_status_t md5(uint8_t *message, size_t size) {

    printf("Original message:\n");
    for (size_t i = 0; i < size; i++) {
        printf("%02x", message[i]);
    }
    printf("\n");
    message = md5_pad(message, &size);
    if (message == NULL) {
        return FT_SSL_ERROR;
    }
    printf("Padded message:\n");
    for (size_t i = 0; i < size; i++) {
        printf("%02x", message[i]);
    }
    printf("\n");
    size_t encoded_size = message[]
    printf()

    free(message);
    return FT_SSL_OK;
}

uint8_t *md5_pad(uint8_t *message, size_t *size) {
    size_t old_size;
    size_t padding;

    //We need to pad the message to contain its size and the length (in bytes)
    //needs to be a multiple of 64.
    old_size = *size;
    padding = PADDING_MODULO + PADDING_SIZE - (old_size + PADDING_SIZE) % PADDING_MODULO;
    *size = old_size + padding;
    message = realloc(message, old_size + padding);
    if (message == NULL) {
        return NULL;
    }
    printf("Padding: %zu\n", padding);
    //Now that the message is at the correct size we need to pad it
    for (size_t i = 0; i < padding; i++) {
        if (i == 0) {
            //First we pad the message with a single `1` bit then `0` bits
            message[old_size] = 0x80;
        }
        else if (i < padding - PADDING_SIZE) {
            //Then we simply pad with `0` bits until we have just enough
            //bytes to write the size
            message[old_size + i] = 0x00;
        }
        else {
            //Then we write the size of the original message at the end
            message[old_size + i] = (old_size >> (padding - i - 1)) & 0xFF;
        }
    }
    return message;
}