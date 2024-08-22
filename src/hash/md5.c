#include "md5.h"
#include "libft.h"
#include <unistd.h>

void md5_init(md5_context_t *, md5_info_t *);
void fill_buffer(unsigned char *, md5_info_t *);
void put_padding_size(unsigned char *, size_t);
// DEBUG FUNCTION
void print_buffer(md5_context_t *, md5_info_t *);

char *md5(char *input) {
	md5_context_t	context;
	md5_info_t		info;

	info.input = (unsigned char *)input;
	info.length = ft_strlen(input);
	md5_init(&context, &info);
	while (info.chunk_index <= info.end_chunk) {
		fill_buffer(context.buffer, &info);
		print_buffer(&context, &info); // TODO: remove debug
	}
	return input;
}

void md5_init(md5_context_t *context, md5_info_t *info) {
	info->chunk_index = 0;
	info->pad_chunk = info->length / 64;
	info->end_chunk = (info->length % 64) >= 56 ? info->pad_chunk + 1 : info->pad_chunk;
	context->state[A_INDEX] = A_INIT;
	context->state[B_INDEX] = B_INIT;
	context->state[C_INDEX] = C_INIT;
	context->state[D_INDEX] = D_INIT;
}

void fill_buffer(unsigned char *buffer, md5_info_t *info) {
	size_t index = info->chunk_index * CHUNK_LEN;
	if (info->chunk_index < info->pad_chunk) {
		ft_memcpy(buffer, info->input + index, CHUNK_LEN);
		return;
	}
	if (info->chunk_index == info->pad_chunk) {
		size_t copy_length = info->length - index;
		ft_memcpy(buffer, info->input + index, copy_length);
		ft_bzero(buffer + copy_length, CHUNK_LEN - copy_length);
		buffer[copy_length] = PADDING_FIRST_BYTE;
	}
	if (info->chunk_index == info->end_chunk) {
		if (info->chunk_index != info->pad_chunk) {
			ft_bzero(buffer, CHUNK_LEN);
		}
		put_padding_size(buffer, info->length);
	}
}

void put_padding_size(unsigned char *buffer, size_t length) {
	size_t offset = CHUNK_LEN - PADDING_MSG_LEN;
	unsigned char byte;

	while (length > 0) {
		byte = length & 0xff;
		buffer[offset] = byte;
		length >>= 8;
		offset++;
	}
}

// DEBUG FUNCTION
#include <stdio.h>

void print_buffer(md5_context_t *context, md5_info_t *info) {
	for (size_t i = 0; i < 8; i++) {
		printf("%zu: ", i + info->chunk_index * 8);
		for (size_t j = 0; j < 8; j++) {
			printf("0x%x ", context->buffer[i * 8 + j]);
		}
		printf("\n");
	}
	printf("\n");
	info->chunk_index++;
}
