#ifndef FT_SSL_MD5_MD5_H
#define FT_SSL_MD5_MD5_H

#include <sys/types.h>

#define CHUNK_LEN			64
#define PADDING_MSG_LEN		8
#define PADDING_FIRST_BYTE	0x80

typedef struct {
	u_int32_t		state[4];
	unsigned char	buffer[64];
} md5_context_t;

typedef struct {
	unsigned char	*input;
	size_t			length;
	size_t			chunk_index;
	size_t			pad_chunk;
	size_t			end_chunk;
} md5_info_t;

char *md5(char *);

#endif
