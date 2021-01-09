/*
 * Copyright (c) 2020 Tim van der Molen <tim@kariliq.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef PROTOBUF_H
#define PROTOBUF_H

#include <stddef.h>
#include <stdint.h>

#define WIRETYPE_VARINT			0
#define WIRETYPE_64BIT			1
#define WIRETYPE_LENGTH_DELIM		2
#define WIRETYPE_32BIT			5

typedef struct ProtobufCAllocator	 ProtobufCAllocator;
typedef struct ProtobufCBinaryData	 ProtobufCBinaryData;
typedef int				 protobuf_c_boolean;

struct ProtobufCAllocator {
	void				*(*alloc)(void *, size_t);
	void				 (*free)(void *, void *);
	void				*allocator_data;
};

struct ProtobufCBinaryData {
	size_t				 len;
	uint8_t				*data;
};

struct tag {
	uint32_t			 fieldnum;
	uint8_t				 wiretype;
};

void	 binarydata_init(ProtobufCBinaryData *);

size_t	 tag_unpack(struct tag *, size_t, const uint8_t *);
size_t	 fieldlen_unpack(size_t *, size_t, const uint8_t *);
size_t	 bool_unpack(protobuf_c_boolean *, size_t, const uint8_t *);
size_t	 uint32_unpack(uint32_t *, size_t, const uint8_t *);
size_t	 uint64_unpack(uint64_t *, size_t, const uint8_t *);
size_t	 fixed64_unpack(uint64_t *, size_t, const uint8_t *);
size_t	 double_unpack(double *, size_t, const uint8_t *);
char	*string_unpack(ProtobufCAllocator *, size_t, const uint8_t *);
size_t	 binarydata_unpack(ProtobufCBinaryData *, ProtobufCAllocator *, size_t,
	    const uint8_t *);

#endif
