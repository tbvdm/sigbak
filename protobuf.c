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

#include <stdlib.h>
#include <string.h>

#include "protobuf.h"

#define VARINT_CONTINUE_BIT	0x80
#define VARINT_VALUE_MASK	0x7f

#define TAG_FIELDNUM_SHIFT	3
#define TAG_WIRETYPE_MASK	0x7

void
binarydata_init(ProtobufCBinaryData *bin)
{
	bin->len = 0;
	bin->data = NULL;
}

static size_t
varint_unpack(uint64_t *varint, size_t buflen, const uint8_t *buf)
{
	size_t i;

	*varint = 0;

	for (i = 0; i < buflen && i * 7 < 64; i++) {
		*varint |= (uint64_t)(buf[i] & VARINT_VALUE_MASK) << (i * 7);

		if ((buf[i] & VARINT_CONTINUE_BIT) == 0)
			return i + 1;
	}

	return 0;
}

size_t
tag_unpack(struct tag *tag, size_t buflen, const uint8_t *buf)
{
	uint64_t	varint;
	size_t		n;

	n = varint_unpack(&varint, buflen, buf);
	if (n == 0 || varint > UINT32_MAX)
		return 0;

	tag->fieldnum = varint >> TAG_FIELDNUM_SHIFT;
	tag->wiretype = varint & TAG_WIRETYPE_MASK;
	return n;
}

size_t
fieldlen_unpack(size_t *fieldlen, size_t buflen, const uint8_t *buf)
{
	uint64_t	varint;
	size_t		n;

	n = varint_unpack(&varint, buflen, buf);
	if (n == 0 || varint > buflen - n)
		return 0;

	*fieldlen = varint;
	return n;
}

size_t
bool_unpack(protobuf_c_boolean *val, size_t buflen, const uint8_t *buf)
{
	uint64_t	varint;
	size_t		n;

	n = varint_unpack(&varint, buflen, buf);
	if (n == 0)
		return 0;

	*val = varint != 0;
	return n;
}

size_t
uint32_unpack(uint32_t *val, size_t buflen, const uint8_t *buf)
{
	uint64_t	varint;
	size_t		n;

	n = varint_unpack(&varint, buflen, buf);
	if (n == 0 || varint > UINT32_MAX)
		return 0;

	*val = varint;
	return n;
}

size_t
uint64_unpack(uint64_t *val, size_t buflen, const uint8_t *buf)
{
	return varint_unpack(val, buflen, buf);
}

size_t
fixed64_unpack(uint64_t *fixed64, size_t buflen, const uint8_t *buf)
{
	if (buflen < sizeof *fixed64)
		return 0;

	*fixed64 =
	    (uint64_t)buf[0]       | (uint64_t)buf[1] <<  8 |
	    (uint64_t)buf[2] << 16 | (uint64_t)buf[3] << 24 |
	    (uint64_t)buf[4] << 32 | (uint64_t)buf[5] << 40 |
	    (uint64_t)buf[6] << 48 | (uint64_t)buf[7] << 56;

	return sizeof *fixed64;
}

size_t
double_unpack(double *val, size_t buflen, const uint8_t *buf)
{
	uint64_t	fixed64;
	size_t		n;

	n = fixed64_unpack(&fixed64, buflen, buf);
	if (n == 0)
		return 0;

	*val = *(double *)&fixed64;
	return sizeof fixed64;
}

char *
string_unpack(__unused ProtobufCAllocator *alloc, size_t buflen,
    const uint8_t *buf)
{
	char *str;

	if (buflen == SIZE_MAX)
		return NULL;

	str = malloc(buflen + 1);
	if (str == NULL)
		return NULL;

	memcpy(str, buf, buflen);
	str[buflen] = '\0';
	return str;
}

size_t
binarydata_unpack(ProtobufCBinaryData *bin, __unused ProtobufCAllocator *alloc,
    size_t buflen, const uint8_t *buf)
{
	if (buflen == 0)
		bin->data = NULL;
	else {
		bin->data = malloc(buflen);
		if (bin->data == NULL)
			return 0;
		memcpy(bin->data, buf, buflen);
	}

	bin->len = buflen;
	return buflen;
}
