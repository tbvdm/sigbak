/*	$OpenBSD: bs_cbb.c,v 1.4 2022/07/07 17:16:05 tb Exp $	*/
/*
 * Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "../config.h"

#ifndef HAVE_HKDF

#include <stdlib.h>
#include <string.h>

#include "bytestring.h"

static int
cbb_init(CBB *cbb, uint8_t *buf, size_t cap)
{
	struct cbb_buffer_st *base;

	if ((base = calloc(1, sizeof(struct cbb_buffer_st))) == NULL)
		return 0;

	base->buf = buf;
	base->len = 0;
	base->cap = cap;
	cbb->base = base;
	return 1;
}

int
CBB_init_fixed(CBB *cbb, uint8_t *buf, size_t len)
{
	if (!cbb_init(cbb, buf, len))
		return 0;

	return 1;
}

void
CBB_cleanup(CBB *cbb)
{
	free(cbb->base);
}

static int
cbb_buffer_add(struct cbb_buffer_st *base, uint8_t **out, size_t len)
{
	size_t newlen;

	newlen = base->len + len;
	if (newlen < base->len)
		/* Overflow */
		return 0;

	if (newlen > base->cap) {
		return 0;
	}

	if (out)
		*out = base->buf + base->len;

	base->len = newlen;
	return 1;
}

int
CBB_add_bytes(CBB *cbb, const uint8_t *data, size_t len)
{
	uint8_t *dest;

	if (!cbb_buffer_add(cbb->base, &dest, len))
		return 0;

	memcpy(dest, data, len);
	return 1;
}

#endif
