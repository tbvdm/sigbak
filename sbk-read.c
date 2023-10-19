/*
 * Copyright (c) 2018 Tim van der Molen <tim@kariliq.nl>
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

#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "sbk-internal.h"

int
sbk_grow_buffers(struct sbk_ctx *ctx, size_t size)
{
	unsigned char *buf;

	if (size <= ctx->ibufsize)
		return 0;

	if (ctx->ibufsize <= (SIZE_MAX - EVP_MAX_BLOCK_LENGTH) / 2 &&
	    size <= ctx->ibufsize * 2)
		size = ctx->ibufsize * 2;
	else if (size > SIZE_MAX - EVP_MAX_BLOCK_LENGTH) {
		warnx("Buffer size too large");
		return -1;
	}

	if ((buf = realloc(ctx->ibuf, size)) == NULL) {
		warn(NULL);
		return -1;
	}
	ctx->ibuf = buf;
	ctx->ibufsize = size;

	size += EVP_MAX_BLOCK_LENGTH;

	if ((buf = realloc(ctx->obuf, size)) == NULL) {
		warn(NULL);
		return -1;
	}
	ctx->obuf = buf;
	ctx->obufsize = size;

	return 0;
}

int
sbk_decrypt_init(struct sbk_ctx *ctx, uint32_t counter)
{
	if (!HMAC_Init_ex(ctx->hmac_ctx, NULL, 0, NULL, NULL)) {
		warnx("Cannot initialise MAC context");
		return -1;
	}

	ctx->iv[0] = counter >> 24;
	ctx->iv[1] = counter >> 16;
	ctx->iv[2] = counter >> 8;
	ctx->iv[3] = counter;

	if (!EVP_DecryptInit_ex(ctx->cipher_ctx, NULL, NULL, ctx->cipher_key,
	    ctx->iv)) {
		warnx("Cannot initialise cipher context");
		return -1;
	}

	return 0;
}

int
sbk_decrypt_update(struct sbk_ctx *ctx, size_t ibuflen, size_t *obuflen)
{
	int len;

	if (!HMAC_Update(ctx->hmac_ctx, ctx->ibuf, ibuflen)) {
		warnx("Cannot compute MAC");
		return -1;
	}

	if (!EVP_DecryptUpdate(ctx->cipher_ctx, ctx->obuf, &len, ctx->ibuf,
	    ibuflen)) {
		warnx("Cannot decrypt data");
		return -1;
	}

	*obuflen = len;
	return 0;
}

int
sbk_decrypt_final(struct sbk_ctx *ctx, size_t *obuflen,
    const unsigned char *theirmac)
{
	unsigned char	ourmac[EVP_MAX_MD_SIZE];
	unsigned int	ourmaclen;
	int		len;

	if (!HMAC_Final(ctx->hmac_ctx, ourmac, &ourmaclen)) {
		warnx("Cannot compute MAC");
		return -1;
	}

	if (memcmp(ourmac, theirmac, SBK_MAC_LEN) != 0) {
		warnx("MAC mismatch");
		return -1;
	}

	if (!EVP_DecryptFinal_ex(ctx->cipher_ctx, ctx->obuf + *obuflen,
	    &len)) {
		warnx("Cannot decrypt data");
		return -1;
	}

	*obuflen += len;
	return 0;
}

int
sbk_read(struct sbk_ctx *ctx, void *ptr, size_t size)
{
	if (fread(ptr, size, 1, ctx->fp) != 1) {
		if (ferror(ctx->fp))
			warn(NULL);
		else
			warnx("Unexpected end of file");
		return -1;
	}

	return 0;
}
