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

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "sbk-internal.h"

void
sbk_free_file(struct sbk_file *file)
{
	free(file);
}

int
sbk_write_file(struct sbk_ctx *ctx, struct sbk_file *file, FILE *fp)
{
	size_t		ibuflen, len, obuflen;
	unsigned char	mac[SBK_MAC_LEN];

	if (sbk_grow_buffers(ctx, BUFSIZ) == -1)
		return -1;

	if (fseeko(ctx->fp, file->pos, SEEK_SET) == -1) {
		warn("Cannot seek");
		return -1;
	}

	if (sbk_decrypt_init(ctx, file->counter) == -1)
		return -1;

#ifdef HAVE_EVP_MAC
	if (!EVP_MAC_update(ctx->mac_ctx, ctx->iv, SBK_IV_LEN)) {
		warnx("Cannot compute MAC");
		return -1;
	}
#else
	if (!HMAC_Update(ctx->hmac_ctx, ctx->iv, SBK_IV_LEN)) {
		warnx("Cannot compute MAC");
		return -1;
	}
#endif

	for (len = file->len; len > 0; len -= ibuflen) {
		ibuflen = (len < BUFSIZ) ? len : BUFSIZ;

		if (sbk_read(ctx, ctx->ibuf, ibuflen) == -1)
			return -1;

		if (sbk_decrypt_update(ctx, ibuflen, &obuflen) == -1)
			return -1;

		if (fp != NULL && fwrite(ctx->obuf, obuflen, 1, fp) != 1) {
			warn("Cannot write file");
			return -1;
		}
	}

	if (sbk_read(ctx, mac, sizeof mac) == -1)
		return -1;

	obuflen = 0;

	if (sbk_decrypt_final(ctx, &obuflen, mac) == -1)
		return -1;

	if (obuflen > 0 && fp != NULL && fwrite(ctx->obuf, obuflen, 1, fp) !=
	    1) {
		warn("Cannot write file");
		return -1;
	}

	return 0;
}

static char *
sbk_decrypt_file_data(struct sbk_ctx *ctx, struct sbk_file *file,
    size_t *buflen, int terminate)
{
	size_t		 ibuflen, len, obuflen, obufsize;
	unsigned char	 mac[SBK_MAC_LEN];
	char		*obuf, *ptr;

	if (buflen != NULL)
		*buflen = 0;

	if (sbk_grow_buffers(ctx, BUFSIZ) == -1)
		return NULL;

	if (fseeko(ctx->fp, file->pos, SEEK_SET) == -1) {
		warn("Cannot seek");
		return NULL;
	}

	if (terminate)
		terminate = 1;

	if ((size_t)file->len > SIZE_MAX - EVP_MAX_BLOCK_LENGTH - terminate) {
		warnx("File too large");
		return NULL;
	}

	obufsize = file->len + EVP_MAX_BLOCK_LENGTH + terminate;

	if ((obuf = malloc(obufsize)) == NULL) {
		warn(NULL);
		return NULL;
	}

	if (sbk_decrypt_init(ctx, file->counter) == -1)
		goto error;

#ifdef HAVE_EVP_MAC
	if (!EVP_MAC_update(ctx->mac_ctx, ctx->iv, SBK_IV_LEN)) {
		warnx("Cannot compute MAC");
		goto error;
	}
#else
	if (!HMAC_Update(ctx->hmac_ctx, ctx->iv, SBK_IV_LEN)) {
		warnx("Cannot compute MAC");
		goto error;
	}
#endif

	ptr = obuf;

	for (len = file->len; len > 0; len -= ibuflen) {
		ibuflen = (len < BUFSIZ) ? len : BUFSIZ;

		if (sbk_read(ctx, ctx->ibuf, ibuflen) == -1)
			goto error;

		if (sbk_decrypt_update(ctx, ibuflen, &obuflen) == -1)
			goto error;

		memcpy(ptr, ctx->obuf, obuflen);
		ptr += obuflen;
	}

	if (sbk_read(ctx, mac, sizeof mac) == -1)
		goto error;

	obuflen = 0;

	if (sbk_decrypt_final(ctx, &obuflen, mac) == -1)
		goto error;

	if (obuflen > 0) {
		memcpy(ptr, ctx->obuf, obuflen);
		ptr += obuflen;
	}

	if (terminate)
		*ptr = '\0';

	if (buflen != NULL)
		*buflen = ptr - obuf;

	return obuf;

error:
	free(obuf);
	return NULL;
}

char *
sbk_get_file_data(struct sbk_ctx *ctx, struct sbk_file *file, size_t *len)
{
	return sbk_decrypt_file_data(ctx, file, len, 0);
}

char *
sbk_get_file_data_as_string(struct sbk_ctx *ctx, struct sbk_file *file)
{
	return sbk_decrypt_file_data(ctx, file, NULL, 1);
}
