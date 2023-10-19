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

#include <endian.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "sbk-internal.h"

void
sbk_free_frame(Signal__BackupFrame *frm)
{
	if (frm != NULL)
		signal__backup_frame__free_unpacked(frm, NULL);
}

static int
sbk_has_file_data(Signal__BackupFrame *frm)
{
	return frm->attachment != NULL || frm->avatar != NULL ||
	    frm->sticker != NULL;
}

static int
sbk_skip_file_data(struct sbk_ctx *ctx, Signal__BackupFrame *frm)
{
	uint32_t len;

	if (frm->attachment != NULL && frm->attachment->has_length)
		len = frm->attachment->length;
	else if (frm->avatar != NULL && frm->avatar->has_length)
		len = frm->avatar->length;
	else if (frm->sticker != NULL && frm->sticker->has_length)
		len = frm->sticker->length;
	else {
		warnx("Invalid frame");
		return -1;
	}

	if (fseeko(ctx->fp, len + SBK_MAC_LEN, SEEK_CUR) == -1) {
		warn("Cannot seek");
		return -1;
	}

	ctx->counter++;
	return 0;
}

static struct sbk_file *
sbk_get_file(struct sbk_ctx *ctx, Signal__BackupFrame *frm)
{
	struct sbk_file *file;

	if ((file = malloc(sizeof *file)) == NULL) {
		warn(NULL);
		return NULL;
	}

	if ((file->pos = ftello(ctx->fp)) == -1) {
		warn("Cannot get file position");
		goto error;
	}

	if (frm->attachment != NULL) {
		if (!frm->attachment->has_length) {
			warnx("Invalid attachment frame");
			goto error;
		}
		file->len = frm->attachment->length;
	} else if (frm->avatar != NULL) {
		if (!frm->avatar->has_length) {
			warnx("Invalid avatar frame");
			goto error;
		}
		file->len = frm->avatar->length;
	} else if (frm->sticker != NULL) {
		if (!frm->sticker->has_length) {
			warnx("Invalid sticker frame");
			goto error;
		}
		file->len = frm->sticker->length;
	}

	file->counter = ctx->counter;
	return file;

error:
	sbk_free_file(file);
	return NULL;
}

static Signal__BackupFrame *
sbk_unpack_frame(unsigned char *buf, size_t len)
{
	Signal__BackupFrame *frm;

	if ((frm = signal__backup_frame__unpack(NULL, len, buf)) == NULL)
		warnx("Cannot unpack frame");

	return frm;
}

Signal__BackupFrame *
sbk_get_first_frame(struct sbk_ctx *ctx)
{
	Signal__BackupFrame	*frm;
	uint32_t		 len;

	if (sbk_read(ctx, &len, sizeof len) == -1)
		return NULL;

	len = be32toh(len);

	if (len == 0) {
		warnx("Invalid frame length");
		return NULL;
	}

	if (sbk_grow_buffers(ctx, len) == -1)
		return NULL;

	if (sbk_read(ctx, ctx->ibuf, len) == -1)
		return NULL;

	if ((frm = sbk_unpack_frame(ctx->ibuf, len)) == NULL)
		return NULL;

	return frm;
}

static Signal__BackupFrame *
sbk_get_encrypted_frame(struct sbk_ctx *ctx, struct sbk_file **file)
{
	Signal__BackupFrame	*frm;
	unsigned char		*mac;
	uint32_t		 elen;	/* Length of encrypted frame */
	size_t			 dlen;	/* Length of decrypted data */

	if (sbk_decrypt_init(ctx, ctx->counter++) == -1)
		return NULL;

	/*
	 * Get the length of the encrypted frame. In newer backups, the frame
	 * length itself is encrypted, too.
	 */
	if (ctx->backup_version == 0) {
		if (sbk_read(ctx, &elen, sizeof elen) == -1)
			return NULL;
	} else {
		if (sbk_read(ctx, ctx->ibuf, sizeof elen) == -1)
			return NULL;
		if (sbk_decrypt_update(ctx, sizeof elen, &dlen) == -1)
			return NULL;
		if (dlen != sizeof elen) {
			warnx("Cannot read frame length");
			return NULL;
		}
		memcpy(&elen, ctx->obuf, sizeof elen);
	}

	elen = be32toh(elen);

	if (elen <= SBK_MAC_LEN) {
		warnx("Invalid frame length");
		return NULL;
	}

	if (sbk_grow_buffers(ctx, elen) == -1)
		return NULL;

	if (sbk_read(ctx, ctx->ibuf, elen) == -1)
		return NULL;

	elen -= SBK_MAC_LEN;
	mac = ctx->ibuf + elen;

	if (sbk_decrypt_update(ctx, elen, &dlen) == -1)
		return NULL;

	if (sbk_decrypt_final(ctx, &dlen, mac) == -1)
		return NULL;

	if ((frm = sbk_unpack_frame(ctx->obuf, dlen)) == NULL)
		return NULL;

	if (sbk_has_file_data(frm)) {
		if (file == NULL) {
			if (sbk_skip_file_data(ctx, frm) == -1) {
				sbk_free_frame(frm);
				return NULL;
			}
		} else {
			if ((*file = sbk_get_file(ctx, frm)) == NULL) {
				sbk_free_frame(frm);
				return NULL;
			}
			if (sbk_skip_file_data(ctx, frm) == -1) {
				sbk_free_frame(frm);
				sbk_free_file(*file);
				return NULL;
			}
		}
	}

	return frm;
}

Signal__BackupFrame *
sbk_get_frame(struct sbk_ctx *ctx, struct sbk_file **file)
{
	Signal__BackupFrame *frm;

	if (file != NULL)
		*file = NULL;

	switch (ctx->state) {
	case SBK_FIRST_FRAME:
		frm = sbk_get_first_frame(ctx);
		ctx->state = SBK_OTHER_FRAME;
		return frm;
	case SBK_OTHER_FRAME:
		if ((frm = sbk_get_encrypted_frame(ctx, file)) == NULL)
			return NULL;
		if (frm->has_end)
			ctx->state = SBK_LAST_FRAME;
		return frm;
	case SBK_LAST_FRAME:
	default:
		return NULL;
	}
}

int
sbk_rewind(struct sbk_ctx *ctx)
{
	if (fseeko(ctx->fp, 0, SEEK_SET) == -1) {
		warn("Cannot seek");
		return -1;
	}

	clearerr(ctx->fp);
	ctx->counter = ctx->counter_start;
	ctx->state = SBK_FIRST_FRAME;
	return 0;
}

int
sbk_eof(struct sbk_ctx *ctx)
{
	return ctx->state == SBK_LAST_FRAME;
}
