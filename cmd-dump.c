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

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sigbak.h"

static void
dump_var(unsigned int ind, const char *name, const char *type, const char *fmt,
    ...)
{
	va_list ap;

	va_start(ap, fmt);
	while (ind-- > 0)
		putchar('\t');
	printf("%s (%s):", name, type);
	if (fmt != NULL) {
		putchar(' ');
		vprintf(fmt, ap);
	}
	putchar('\n');
	va_end(ap);
}

static void
dump_bool(unsigned int ind, const char *name, int val)
{
	dump_var(ind, name, "bool", "%d", val);
}

static void
dump_uint32(unsigned int ind, const char *name, uint32_t val)
{
	dump_var(ind, name, "uint32", "%" PRIu32, val);
}

static void
dump_uint64(unsigned int ind, const char *name, uint64_t val)
{
	dump_var(ind, name, "uint64", "%" PRIu64, val);
}

static void
dump_double(unsigned int ind, const char *name, double val)
{
	dump_var(ind, name, "double", "%g", val);
}

static void
dump_string(unsigned int ind, const char *name, const char *val)
{
	dump_var(ind, name, "string", "%s", val);
}

static void
dump_binary(unsigned int ind, const char *name, ProtobufCBinaryData *bin)
{
	char	*hex;
	size_t	 i;

	if (bin->len == SIZE_MAX) {
		warnx("Binary data too large");
		return;
	}

	if ((hex = reallocarray(NULL, bin->len + 1, 2)) == NULL) {
		warn(NULL);
		return;
	}

	for (i = 0; i < bin->len; i++)
		snprintf(hex + (i * 2), 3, "%02x", bin->data[i]);

	dump_var(ind, name, "bytes", "%s", hex);
	freezero(hex, (bin->len + 1) * 2);
}

static void
dump_attachment(unsigned int ind, const char *name, Signal__Attachment *att)
{
	dump_var(ind++, name, "Attachment", NULL);
	if (att->has_rowid)
		dump_uint64(ind, "rowId", att->rowid);
	if (att->has_attachmentid)
		dump_uint64(ind, "attachmentId", att->attachmentid);
	if (att->has_length)
		dump_uint32(ind, "length", att->length);
}

static void
dump_avatar(unsigned int ind, const char *name, Signal__Avatar *avt)
{
	dump_var(ind++, name, "Avatar", NULL);
	if (avt->name != NULL)
		dump_string(ind, "name", avt->name);
	if (avt->has_length)
		dump_uint32(ind, "length", avt->length);
	if (avt->recipientid != NULL)
		dump_string(ind, "recipientId", avt->recipientid);
}

static void
dump_header(unsigned int ind, const char *name, Signal__Header *hdr)
{
	dump_var(ind++, name, "Header", NULL);
	if (hdr->has_iv)
		dump_binary(ind, "iv", &hdr->iv);
	if (hdr->has_salt)
		dump_binary(ind, "salt", &hdr->salt);
}

static void
dump_preference(unsigned int ind, const char *name,
    Signal__SharedPreference *prf)
{
	dump_var(ind++, name, "SharedPreference", NULL);
	if (prf->file != NULL)
		dump_string(ind, "file", prf->file);
	if (prf->key != NULL)
		dump_string(ind, "key", prf->key);
	if (prf->value != NULL)
		dump_string(ind, "value", prf->value);
}

static void
dump_parameter(unsigned int ind, const char *name,
    Signal__SqlStatement__SqlParameter *par)
{
	dump_var(ind++, name, "SqlParameter", NULL);
	if (par->stringparamter != NULL)
		dump_string(ind, "stringParamter", par->stringparamter);
	if (par->has_integerparameter)
		dump_uint64(ind, "integerParameter", par->integerparameter);
	if (par->has_doubleparameter)
		dump_double(ind, "doubleParameter", par->doubleparameter);
	if (par->has_blobparameter)
		dump_binary(ind, "blobParameter", &par->blobparameter);
	if (par->has_nullparameter)
		dump_bool(ind, "nullparameter", par->nullparameter);
}

static void
dump_statement(unsigned int ind, const char *name, Signal__SqlStatement *stm)
{
	size_t i;

	dump_var(ind++, name, "SqlStatement", NULL);
	if (stm->statement != NULL)
		dump_string(ind, "statement", stm->statement);
	for (i = 0; i < stm->n_parameters; i++)
		dump_parameter(ind, "parameters", stm->parameters[i]);
}

static void
dump_sticker(unsigned int ind, const char *name, Signal__Sticker *stk)
{
	dump_var(ind++, name, "Sticker", NULL);
	if (stk->has_rowid)
		dump_uint64(ind, "rowId", stk->rowid);
	if (stk->has_length)
		dump_uint32(ind, "length", stk->length);
}

static void
dump_version(unsigned int ind, const char *name, Signal__DatabaseVersion *ver)
{
	dump_var(ind++, name, "DatabaseVersion", NULL);
	if (ver->has_version)
		dump_uint32(ind, "version", ver->version);
}

static void
dump_frame(Signal__BackupFrame *frm)
{
	dump_var(0, "frame", "BackupFrame", NULL);
	if (frm->header != NULL)
		dump_header(1, "header", frm->header);
	if (frm->statement != NULL)
		dump_statement(1, "statement", frm->statement);
	if (frm->preference != NULL)
		dump_preference(1, "preference", frm->preference);
	if (frm->attachment != NULL)
		dump_attachment(1, "attachment", frm->attachment);
	if (frm->version != NULL)
		dump_version(1, "version", frm->version);
	if (frm->has_end)
		dump_bool(1, "end", frm->end);
	if (frm->avatar != NULL)
		dump_avatar(1, "avatar", frm->avatar);
	if (frm->sticker != NULL)
		dump_sticker(1, "sticker", frm->sticker);
}

int
cmd_dump(int argc, char **argv)
{
	struct sbk_ctx		*ctx;
	Signal__BackupFrame	*frm;
	char			*passfile, passphr[128];
	int			 c, ret;

	passfile = NULL;

	while ((c = getopt(argc, argv, "p:")) != -1)
		switch (c) {
		case 'p':
			passfile = optarg;
			break;
		default:
			goto usage;
		}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		goto usage;

	if (unveil(argv[0], "r") == -1)
		err(1, "unveil");

	if (passfile == NULL) {
		if (pledge("stdio rpath tty", NULL) == -1)
			err(1, "pledge");
	} else {
		if (unveil(passfile, "r") == -1)
			err(1, "unveil");

		if (pledge("stdio rpath", NULL) == -1)
			err(1, "pledge");
	}

	if ((ctx = sbk_ctx_new()) == NULL)
		errx(1, "Cannot create backup context");

	if (get_passphrase(passfile, passphr, sizeof passphr) == -1) {
		sbk_ctx_free(ctx);
		return 1;
	}

	if (sbk_open(ctx, argv[0], passphr) == -1) {
		warnx("%s: %s", argv[0], sbk_error(ctx));
		explicit_bzero(passphr, sizeof passphr);
		sbk_ctx_free(ctx);
		return 1;
	}

	explicit_bzero(passphr, sizeof passphr);

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	while ((frm = sbk_get_frame(ctx, NULL)) != NULL) {
		dump_frame(frm);
		sbk_free_frame(frm);
	}

	if (sbk_eof(ctx))
		ret = 0;
	else {
		warnx("%s: %s", argv[0], sbk_error(ctx));
		ret = 1;
	}

	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return ret;

usage:
	usage("dump", "[-p passfile] backup");
}
