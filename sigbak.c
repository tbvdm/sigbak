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
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <readpassphrase.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sbk.h"

void
usage(const char *args)
{
	fprintf(stderr, "usage: %s %s\n", getprogname(), args);
}

void
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

void
dump_bool(unsigned int ind, const char *name, int val)
{
	dump_var(ind, name, "bool", "%d", val);
}

void
dump_uint32(unsigned int ind, const char *name, uint32_t val)
{
	dump_var(ind, name, "uint32", "%" PRIu32, val);
}

void
dump_uint64(unsigned int ind, const char *name, uint64_t val)
{
	dump_var(ind, name, "uint64", "%" PRIu64, val);
}

void
dump_double(unsigned int ind, const char *name, double val)
{
	dump_var(ind, name, "string", "%g", val);
}

void
dump_string(unsigned int ind, const char *name, const char *val)
{
	dump_var(ind, name, "string", "%s", val);
}

void
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

void
dump_attachment(unsigned int ind, const char *name, Signal__Attachment *att)
{
	dump_var(ind, name, "Attachment", NULL);
	if (att->has_rowid)
		dump_uint64(ind + 1, "rowId", att->rowid);
	if (att->has_attachmentid)
		dump_uint64(ind + 1, "attachmentId", att->attachmentid);
	if (att->has_length)
		dump_uint32(ind + 1, "length", att->length);
}

void
dump_avatar(unsigned int ind, const char *name, Signal__Avatar *avt)
{
	dump_var(ind, name, "Avatar", NULL, NULL);
	if (avt->name != NULL)
		dump_string(ind + 1, "name", avt->name);
	if (avt->has_length)
		dump_uint32(ind + 1, "length", avt->length);
}

void
dump_header(unsigned int ind, const char *name, Signal__Header *hdr)
{
	dump_var(ind, name, "Header", NULL);
	if (hdr->has_iv)
		dump_binary(ind + 1, "iv", &hdr->iv);
	if (hdr->has_salt)
		dump_binary(ind + 1, "salt", &hdr->salt);
}

void
dump_preference(unsigned int ind, const char *name,
    Signal__SharedPreference *prf)
{
	dump_var(ind, name, "SharedPreference", NULL, NULL);
	if (prf->file != NULL)
		dump_string(ind + 1, "file", prf->file);
	if (prf->key != NULL)
		dump_string(ind + 1, "key", prf->key);
	if (prf->value != NULL)
		dump_string(ind + 1, "value", prf->value);
}

void
dump_parameter(unsigned int ind, const char *name,
    Signal__SqlStatement__SqlParameter *par)
{
	dump_var(ind, name, "SqlParameter", NULL);
	if (par->stringparamter != NULL)
		dump_string(ind + 1, "stringParamter", par->stringparamter);
	if (par->has_integerparameter)
		dump_uint64(ind + 1, "integerParameter",
		    par->integerparameter);
	if (par->has_doubleparameter)
		dump_double(ind + 1, "doubleParameter", par->doubleparameter);
	if (par->has_blobparameter)
		dump_binary(ind + 1, "blobParameter", &par->blobparameter);
	if (par->has_nullparameter)
		dump_bool(ind + 1, "nullparameter", par->nullparameter);
}

void
dump_statement(unsigned int ind, const char *name, Signal__SqlStatement *stm)
{
	size_t i;

	dump_var(ind, name, "SqlStatement", NULL);
	if (stm->statement != NULL)
		dump_string(ind + 1, "string", stm->statement);
	for (i = 0; i < stm->n_parameters; i++)
		dump_parameter(ind + 1, "parameters", stm->parameters[i]);
}

void
dump_sticker(unsigned int ind, const char *name, Signal__Sticker *stk)
{
	dump_var(ind, name, "Sticker", NULL);
	if (stk->has_rowid)
		dump_uint64(ind + 1, "rowId", stk->rowid);
	if (stk->has_length)
		dump_uint32(ind + 1, "length", stk->length);
}

void
dump_version(unsigned int ind, const char *name, Signal__DatabaseVersion *ver)
{
	dump_var(ind, name, "DatabaseVersion", NULL);
	if (ver->has_version)
		dump_uint32(ind + 1, "version", ver->version);
}

void
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
write_files(char *path, const char *passphr, enum sbk_file_type type)
{
	struct sbk_ctx	*ctx;
	struct sbk_file	*file;
	FILE		*fp;
	int		 fd, ret;

	if (unveil(path, "r") == -1 || unveil(".", "wc") == -1) {
		warn("unveil");
		return 1;
	}

	if (pledge("stdio rpath wpath cpath", NULL) == -1) {
		warn("pledge");
		return 1;
	}

	if ((ctx = sbk_ctx_new()) == NULL) {
		warnx("Cannot create backup context");
		return 1;
	}

	if (sbk_open(ctx, path, passphr) == -1) {
		warnx("%s: %s", path, sbk_error(ctx));
		sbk_ctx_free(ctx);
		return 1;
	}

	ret = 1;

	while ((file = sbk_get_file(ctx)) != NULL) {
		if (sbk_get_file_type(file) != type)
			continue;

		if ((fd = open(sbk_get_file_name(file), O_WRONLY | O_CREAT |
		    O_EXCL, 0666)) == -1) {
			warn("%s", sbk_get_file_name(file));
			goto out;
		}

		if ((fp = fdopen(fd, "wb")) == NULL) {
			warn("%s", sbk_get_file_name(file));
			close(fd);
			goto out;
		}

		if (sbk_write_file(ctx, file, fp) == -1) {
			warnx("%s: %s", sbk_get_file_name(file),
			    sbk_error(ctx));
			fclose(fp);
			goto out;
		}

		fclose(fp);
		sbk_free_file(file);
	}

	if (!sbk_eof(ctx)) {
		warnx("%s: %s", path, sbk_error(ctx));
		goto out;
	}

	ret = 0;

out:
	sbk_free_file(file);
	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return ret;
}

int
cmd_attachments(int argc, char **argv, const char *passphr)
{
	if (argc != 2) {
		usage("attachments backup-file");
		return 1;
	}

	return write_files(argv[1], passphr, SBK_ATTACHMENT);
}

int
cmd_avatars(int argc, char **argv, const char *passphr)
{
	if (argc != 2) {
		usage("avatars backup-file");
		return 1;
	}

	return write_files(argv[1], passphr, SBK_AVATAR);
}

int
cmd_dump(int argc, char **argv, const char *passphr)
{
	struct sbk_ctx		*ctx;
	Signal__BackupFrame	*frm;
	int			 ret;

	if (argc != 2) {
		usage("dump backup-file");
		return 1;
	}

	if (unveil(argv[1], "r") == -1) {
		warn("unveil");
		return 1;
	}

	if (pledge("stdio rpath", NULL) == -1) {
		warn("pledge");
		return 1;
	}

	if ((ctx = sbk_ctx_new()) == NULL) {
		warnx("Cannot create backup context");
		return 1;
	}

	if (sbk_open(ctx, argv[1], passphr) == -1) {
		warnx("%s: %s", argv[1], sbk_error(ctx));
		sbk_ctx_free(ctx);
		return 1;
	}

	ret = 1;

	while ((frm = sbk_get_frame(ctx)) != NULL) {
		dump_frame(frm);

		if (sbk_has_file_data(frm) &&
		    sbk_skip_file_data(ctx, frm) == -1) {
			warnx("%s: %s", argv[1], sbk_error(ctx));
			goto out;
		}

		sbk_free_frame(frm);
	}

	if (!sbk_eof(ctx)) {
		warnx("%s: %s", argv[1], sbk_error(ctx));
		goto out;
	}

	ret = 0;

out:
	sbk_free_frame(frm);
	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return ret;
}

int
cmd_sqlite(int argc, char **argv, const char *passphr)
{
	struct sbk_ctx	*ctx;
	char		*dbdir, *dbpath;
	int		 fd, ret;

	if (argc != 3) {
		usage("sqlite backup-file database-file");
		return 1;
	}

	if (unveil(argv[1], "r") == -1) {
		warn("unveil");
		return 1;
	}

	if (unveil(argv[2], "rwc") == -1) {
		warn("unveil");
		return 1;
	}

	/* For SQLite */
	if (unveil("/dev/urandom", "r") == -1) {
		warn("unveil");
		return 1;
	}

	if ((dbpath = strdup(argv[2])) == NULL) {
		warn(NULL);
		return 1;
	}

	if ((dbdir = dirname(dbpath)) == NULL) {
		warn("dirname");
		free(dbpath);
		return 1;
	}

	/* SQLite creates temporary files in the same dir as the database */
	if (unveil(dbdir, "rwc") == -1) {
		warn("unveil");
		free(dbpath);
		return 1;
	}

	free(dbpath);

	if (pledge("stdio rpath wpath cpath flock", NULL) == -1) {
		warn("pledge");
		return 1;
	}

	/* Prevent SQLite from writing to an existing file */
	if ((fd = open(argv[2], O_RDONLY | O_CREAT | O_EXCL, 0666)) == -1) {
		warn("%s", argv[2]);
		return 1;
	}

	close(fd);

	if ((ctx = sbk_ctx_new()) == NULL) {
		warnx("Cannot create backup context");
		return 1;
	}

	if (sbk_open(ctx, argv[1], passphr) == -1) {
		warnx("%s: %s", argv[1], sbk_error(ctx));
		sbk_ctx_free(ctx);
		return 1;
	}

	if ((ret = sbk_write_database(ctx, argv[2])) == -1)
		warnx("%s", sbk_error(ctx));

	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return (ret == 0) ? 0 : 1;
}

void
remove_spaces(char *s)
{
	char *t;

	for (t = s; *s != '\0'; s++)
		if (*s != ' ')
			*t++ = *s;
	*t = '\0';
}

int
main(int argc, char **argv)
{
	char	passphr[128];
	int	ret;

	if (argc < 2) {
		usage("command [argument ...]");
		return 1;
	}

	if (readpassphrase("Enter 30-digit passphrase (spaces are ignored): ",
	    passphr, sizeof passphr, 0) == NULL)
		errx(1, "Cannot read passphrase");

	remove_spaces(passphr);

	argc--;
	argv++;

	if (strcmp(argv[0], "attachments") == 0)
		ret = cmd_attachments(argc, argv, passphr);
	else if (strcmp(argv[0], "avatars") == 0)
		ret = cmd_avatars(argc, argv, passphr);
	else if (strcmp(argv[0], "dump") == 0)
		ret = cmd_dump(argc, argv, passphr);
	else if (strcmp(argv[0], "sqlite") == 0)
		ret = cmd_sqlite(argc, argv, passphr);
	else {
		warnx("%s: Invalid command", argv[0]);
		ret = 1;
	}

	explicit_bzero(passphr, sizeof passphr);
	return ret;
}
