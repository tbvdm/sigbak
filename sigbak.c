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
#include <readpassphrase.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sbk.h"

int
write_files(char *path, const char *passphr, enum sbk_file_type type)
{
	struct sbk_ctx	*ctx;
	struct sbk_file	*file;
	FILE		*fp;
	int		 fd, ret;

	if ((ctx = sbk_ctx_new()) == NULL)
		return 1;

	if (sbk_open(ctx, path, passphr) == -1) {
		sbk_ctx_free(ctx);
		return 1;
	}

	while ((file = sbk_get_file(ctx)) != NULL) {
		if (sbk_get_file_type(file) != type)
			continue;

		if ((fd = open(sbk_get_file_name(file), O_WRONLY | O_CREAT |
		    O_EXCL, 0666)) == -1) {
			warn("%s", sbk_get_file_name(file));
			goto error;
		}

		if ((fp = fdopen(fd, "wb")) == NULL) {
			warn("%s", sbk_get_file_name(file));
			close(fd);
			goto error;
		}

		if (sbk_write_file(ctx, file, fp) == -1) {
			fclose(fp);
			goto error;
		}

		fclose(fp);
		sbk_free_file(file);
	}

	ret = sbk_eof(ctx) ? 0 : 1;
	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return ret;

error:
	sbk_free_file(file);
	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return 1;
}

int
cmd_attachments(int argc, char **argv, const char *passphr)
{
	if (argc != 2)
		return 1;

	return write_files(argv[1], passphr, SBK_ATTACHMENT);
}

int
cmd_avatars(int argc, char **argv, const char *passphr)
{
	if (argc != 2)
		return 1;

	return write_files(argv[1], passphr, SBK_AVATAR);
}

int
cmd_dump(int argc, char **argv, const char *passphr)
{
	if (argc != 2)
		return 1;

	return (sbk_dump(argv[1], passphr) == 0) ? 0 : 1;
}

int
cmd_sqlite(int argc, char **argv, const char *passphr)
{
	int fd;

	if (argc != 3)
		return 1;

	/* Prevent SQLite from writing to an existing file */
	if ((fd = open(argv[2], O_RDONLY | O_CREAT | O_EXCL, 0666)) == -1) {
		warn("%s", argv[2]);
		return 1;
	}

	close(fd);
	return (sbk_sqlite(argv[1], passphr, argv[2]) == 0) ? 0 : 1;
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

	if (argc <= 2)
		return 1;

	if (readpassphrase("Enter 30-digit passphrase (spaces are ignored): ",
	    passphr, sizeof passphr, 0) == NULL)
		errx(1, "Cannot read passphrase");

	if (pledge("stdio rpath wpath cpath flock", NULL) == -1) {
		explicit_bzero(passphr, sizeof passphr);
		err(1, "pledge");
	}

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
	else
		ret = 1;

	explicit_bzero(passphr, sizeof passphr);
	return ret;
}
