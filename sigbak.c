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
#include <string.h>
#include <unistd.h>

#include "sbk.h"

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

	if (pledge("stdio rpath wpath cpath flock", NULL) == -1)
		err(1, "pledge");

	remove_spaces(passphr);

	argc--;
	argv++;

	if (strcmp(argv[0], "dump") == 0)
		ret = cmd_dump(argc, argv, passphr);
	else if (strcmp(argv[0], "sqlite") == 0)
		ret = cmd_sqlite(argc, argv, passphr);
	else
		ret = 1;

	explicit_bzero(passphr, sizeof passphr);
	return ret;
}
