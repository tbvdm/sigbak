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

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "sigbak.h"

int
cmd_sqlite(int argc, char **argv)
{
	struct sbk_ctx	*ctx;
	char		*passfile, passphr[128];
	int		 c, fd, ret;

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

	if (argc != 2)
		goto usage;

	if (unveil(argv[0], "r") == -1)
		err(1, "unveil");

	if (unveil(argv[1], "rwc") == -1)
		err(1, "unveil");

	/* SQLite creates temporary files in the same dir as the database */
	if (unveil_dirname(argv[1], "rwc") == -1)
		return 1;

	/* For SQLite */
	if (unveil("/dev/urandom", "r") == -1)
		err(1, "unveil");

	if (passfile == NULL) {
		if (pledge("stdio rpath wpath cpath flock tty", NULL) == -1)
			err(1, "pledge");
	} else {
		if (unveil(passfile, "r") == -1)
			err(1, "unveil");

		if (pledge("stdio rpath wpath cpath flock", NULL) == -1)
			err(1, "pledge");
	}

	/* Prevent SQLite from writing to an existing file */
	if ((fd = open(argv[1], O_RDONLY | O_CREAT | O_EXCL, 0666)) == -1)
		err(1, "%s", argv[1]);

	close(fd);

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

	if (passfile == NULL &&
	    pledge("stdio rpath wpath cpath flock", NULL) == -1)
		err(1, "pledge");

	if ((ret = sbk_write_database(ctx, argv[1])) == -1)
		warnx("%s", sbk_error(ctx));

	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return (ret == 0) ? 0 : 1;

usage:
	usage("sqlite", "[-p passfile] backup database");
}
