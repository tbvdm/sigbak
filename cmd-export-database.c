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
#include <string.h>
#include <unistd.h>

#include "sigbak.h"

static enum cmd_status cmd_export_database(int, char **);

const struct cmd_entry cmd_export_database_entry = {
	.name = "export-database",
	.alias = "db",
	.usage = "[-p passfile] backup database",
	.exec = cmd_export_database
};

static enum cmd_status
cmd_export_database(int argc, char **argv)
{
	struct sbk_ctx	*ctx;
	char		*backup, *db, *passfile, passphr[128];
	int		 c, fd, ret;

	passfile = NULL;

	while ((c = getopt(argc, argv, "p:")) != -1)
		switch (c) {
		case 'p':
			passfile = optarg;
			break;
		default:
			return CMD_USAGE;
		}

	argc -= optind;
	argv += optind;

	if (argc != 2)
		return CMD_USAGE;

	backup = argv[0];
	db = argv[1];

	if (unveil(backup, "r") == -1)
		err(1, "unveil: %s", backup);

	/* For the export database and its temporary files */
	if (unveil_dirname(db, "rwc") == -1)
		return CMD_ERROR;

	/* For SQLite */
	if (unveil("/dev/urandom", "r") == -1)
		err(1, "unveil: /dev/urandom");

	/* For SQLite */
	if (unveil("/tmp", "rwc") == -1)
		err(1, "unveil: /tmp");

	if (passfile == NULL) {
		if (pledge("stdio rpath wpath cpath flock tty", NULL) == -1)
			err(1, "pledge");
	} else {
		if (strcmp(passfile, "-") != 0 && unveil(passfile, "r") == -1)
			err(1, "unveil: %s", passfile);

		if (pledge("stdio rpath wpath cpath flock", NULL) == -1)
			err(1, "pledge");
	}

	/* Prevent SQLite from writing to an existing file */
	if ((fd = open(db, O_RDONLY | O_CREAT | O_EXCL, 0666)) == -1) {
		warn("%s", db);
		return CMD_ERROR;
	}

	close(fd);

	if ((ctx = sbk_ctx_new()) == NULL)
		return CMD_ERROR;

	if (get_passphrase(passfile, passphr, sizeof passphr) == -1) {
		sbk_ctx_free(ctx);
		return CMD_ERROR;
	}

	if (sbk_open(ctx, backup, passphr) == -1) {
		explicit_bzero(passphr, sizeof passphr);
		sbk_ctx_free(ctx);
		return CMD_ERROR;
	}

	explicit_bzero(passphr, sizeof passphr);

	if (passfile == NULL &&
	    pledge("stdio rpath wpath cpath flock", NULL) == -1)
		err(1, "pledge");

	ret = sbk_write_database(ctx, db);
	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return (ret == -1) ? CMD_ERROR : CMD_OK;
}
