/*
 * Copyright (c) 2019 Tim van der Molen <tim@kariliq.nl>
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

#include <string.h>
#include <unistd.h>

#include "sigbak.h"

static enum cmd_status cmd_check_backup(int, char **);

const struct cmd_entry cmd_check_backup_entry = {
	.name = "check-backup",
	.alias = "check",
	.usage = "[-p passfile] backup",
	.exec = cmd_check_backup
};

static enum cmd_status
cmd_check_backup(int argc, char **argv)
{
	struct sbk_ctx		*ctx;
	struct sbk_file		*file;
	Signal__BackupFrame	*frm;
	char			*backup, *passfile, passphr[128];
	unsigned long long	 n;
	int			 c, ret;

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

	if (argc != 1)
		return CMD_USAGE;

	backup = argv[0];

	if (unveil(backup, "r") == -1)
		err(1, "unveil: %s", backup);

	if (passfile == NULL) {
		if (pledge("stdio rpath tty", NULL) == -1)
			err(1, "pledge");
	} else {
		if (strcmp(passfile, "-") != 0 && unveil(passfile, "r") == -1)
			err(1, "unveil: %s", passfile);

		if (pledge("stdio rpath", NULL) == -1)
			err(1, "pledge");
	}

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

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	ret = 0;
	n = 1;

	while ((frm = sbk_get_frame(ctx, &file)) != NULL) {
		sbk_free_frame(frm);
		if (file != NULL) {
			ret = sbk_write_file(ctx, file, NULL);
			sbk_free_file(file);
			if (ret == -1)
				break;
		}
		n++;
	}

	if (!sbk_eof(ctx) || ret == -1) {
		warnx("Error in frame %llu", n);
		ret = -1;
	}

	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return (ret == -1) ? CMD_ERROR : CMD_OK;
}
