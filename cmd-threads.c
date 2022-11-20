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

#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sigbak.h"

static enum cmd_status cmd_threads(int, char **);

const struct cmd_entry cmd_threads_entry = {
	.name = "threads",
	.usage = "[-p passfile] backup",
	.exec = cmd_threads
};

enum cmd_status
cmd_threads(int argc, char **argv)
{
	struct sbk_ctx		*ctx;
	struct sbk_thread_list	*lst;
	struct sbk_thread	*thd;
	char			*passfile, passphr[128];
	int			 c;

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

	if (unveil(argv[0], "r") == -1)
		err(1, "unveil: %s", argv[0]);

	/* For SQLite */
	if (unveil("/dev/urandom", "r") == -1)
		err(1, "unveil: /dev/urandom");

	/* For SQLite */
	if (unveil("/tmp", "rwc") == -1)
		err(1, "unveil: /tmp");

	if (passfile == NULL) {
		if (pledge("stdio rpath tty", NULL) == -1)
			err(1, "pledge");
	} else {
		if (unveil(passfile, "r") == -1)
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

	if (sbk_open(ctx, argv[0], passphr) == -1) {
		explicit_bzero(passphr, sizeof passphr);
		sbk_ctx_free(ctx);
		return CMD_ERROR;
	}

	explicit_bzero(passphr, sizeof passphr);

	if (passfile == NULL && pledge("stdio rpath", NULL) == -1)
		err(1, "pledge");

	if ((lst = sbk_get_threads(ctx)) == NULL) {
		sbk_close(ctx);
		sbk_ctx_free(ctx);
		return CMD_ERROR;
	}

	SIMPLEQ_FOREACH(thd, lst, entries)
		printf("%4" PRIu64 ": %s\n", thd->id,
		    sbk_get_recipient_display_name(thd->recipient));

	sbk_free_thread_list(lst);
	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return CMD_OK;
}
