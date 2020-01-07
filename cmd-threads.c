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

#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include "sigbak.h"

int
cmd_threads(int argc, char **argv)
{
	struct sbk_ctx		*ctx;
	struct sbk_thread_list	*lst;
	struct sbk_thread	*thd;
	char			*name, *passfile, passphr[128];
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

	/* For SQLite */
	if (unveil("/dev/urandom", "r") == -1)
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

	if (passfile == NULL && pledge("stdio rpath", NULL) == -1)
		err(1, "pledge");

	ret = -1;

	if ((lst = sbk_get_threads(ctx)) == NULL) {
		warnx("%s", sbk_error(ctx));
		goto out;
	}

	SIMPLEQ_FOREACH(thd, lst, entries) {
		if (sbk_is_group(ctx, thd->recipient))
			ret = sbk_get_group(ctx, thd->recipient, &name);
		else
			ret = sbk_get_contact(ctx, thd->recipient, &name,
			    NULL);

		if (ret == -1) {
			warnx("%s", sbk_error(ctx));
			continue;
		}

		printf("%4" PRIu64 ": %s\n", thd->id, name);
		freezero_string(name);
	}

	sbk_free_thread_list(lst);
	ret = 0;

out:
	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return (ret == 0) ? 0 : 1;

usage:
	usage("threads", "[-p passfile] backup");
}
