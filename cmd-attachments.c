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

#include <sys/stat.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sigbak.h"

static char *
get_filename(struct sbk_attachment *att)
{
	char		*fname;
	const char	*ext;

	if (att->content_type == NULL)
		ext = NULL;
	else
		ext = mime_get_extension(att->content_type);

	if (asprintf(&fname, "%" PRId64 "-%" PRId64 "%s%s",
	    att->rowid,
	    att->attachmentid,
	    (ext != NULL) ? "." : "",
	    (ext != NULL) ? ext : "") == -1) {
		warnx("asprintf() failed");
		fname = NULL;
	}

	return fname;
}

static int
write_attachments(struct sbk_ctx *ctx, struct sbk_attachment_list *lst)
{
	struct sbk_attachment	*att;
	FILE			*fp;
	char			*fname;
	int			 ret;

	ret = 0;

	TAILQ_FOREACH(att, lst, entries) {
		if (att->file == NULL)
			continue;

		if ((fname = get_filename(att)) == NULL) {
			ret = 1;
			continue;
		}

		if ((fp = fopen(fname, "wx")) == NULL) {
			warn("%s", fname);
			ret = 1;
		} else {
			if (sbk_write_file(ctx, att->file, fp) == -1) {
				warnx("%s: %s", fname, sbk_error(ctx));
				ret = 1;
			}
			fclose(fp);
		}

		free(fname);
	}

	return ret;
}

int
cmd_attachments(int argc, char **argv)
{
	struct sbk_ctx			*ctx;
	struct sbk_attachment_list	*lst;
	char				*passfile, passphr[128];
	const char			*errstr, *outdir;
	int				 c, ret, thread;

	passfile = NULL;
	thread = -1;

	while ((c = getopt(argc, argv, "p:t:")) != -1)
		switch (c) {
		case 'p':
			passfile = optarg;
			break;
		case 't':
			thread = strtonum(optarg, 1, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "%s: thread id is %s", optarg, errstr);
			break;
		default:
			goto usage;
		}

	argc -= optind;
	argv += optind;

	switch (argc) {
	case 1:
		outdir = ".";
		break;
	case 2:
		outdir = argv[1];
		if (mkdir(outdir, 0777) == -1 && errno != EEXIST)
			err(1, "mkdir: %s", outdir);
		break;
	default:
		goto usage;
	}

	if (unveil(argv[0], "r") == -1)
		err(1, "unveil: %s", argv[0]);

	if (unveil(outdir, "rwc") == -1)
		err(1, "unveil: %s", outdir);

	/* For SQLite */
	if (unveil("/dev/urandom", "r") == -1)
		err(1, "unveil: /dev/urandom");

	/* For SQLite */
	if (unveil("/tmp", "rwc") == -1)
		err(1, "unveil: /tmp");

	if (passfile == NULL) {
		if (pledge("stdio rpath wpath cpath tty", NULL) == -1)
			err(1, "pledge");
	} else {
		if (unveil(passfile, "r") == -1)
			err(1, "unveil: %s", passfile);

		if (pledge("stdio rpath wpath cpath", NULL) == -1)
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

	if (chdir(outdir) == -1) {
		warn("chdir: %s", outdir);
		sbk_close(ctx);
		sbk_ctx_free(ctx);
		return 1;
	}

	if (passfile == NULL && pledge("stdio rpath wpath cpath", NULL) == -1)
		err(1, "pledge");

	if (thread == -1)
		lst = sbk_get_all_attachments(ctx);
	else
		lst = sbk_get_attachments_for_thread(ctx, thread);

	if (lst == NULL) {
		warnx("%s", sbk_error(ctx));
		ret = 1;
	} else {
		ret = write_attachments(ctx, lst);
		sbk_free_attachment_list(lst);
	}

	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return ret;

usage:
	usage("attachments", "[-p passfile] [-t thread] backup [directory]");
}
