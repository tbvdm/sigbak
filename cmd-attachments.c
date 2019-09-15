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

#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sbk.h"
#include "sigbak.h"

static int
write_files(int argc, char **argv, enum sbk_file_type type)
{
	struct sbk_ctx	*ctx;
	struct sbk_file	*file;
	FILE		*fp;
	char		*cmd, *passfile, passphr[128];
	const char	*outdir;
	int		 c, ret;

	cmd = argv[0];
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

	if (unveil(argv[0], "r") == -1 || unveil(outdir, "rwc") == -1)
		err(1, "unveil");

	if (passfile == NULL) {
		if (pledge("stdio rpath wpath cpath tty", NULL) == -1)
			err(1, "pledge");
	} else {
		if (unveil(passfile, "r") == -1)
			err(1, "unveil");

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

	if (pledge("stdio wpath cpath", NULL) == -1)
		err(1, "pledge");

	ret = 1;

	while ((file = sbk_get_file(ctx)) != NULL) {
		if (sbk_get_file_type(file) != type)
			continue;

		if ((fp = fopen(sbk_get_file_name(file), "wbx")) == NULL) {
			warn("%s", sbk_get_file_name(file));
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
		warnx("%s: %s", argv[0], sbk_error(ctx));
		goto out;
	}

	ret = 0;

out:
	sbk_free_file(file);
	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return ret;

usage:
	usage(cmd, "[-p passfile] backup [directory]");
}

int
cmd_attachments(int argc, char **argv)
{
	return write_files(argc, argv, SBK_ATTACHMENT);
}

int
cmd_avatars(int argc, char **argv)
{
	return write_files(argc, argv, SBK_AVATAR);
}
