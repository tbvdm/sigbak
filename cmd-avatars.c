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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sigbak.h"

enum type {
	AVATAR,
	STICKER
};

static const char *
get_extension(const char *data, size_t datalen)
{
	if (datalen >= 3 && memcmp(data, "\xff\xd8\xff", 3) == 0)
		return ".jpg";

	if (datalen >= 8 && memcmp(data, "\x89PNG\r\n\x1a\n", 8) == 0)
		return ".png";

	if (datalen >= 12 && memcmp(data, "RIFF", 4) == 0 &&
	    memcmp(data + 8, "WEBP", 4) == 0)
		return ".webp";

	return "";
}

static int
write_file(const char *path, const char *data, size_t datalen)
{
	FILE *fp;

	if ((fp = fopen(path, "wx")) == NULL) {
		warn("%s", path);
		return -1;
	}

	if (fwrite(data, datalen, 1, fp) != 1) {
		warn("%s", path);
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

static int
write_avatar(struct sbk_ctx *ctx, Signal__Avatar *avt, struct sbk_file *file)
{
	char		*base, *data, *name;
	const char	*ext;
	size_t		 datalen;
	int		 ret;

	data = name = NULL;
	ret = -1;

	if (avt->recipientid != NULL)
		base = avt->recipientid;
	else if (avt->name != NULL)
		base = avt->name;
	else {
		warnx("Invalid avatar frame");
		goto out;
	}

	if (strchr(base, '/') != NULL) {
		warnx("Invalid avatar filename");
		goto out;
	}

	if ((data = sbk_get_file_data(ctx, file, &datalen)) == NULL)
		goto out;

	ext = get_extension(data, datalen);

	if (asprintf(&name, "%s%s", base, ext) == -1) {
		warnx("asprintf() failed");
		name = NULL;
		goto out;
	}

	ret = write_file(name, data, datalen);

out:
	free(name);
	free(data);
	return ret;
}

static int
write_sticker(struct sbk_ctx *ctx, Signal__Sticker *stk, struct sbk_file *file)
{
	char		*data, *name;
	const char	*ext;
	size_t		 datalen;
	int		 ret;

	data = name = NULL;
	ret = -1;

	if (!stk->has_rowid) {
		warnx("Invalid sticker frame");
		goto out;
	}

	if ((data = sbk_get_file_data(ctx, file, &datalen)) == NULL)
		goto out;

	ext = get_extension(data, datalen);

	if (asprintf(&name, "%" PRIu64 "%s", stk->rowid, ext) == -1) {
		warnx("asprintf() failed");
		name = NULL;
		goto out;
	}

	ret = write_file(name, data, datalen);

out:
	free(name);
	free(data);
	return ret;
}

static int
write_files(int argc, char **argv, enum type type)
{
	struct sbk_ctx		*ctx;
	struct sbk_file		*file;
	Signal__BackupFrame	*frm;
	char			*cmd, *passfile, passphr[128];
	const char		*outdir;
	int			 c, ret;

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

	if (unveil(argv[0], "r") == -1)
		err(1, "unveil: %s", argv[0]);

	if (unveil(outdir, "rwc") == -1)
		err(1, "unveil: %s", outdir);

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
		return 1;

	if (get_passphrase(passfile, passphr, sizeof passphr) == -1) {
		sbk_ctx_free(ctx);
		return 1;
	}

	if (sbk_open(ctx, argv[0], passphr) == -1) {
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

	ret = 0;

	while ((frm = sbk_get_frame(ctx, &file)) != NULL) {
		if (frm->avatar != NULL && type == AVATAR) {
			if (write_avatar(ctx, frm->avatar, file) == -1)
				ret = 1;
		} else if (frm->sticker != NULL && type == STICKER) {
			if (write_sticker(ctx, frm->sticker, file) == -1)
				ret = 1;
		}
		sbk_free_frame(frm);
		sbk_free_file(file);
	}

	if (!sbk_eof(ctx))
		ret = 1;

	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return ret;

usage:
	usage(cmd, "[-p passfile] backup [directory]");
}

int
cmd_avatars(int argc, char **argv)
{
	return write_files(argc, argv, AVATAR);
}

int
cmd_stickers(int argc, char **argv)
{
	return write_files(argc, argv, STICKER);
}
