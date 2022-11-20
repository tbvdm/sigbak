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
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sigbak.h"

static enum cmd_status cmd_export_attachments(int, char **);

const struct cmd_entry cmd_export_attachments_entry = {
	.name = "export-attachments",
	.alias = "att",
	.usage = "[-p passfile] [-t thread] backup [directory]",
	.oldname = "attachments",
	.exec = cmd_export_attachments
};

/*
 * Create a file with a unique name. If a file with the specified name already
 * exists, a new, unique name is used. Given a name of the form "base[.ext]",
 * the new name is of the form "base-n[.ext]" where 1 < n < 1000.
 */
static FILE *
create_unique_file(const char *name)
{
	FILE		*fp;
	char		*buf;
	const char	*base, *ext, *oldname;
	size_t		 baselen, bufsize, namelen;
	int		 i;

	buf = NULL;
	oldname = name;

	for (i = 2; i <= 1000; i++) {
		if ((fp = fopen(name, "wx")) != NULL)
			goto out;
		if (errno != EEXIST) {
			warn("%s", name);
			goto out;
		}

		if (buf == NULL) {
			namelen = strlen(name);

			ext = strrchr(name, '.');
			if (ext != NULL && ext != name && ext[1] != '\0')
				baselen = ext - name;
			else {
				baselen = namelen;
				ext = "";
			}

			if (namelen > SIZE_MAX - 5 || baselen > INT_MAX) {
				warnx("Attachment filename too long");
				goto out;
			}

			/* 4 for the "-n" affix and 1 for the NUL */
			bufsize = namelen + 5;
			if ((buf = malloc(bufsize)) == NULL) {
				warn(NULL);
				goto out;
			}

			base = name;
			name = buf;
		}

		snprintf(buf, bufsize, "%.*s-%d%s", (int)baselen, base, i,
		    ext);
	}

	warnx("%s: Cannot generate unique name", oldname);

out:
	free(buf);
	return fp;
}

static FILE *
get_file(struct sbk_attachment *att)
{
	FILE		*fp;
	struct tm	*tm;
	char		*name;
	const char	*ext;
	time_t		 tt;
	char		 base[40];

	if (att->filename != NULL && *att->filename != '\0') {
		if ((name = strdup(att->filename)) == NULL) {
			warn(NULL);
			return NULL;
		}
		sanitise_filename(name);
	} else {
		tt = att->time_sent / 1000;
		if ((tm = localtime(&tt)) == NULL) {
			warnx("localtime() failed");
			return NULL;
		}
		snprintf(base, sizeof base,
		    "attachment-%d-%02d-%02d-%02d-%02d-%02d",
		    tm->tm_year + 1900,
		    tm->tm_mon + 1,
		    tm->tm_mday,
		    tm->tm_hour,
		    tm->tm_min,
		    tm->tm_sec);
		if (att->content_type == NULL)
			ext = NULL;
		else
			ext = mime_get_extension(att->content_type);
		if (ext == NULL) {
			if ((name = strdup(base)) == NULL) {
				warn(NULL);
				return NULL;
			}
		} else {
			if (asprintf(&name, "%s.%s", base, ext) == -1) {
				warnx("asprintf() failed");
				return NULL;
			}
		}
	}

	fp = create_unique_file(name);
	free(name);
	return fp;
}

static int
write_attachments(struct sbk_ctx *ctx, struct sbk_attachment_list *lst)
{
	struct sbk_attachment	*att;
	FILE			*fp;
	int			 ret;

	ret = 0;

	TAILQ_FOREACH(att, lst, entries) {
		if (att->file == NULL)
			continue;

		if ((fp = get_file(att)) == NULL) {
			ret = -1;
			continue;
		}

		if (sbk_write_file(ctx, att->file, fp) == -1)
			ret = -1;

		fclose(fp);
	}

	return ret;
}

static enum cmd_status
cmd_export_attachments(int argc, char **argv)
{
	struct sbk_ctx			*ctx;
	struct sbk_attachment_list	*lst;
	char				*passfile, passphr[128];
	const char			*errstr, *outdir;
	int				 c, thread;

	passfile = NULL;
	thread = -1;

	while ((c = getopt(argc, argv, "p:t:")) != -1)
		switch (c) {
		case 'p':
			passfile = optarg;
			break;
		case 't':
			thread = strtonum(optarg, 1, INT_MAX, &errstr);
			if (errstr != NULL) {
				warnx("%s: Thread id is %s", optarg, errstr);
				return CMD_ERROR;
			}
			break;
		default:
			return CMD_USAGE;
		}

	argc -= optind;
	argv += optind;

	switch (argc) {
	case 1:
		outdir = ".";
		break;
	case 2:
		outdir = argv[1];
		if (mkdir(outdir, 0777) == -1 && errno != EEXIST) {
			warn("mkdir: %s", outdir);
			return CMD_ERROR;
		}
		break;
	default:
		return CMD_USAGE;
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

	if (chdir(outdir) == -1) {
		warn("chdir: %s", outdir);
		sbk_close(ctx);
		sbk_ctx_free(ctx);
		return CMD_ERROR;
	}

	if (passfile == NULL && pledge("stdio rpath wpath cpath", NULL) == -1)
		err(1, "pledge");

	if (thread == -1)
		lst = sbk_get_all_attachments(ctx);
	else
		lst = sbk_get_attachments_for_thread(ctx, thread);

	if (lst == NULL) {
		sbk_close(ctx);
		sbk_ctx_free(ctx);
		return CMD_ERROR;
	}

	if (write_attachments(ctx, lst) == -1) {
		sbk_free_attachment_list(lst);
		sbk_close(ctx);
		sbk_ctx_free(ctx);
		return CMD_ERROR;
	}

	sbk_free_attachment_list(lst);
	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return CMD_OK;
}
