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
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sigbak.h"

#define FLAG_EXPORT_ALL		0x1
#define FLAG_FILENAME_ID	0x2

static enum cmd_status cmd_export_attachments(int, char **);

const struct cmd_entry cmd_export_attachments_entry = {
	.name = "export-attachments",
	.alias = "att",
	.usage = "[-aI] [-p passfile] backup [directory]",
	.exec = cmd_export_attachments
};

/*
 * Create a file with a unique name. If a file with the specified name already
 * exists, a new, unique name is used. Given a name of the form "base[.ext]",
 * the new name is of the form "base-n[.ext]" where 1 < n < 1000.
 */
static FILE *
create_unique_file(int dfd, const char *name)
{
	FILE		*fp;
	char		*buf;
	const char	*base, *ext, *oldname;
	size_t		 baselen, bufsize, namelen;
	int		 fd, i;

	buf = NULL;
	oldname = name;

	for (i = 2; i <= 1000; i++) {
		fd = openat(dfd, name, O_WRONLY | O_CREAT | O_EXCL, 0666);
		if (fd != -1)
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
	if (fd == -1)
		fp = NULL;
	else if ((fp = fdopen(fd, "w")) == NULL) {
		warn("%s", name);
		close(fd);
	}

	free(buf);
	return fp;
}

static FILE *
get_file(int dfd, struct sbk_attachment *att, int flags)
{
	FILE		*fp;
	struct tm	*tm;
	char		*name, *tmp;
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

	if (flags & FLAG_FILENAME_ID) {
		if (asprintf(&tmp, "%s %s",
		    sbk_attachment_id_to_string(att), name) == -1) {
			warnx("asprintf() failed");
			free(name);
			return NULL;
		}
		free(name);
		name = tmp;
	}

	fp = create_unique_file(dfd, name);
	free(name);
	return fp;
}

static int
get_thread_directory(int dfd, struct sbk_thread *thd)
{
	char	*name;
	int	 thd_dfd;

	if ((name = get_recipient_filename(thd->recipient, NULL)) == NULL)
		return -1;

	if (mkdirat(dfd, name, 0777) == -1 && errno != EEXIST) {
		warn("%s", name);
		free(name);
		return -1;
	}

	if ((thd_dfd = openat(dfd, name, O_RDONLY | O_DIRECTORY)) == -1) {
		warn("%s", name);
		free(name);
		return -1;
	}

	free(name);
	return thd_dfd;
}

static int
export_thread_attachments(struct sbk_ctx *ctx, struct sbk_thread *thd, int dfd,
    int flags)
{
	struct sbk_attachment_list	*lst;
	struct sbk_attachment		*att, *tmp;
	FILE				*fp;
	int				 ret, thd_dfd;

	if ((lst = sbk_get_attachments_for_thread(ctx, thd)) == NULL)
		return -1;

	if (~flags & FLAG_EXPORT_ALL) {
		/* Skip long-message attachments */
		TAILQ_FOREACH_SAFE(att, lst, entries, tmp)
			if (att->content_type != NULL &&
			    strcmp(att->content_type, SBK_LONG_TEXT_TYPE) == 0)
				TAILQ_REMOVE(lst, att, entries);
	}

	if (TAILQ_EMPTY(lst)) {
		sbk_free_attachment_list(lst);
		return 0;
	}

	if ((thd_dfd = get_thread_directory(dfd, thd)) == -1) {
		sbk_free_attachment_list(lst);
		return -1;
	}

	ret = 0;
	TAILQ_FOREACH(att, lst, entries) {
		if (att->file == NULL)
			continue;

		if ((fp = get_file(thd_dfd, att, flags)) == NULL) {
			ret = -1;
			continue;
		}

		if (sbk_write_file(ctx, att->file, fp) == -1)
			ret = -1;

		fclose(fp);
	}

	close(thd_dfd);
	sbk_free_attachment_list(lst);
	return ret;
}

static int
export_attachments(struct sbk_ctx *ctx, const char *outdir, int flags)
{
	struct sbk_thread_list	*lst;
	struct sbk_thread	*thd;
	int			 dfd, ret;

	if ((dfd = open(outdir, O_RDONLY | O_DIRECTORY)) == -1) {
		warn("%s", outdir);
		return -1;
	}

	if ((lst = sbk_get_threads(ctx)) == NULL) {
		close(dfd);
		return -1;
	}

	ret = 0;
	SIMPLEQ_FOREACH(thd, lst, entries) {
		if (export_thread_attachments(ctx, thd, dfd, flags) == -1)
			ret = -1;
	}

	sbk_free_thread_list(lst);
	close(dfd);
	return ret;
}

static enum cmd_status
cmd_export_attachments(int argc, char **argv)
{
	struct sbk_ctx	*ctx;
	char		*backup, *passfile, passphr[128];
	const char	*outdir;
	int		 c, flags, ret;

	flags = 0;
	passfile = NULL;

	while ((c = getopt(argc, argv, "aIp:")) != -1)
		switch (c) {
		case 'a':
			flags |= FLAG_EXPORT_ALL;
			break;
		case 'I':
			flags |= FLAG_FILENAME_ID;
			break;
		case 'p':
			passfile = optarg;
			break;
		default:
			return CMD_USAGE;
		}

	argc -= optind;
	argv += optind;

	switch (argc) {
	case 1:
		backup = argv[0];
		outdir = ".";
		break;
	case 2:
		backup = argv[0];
		outdir = argv[1];
		if (mkdir(outdir, 0777) == -1 && errno != EEXIST) {
			warn("mkdir: %s", outdir);
			return CMD_ERROR;
		}
		break;
	default:
		return CMD_USAGE;
	}

	if (unveil(backup, "r") == -1)
		err(1, "unveil: %s", backup);

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

	if (sbk_open(ctx, backup, passphr) == -1) {
		explicit_bzero(passphr, sizeof passphr);
		sbk_ctx_free(ctx);
		return CMD_ERROR;
	}

	explicit_bzero(passphr, sizeof passphr);

	if (passfile == NULL && pledge("stdio rpath wpath cpath", NULL) == -1)
		err(1, "pledge");

	ret = export_attachments(ctx, outdir, flags);
	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return (ret == -1) ? CMD_ERROR : CMD_OK;
}
