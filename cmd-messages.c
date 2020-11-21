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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <err.h>
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

#define FORMAT_MAILDIR	0
#define FORMAT_TEXT	1

static void
maildir_create(const char *path)
{
	int fd;

	if (mkdir(path, 0777) == -1)
		err(1, "mkdir: %s", path);

	if ((fd = open(path, O_RDONLY | O_DIRECTORY)) == -1)
		err(1, "open: %s", path);

	if (mkdirat(fd, "cur", 0777) == -1)
		err(1, "mkdirat: %s/%s", path, "cur");

	if (mkdirat(fd, "new", 0777) == -1)
		err(1, "mkdirat: %s/%s", path, "new");

	if (mkdirat(fd, "tmp", 0777) == -1)
		err(1, "mkdirat: %s/%s", path, "tmp");

	close(fd);
}

static FILE *
maildir_open_file(const char *maildir, int64_t date_recv, int64_t date_sent)
{
	FILE	*fp;
	char	*path;

	/* Intentionally create deterministic filenames */
	/* XXX Shouldn't write directly into cur */
	if (asprintf(&path, "%s/cur/%" PRId64 ".%" PRId64 ".localhost:2,S",
	    maildir, date_recv, date_sent) == -1) {
		warnx("asprintf() failed");
		return NULL;
	}

	if ((fp = fopen(path, "wx")) == NULL)
		warn("fopen: %s", path);

	free(path);
	return fp;
}

static void
maildir_write_address_header(FILE *fp, const char *hdr, const char *addr,
    const char *name)
{
	if (name == NULL)
		fprintf(fp, "%s: %s@invalid\n", hdr, addr);
	else
		/* XXX Need to escape double quotes in name */
		fprintf(fp, "%s: \"%s\" <%s@invalid>\n", hdr, name, addr);
}

static void
maildir_write_date_header(FILE *fp, const char *hdr, int64_t date)
{
	const char	*days[] = {
	    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

	const char	*months[] = {
	    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
	    "Oct", "Nov", "Dec" };

	struct tm	*tm;
	time_t		 tt;

	tt = date / 1000;

	if ((tm = localtime(&tt)) == NULL) {
		warnx("localtime() failed");
		return;
	}

	fprintf(fp, "%s: %s, %d %s %d %02d:%02d:%02d %c%02ld%02ld\n",
	    hdr,
	    days[tm->tm_wday],
	    tm->tm_mday,
	    months[tm->tm_mon],
	    tm->tm_year + 1900,
	    tm->tm_hour,
	    tm->tm_min,
	    tm->tm_sec,
	    (tm->tm_gmtoff < 0) ? '-' : '+',
	    labs(tm->tm_gmtoff) / 3600,
	    labs(tm->tm_gmtoff) % 3600 / 60);
}

static int
maildir_write_message(struct sbk_ctx *ctx, const char *maildir,
    struct sbk_message *msg)
{
	FILE	*fp;
	char	*name, *phone;
	int	 isgroup, ret;

	ret = -1;
	isgroup = sbk_is_group(ctx, msg->address);

	if (isgroup) {
		if (sbk_get_group(ctx, msg->address, &name) == -1) {
			warnx("%s", sbk_error(ctx));
			return -1;
		}
		phone = NULL;
	} else {
		if (sbk_get_contact(ctx, msg->address, &name, &phone) == -1) {
			warnx("%s", sbk_error(ctx));
			return -1;
		}
	}

	if ((fp = maildir_open_file(maildir, msg->time_recv, msg->time_sent))
	    == NULL)
		goto out;

	if (sbk_is_outgoing_message(msg)) {
		maildir_write_address_header(fp, "From", "you", "You");
		maildir_write_address_header(fp, "To",
		    isgroup ? "group" : phone, name);
	} else {
		maildir_write_address_header(fp, "From", phone, name);
		maildir_write_address_header(fp, "To", "you", "You");
	}

	maildir_write_date_header(fp, "Date", msg->time_sent);

	if (!sbk_is_outgoing_message(msg))
		maildir_write_date_header(fp, "X-Received", msg->time_recv);

	fprintf(fp, "X-Thread: %d\n", msg->thread);
	fputs("MIME-Version: 1.0\n", fp);
	fputs("Content-Type: text/plain; charset=utf-8\n", fp);
	fputs("Content-Disposition: inline\n", fp);

	if (msg->text != NULL)
		fprintf(fp, "\n%s\n", msg->text);

	fclose(fp);
	ret = 0;

out:
	freezero_string(name);
	freezero_string(phone);
	return ret;
}

static int
maildir_write_messages(struct sbk_ctx *ctx, const char *maildir, int thread)
{
	struct sbk_message_list	*lst;
	struct sbk_message	*msg;
	int			 ret;

	if (thread == -1)
		lst = sbk_get_all_messages(ctx);
	else
		lst = sbk_get_messages_for_thread(ctx, thread);

	if (lst == NULL) {
		warnx("Cannot get messages: %s", sbk_error(ctx));
		return -1;
	}

	ret = 0;

	SIMPLEQ_FOREACH(msg, lst, entries)
		if (maildir_write_message(ctx, maildir, msg) == -1)
			ret = -1;

	sbk_free_message_list(lst);
	return ret;
}

static int
text_write_message(struct sbk_ctx *ctx, FILE *fp, struct sbk_message *msg)
{
	struct sbk_attachment	*att;
	char			*name, *phone;
	int			 isgroup;

	isgroup = sbk_is_group(ctx, msg->address);

	if (isgroup) {
		if (sbk_get_group(ctx, msg->address, &name) == -1) {
			warnx("%s", sbk_error(ctx));
			return -1;
		}
		phone = NULL;
	} else {
		if (sbk_get_contact(ctx, msg->address, &name, &phone) == -1) {
			warnx("%s", sbk_error(ctx));
			return -1;
		}
	}

	if (sbk_is_outgoing_message(msg))
		fputs("To: ", fp);
	else
		fputs("From: ", fp);

	fprintf(fp, "%s (%s)\n",
	    (name != NULL) ? name : "unknown",
	    isgroup ? "group" : ((phone != NULL) ? phone : "unknown"));

	maildir_write_date_header(fp, "Sent", msg->time_sent);

	if (!sbk_is_outgoing_message(msg))
		maildir_write_date_header(fp, "Received", msg->time_recv);

	fprintf(fp, "Thread: %d\n", msg->thread);

	if (msg->attachments != NULL)
		TAILQ_FOREACH(att, msg->attachments, entries) {
			fputs("Attachment: ", fp);

			if (att->filename == NULL)
				fputs("no filename", fp);
			else
				fprintf(fp, "\"%s\"", att->filename);

			fprintf(fp, " (%s, %" PRIu64 " bytes, id %" PRId64
			    "-%" PRId64 ")\n",
			    (att->content_type != NULL) ?
			    att->content_type : "",
			    att->size,
			    att->rowid,
			    att->attachmentid);
		}

	if (msg->text != NULL)
		fprintf(fp, "\n%s\n\n", msg->text);
	else
		fputs("\n", fp);

	freezero_string(name);
	freezero_string(phone);
	return 0;
}

static int
text_write_messages(struct sbk_ctx *ctx, const char *outfile, int thread)
{
	struct sbk_message_list	*lst;
	struct sbk_message	*msg;
	FILE			*fp;
	int			 ret;

	if (outfile == NULL)
		fp = stdout;
	else if ((fp = fopen(outfile, "wx")) == NULL) {
		warn("fopen: %s", outfile);
		return -1;
	}

	if (thread == -1)
		lst = sbk_get_all_messages(ctx);
	else
		lst = sbk_get_messages_for_thread(ctx, thread);

	if (lst == NULL) {
		warnx("Cannot get messages: %s", sbk_error(ctx));
		fclose(fp);
		return -1;
	}

	ret = 0;

	SIMPLEQ_FOREACH(msg, lst, entries)
		if (text_write_message(ctx, fp, msg) == -1)
			ret = -1;

	sbk_free_message_list(lst);

	if (fp != stdout)
		fclose(fp);

	return ret;
}

int
cmd_messages(int argc, char **argv)
{
	struct sbk_ctx	*ctx;
	char		*dest, *passfile, passphr[128];
	const char	*errstr;
	int		 c, format, ret, thread;

	format = FORMAT_TEXT;
	passfile = NULL;
	thread = -1;

	while ((c = getopt(argc, argv, "f:p:t:")) != -1)
		switch (c) {
		case 'f':
			if (strcmp(optarg, "maildir") == 0)
				format = FORMAT_MAILDIR;
			else if (strcmp(optarg, "text") == 0)
				format = FORMAT_TEXT;
			else
				errx(1, "%s: invalid format", optarg);
			break;
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
		if (format == FORMAT_MAILDIR)
			goto usage;
		dest = NULL;
		break;
	case 2:
		dest = argv[1];
		if (format == FORMAT_MAILDIR)
			maildir_create(dest);
		if (unveil(dest, "wc") == -1)
			err(1, "unveil");
		break;
	default:
		goto usage;
	}

	if (unveil(argv[0], "r") == -1)
		err(1, "unveil");

	/* For SQLite */
	if (unveil("/dev/urandom", "r") == -1)
		err(1, "unveil");

	/* For SQLite */
	if (unveil("/tmp", "rwc") == -1)
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

	if (get_passphrase(passfile, passphr, sizeof passphr) == -1)
		return -1;

	if (sbk_open(ctx, argv[0], passphr) == -1) {
		warnx("%s: %s", argv[0], sbk_error(ctx));
		explicit_bzero(passphr, sizeof passphr);
		sbk_ctx_free(ctx);
		return 1;
	}

	explicit_bzero(passphr, sizeof passphr);

	if (passfile == NULL && pledge("stdio rpath wpath cpath", NULL) == -1)
		err(1, "pledge");

	switch (format) {
	case FORMAT_MAILDIR:
		ret = maildir_write_messages(ctx, dest, thread);
		break;
	case FORMAT_TEXT:
		ret = text_write_messages(ctx, dest, thread);
		break;
	}

	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return (ret == 0) ? 0 : 1;

usage:
	usage("messages", "[-f format] [-p passfile] [-t thread] backup dest");
}
