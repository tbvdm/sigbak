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

#include <sys/types.h>
#include <sys/stat.h>

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

#include <openssl/evp.h>

#include "sigbak.h"

static enum cmd_status cmd_export_messages(int, char **);

const struct cmd_entry cmd_export_messages_entry = {
	.name = "export-messages",
	.alias = "msg",
	.usage = "[-f format] [-p passfile] backup [directory]",
	.exec = cmd_export_messages
};

enum {
	FORMAT_CSV,
	FORMAT_MAILDIR,
	FORMAT_TEXT
};

static FILE *
get_thread_file(struct sbk_thread *thd, int dfd, const char *ext)
{
	FILE	*fp;
	char	*name;
	int	 fd;

	if ((name = get_recipient_filename(thd->recipient, ext)) == NULL)
		return NULL;

	fd = openat(dfd, name, O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (fd == -1) {
		warn("%s", name);
		free(name);
		return NULL;
	}

	if ((fp = fdopen(fd, "w")) == NULL) {
		warn("%s", name);
		close(fd);
		free(name);
		return NULL;
	}

	free(name);
	return fp;
}

static void
csv_print_quoted_string(FILE *fp, const char *str)
{
	const char *c;

	if (str == NULL || str[0] == '\0')
		return;

	putc('"', fp);

	for (c = str; *c != '\0'; c++) {
		putc(*c, fp);
		if (*c == '"')
			putc('"', fp);
	}

	putc('"', fp);
}

static void
csv_write_record(FILE *fp, uint64_t time_sent, uint64_t time_recv,
    int thread, int type, int nattachments, const char *addr,
    const char *name, const char *text)
{
	fprintf(fp, "%" PRIu64 ",%" PRIu64 ",%d,%d,%d,",
	    time_sent, time_recv, thread, type, nattachments);

	csv_print_quoted_string(fp, addr);
	putc(',', fp);
	csv_print_quoted_string(fp, name);
	putc(',', fp);
	csv_print_quoted_string(fp, text);
	putc('\n', fp);
}

static int
csv_write_message(FILE *fp, struct sbk_message *msg)
{
	struct sbk_attachment	*att;
	struct sbk_reaction	*rct;
	const char		*addr;
	int			 nattachments;

	addr = (msg->recipient->type == SBK_CONTACT) ?
	    msg->recipient->contact->phone : "group";

	nattachments = 0;
	if (msg->attachments != NULL)
		TAILQ_FOREACH(att, msg->attachments, entries)
			nattachments++;

	csv_write_record(fp,
	    msg->time_sent,
	    msg->time_recv,
	    msg->thread,
	    sbk_is_outgoing_message(msg),
	    nattachments,
	    addr,
	    sbk_get_recipient_display_name(msg->recipient),
	    msg->text);

	if (msg->reactions != NULL)
		SIMPLEQ_FOREACH(rct, msg->reactions, entries)
			csv_write_record(fp,
			    rct->time_sent,
			    rct->time_recv,
			    msg->thread,
			    2,
			    0,
			    rct->recipient->contact->phone,
			    sbk_get_recipient_display_name(rct->recipient),
			    rct->emoji);

	return 0;
}

static int
csv_export_thread_messages(struct sbk_ctx *ctx, struct sbk_thread *thd,
    int dfd)
{
	struct sbk_message_list	*lst;
	struct sbk_message	*msg;
	FILE			*fp;
	int			 ret;

	if ((lst = sbk_get_messages_for_thread(ctx, thd)) == NULL)
		return -1;

	if (SIMPLEQ_EMPTY(lst)) {
		sbk_free_message_list(lst);
		return 0;
	}

	if ((fp = get_thread_file(thd, dfd, ".csv")) == NULL) {
		sbk_free_message_list(lst);
		return -1;
	}

	ret = 0;
	SIMPLEQ_FOREACH(msg, lst, entries)
		if (csv_write_message(fp, msg) == -1)
			ret = -1;

	fclose(fp);
	sbk_free_message_list(lst);
	return ret;
}

static int
maildir_create(int dfd, const char *path)
{
	int maildir_dfd, ret;

	maildir_dfd = -1;
	ret = -1;

	if (mkdirat(dfd, path, 0777) == -1) {
		warn("mkdir: %s", path);
		goto out;
	}

	if ((maildir_dfd = openat(dfd, path, O_RDONLY | O_DIRECTORY)) == -1) {
		warn("open: %s", path);
		goto out;
	}

	if (mkdirat(maildir_dfd, "cur", 0777) == -1) {
		warn("mkdirat: %s/%s", path, "cur");
		goto out;
	}

	if (mkdirat(maildir_dfd, "new", 0777) == -1) {
		warn("mkdirat: %s/%s", path, "new");
		goto out;
	}

	if (mkdirat(maildir_dfd, "tmp", 0777) == -1) {
		warn("mkdirat: %s/%s", path, "tmp");
		goto out;
	}

	ret = 0;

out:
	if (maildir_dfd != -1)
		close(maildir_dfd);
	return ret;
}

static FILE *
maildir_open_file(int dfd, const char *maildir, const struct sbk_message *msg)
{
	FILE	*fp;
	char	*path;
	int	 fd;

	/* Intentionally create deterministic filenames */
	/* XXX Shouldn't write directly into cur */
	if (asprintf(&path, "%s/cur/%" PRIu64 ".%s.localhost:2,S", maildir,
	    msg->time_recv, sbk_message_id_to_string(msg)) == -1) {
		warnx("asprintf() failed");
		return NULL;
	}

	fd = openat(dfd, path, O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (fd == -1) {
		warn("%s", path);
		return NULL;
	}

	if ((fp = fdopen(fd, "w")) == NULL) {
		warn("%s", path);
		close(fd);
		free(path);
		return NULL;
	}

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

#ifdef HAVE_TM_GMTOFF
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
#else
	fprintf(fp, "%s: %s, %d %s %d %02d:%02d:%02d\n",
	    hdr,
	    days[tm->tm_wday],
	    tm->tm_mday,
	    months[tm->tm_mon],
	    tm->tm_year + 1900,
	    tm->tm_hour,
	    tm->tm_min,
	    tm->tm_sec);
#endif
}

static int
maildir_generate_random_boundary(char *buf, size_t bufsize)
{
	size_t		i;
	const char	chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz";

	if (bufsize < 2)
		return -1;

	/*
	 * Include an underscore to ensure that the boundary does not occur in
	 * Base64 strings or in the headers of a body part
	 */
	buf[0] = '_';

	for (i = 1; i < bufsize - 1; i++) {
		/* Subtract 1 to exclude the NUL */
		buf[i] = chars[rand() % (sizeof chars - 1)];
	}

	buf[i] = '\0';
	return 0;
}

static int
maildir_generate_boundary(struct sbk_message *msg, char *buf,
    size_t bufsize)
{
	for (;;) {
		if (maildir_generate_random_boundary(buf, bufsize) == -1)
			return -1;
		if (msg->text == NULL || strstr(msg->text, buf) == NULL)
			return 0;
	}
}

static char *
maildir_base64_encode(const char *in, size_t inlen, size_t *outlen)
{
	char	*out;
	size_t	 outsize;

	*outlen = 0;

	/*
	 * Ensure that inlen can be passed to EVP_EncodeBlock() and that the
	 * outsize computation won't overflow
	 */
	if (inlen > INT_MAX || inlen > (SIZE_MAX - 1) / 4 * 3) {
		warnx("Attachment too large");
		return NULL;
	}

	outsize = (inlen + 2) / 3 * 4 + 1;
	if ((out = malloc(outsize)) == NULL) {
		warn(NULL);
		return NULL;
	}

	*outlen = EVP_EncodeBlock((unsigned char *)out,
	    (const unsigned char *)in, inlen);
	return out;
}

static int
maildir_write_attachment(struct sbk_ctx *ctx, FILE *fp,
    struct sbk_attachment *att)
{
	char	*b64, *data, *s;
	size_t	 b64len, datalen, n;

	if ((data = sbk_get_file_data(ctx, att->file, &datalen)) == NULL)
		return -1;

	if ((b64 = maildir_base64_encode(data, datalen, &b64len)) == NULL) {
		free(data);
		return -1;
	}

	s = b64;
	while (b64len > 0) {
		n = (b64len > 76) ? 76 : b64len;
		fprintf(fp, "%.*s\n", (int)n, s);
		s += n;
		b64len -= n;
	}

	free(data);
	free(b64);
	return 0;
}

static int
maildir_write_message(struct sbk_ctx *ctx, int dfd, const char *maildir,
    struct sbk_message *msg)
{
	FILE			*fp;
	struct sbk_attachment	*att;
	const char		*addr, *ext, *name, *type;
	int			 ret;
	char			 boundary[33];

	if (msg->attachments != NULL &&
	    maildir_generate_boundary(msg, boundary, sizeof boundary) == -1)
		return -1;

	if ((fp = maildir_open_file(dfd, maildir, msg)) == NULL)
		return -1;

	name = sbk_get_recipient_display_name(msg->recipient);
	addr = (msg->recipient->type == SBK_CONTACT) ?
	    msg->recipient->contact->phone : "group";

	if (sbk_is_outgoing_message(msg)) {
		maildir_write_address_header(fp, "From", "you", "You");
		maildir_write_address_header(fp, "To", addr, name);
	} else {
		maildir_write_address_header(fp, "From", addr, name);
		maildir_write_address_header(fp, "To", "you", "You");
	}

	maildir_write_date_header(fp, "Date", msg->time_sent);

	if (!sbk_is_outgoing_message(msg))
		maildir_write_date_header(fp, "X-Received", msg->time_recv);

	fprintf(fp, "X-Thread: %d\n", msg->thread);
	fputs("MIME-Version: 1.0\n", fp);

	if (msg->attachments != NULL) {
		fprintf(fp, "Content-Type: multipart/mixed; "
		    "boundary=%s\n\n", boundary);
		fprintf(fp, "--%s\n", boundary);
	}

	fputs("Content-Type: text/plain; charset=utf-8\n", fp);
	fputs("Content-Transfer-Encoding: binary\n", fp);
	fputs("Content-Disposition: inline\n\n", fp);
	if (msg->text != NULL)
		fprintf(fp, "%s\n", msg->text);

	ret = 0;

	if (msg->attachments != NULL) {
		TAILQ_FOREACH(att, msg->attachments, entries) {
			if (att->file == NULL)
				continue;
			if (att->content_type == NULL) {
				type = "application/octet-stream";
				ext = NULL;
			} else {
				type = att->content_type;
				ext = mime_get_extension(att->content_type);
			}
			fprintf(fp, "--%s\n", boundary);
			fprintf(fp, "Content-Type: %s\n", type);
			fputs("Content-Transfer-Encoding: base64\n", fp);
			fprintf(fp, "Content-Disposition: attachment; "
			    "filename=%s%s%s\n\n",
			    sbk_attachment_id_to_string(att),
			    (ext != NULL) ? "." : "",
			    (ext != NULL) ? ext : "");
			ret |= maildir_write_attachment(ctx, fp, att);
		}
		fprintf(fp, "--%s--\n", boundary);
	}

	fclose(fp);
	return ret;
}

static int
maildir_export_thread_messages(struct sbk_ctx *ctx, struct sbk_thread *thd,
    int dfd)
{
	struct sbk_message_list	*lst;
	struct sbk_message	*msg;
	char			*maildir;
	int			 ret;

	if ((lst = sbk_get_messages_for_thread(ctx, thd)) == NULL)
		return -1;

	if (SIMPLEQ_EMPTY(lst)) {
		sbk_free_message_list(lst);
		return 0;
	}

	if ((maildir = get_recipient_filename(thd->recipient, NULL)) == NULL)
		return -1;

	if (maildir_create(dfd, maildir) == -1) {
		free(maildir);
		return -1;
	}

	ret = 0;
	SIMPLEQ_FOREACH(msg, lst, entries)
		if (maildir_write_message(ctx, dfd, maildir, msg) == -1)
			ret = -1;

	free(maildir);
	sbk_free_message_list(lst);
	return ret;
}

static void
text_write_recipient_field(FILE *fp, const char *field,
    struct sbk_recipient *rcp)
{
	fprintf(fp, "%s: %s", field, sbk_get_recipient_display_name(rcp));

	if (rcp != NULL) {
		if (rcp->type == SBK_GROUP)
			fputs(" (group)", fp);
		else if (rcp->contact->phone != NULL)
			fprintf(fp, " (%s)", rcp->contact->phone);
	}

	putc('\n', fp);
}

static void
text_write_time_field(FILE *fp, const char *field, int64_t t)
{
	maildir_write_date_header(fp, field, t);
}

static void
text_write_attachment_field(FILE *fp, struct sbk_attachment *att)
{
	fputs("Attachment: ", fp);

	if (att->filename == NULL || *att->filename == '\0')
		fputs("no filename", fp);
	else
		fprintf(fp, "%s", att->filename);

	fprintf(fp, " (%s, %" PRIu64 " bytes, id %s)\n",
	    (att->content_type != NULL) ?
	    att->content_type : "",
	    att->size,
	    sbk_attachment_id_to_string(att));
}

static void
text_write_quote(FILE *fp, struct sbk_quote *qte)
{
	struct sbk_attachment	*att;
	char			*s, *t;

	fputs("\n> ", fp);
	text_write_recipient_field(fp, "From", qte->recipient);

	fputs("> ", fp);
	text_write_time_field(fp, "Sent", qte->id);

	if (qte->attachments != NULL)
		TAILQ_FOREACH(att, qte->attachments, entries) {
			fputs("> ", fp);
			text_write_attachment_field(fp, att);
		}

	if (qte->text != NULL && *qte->text != '\0') {
		fputs(">\n", fp);
		for (s = qte->text; (t = strchr(s, '\n')) != NULL; s = t + 1)
			fprintf(fp, "> %.*s\n", (int)(t - s), s);
		fprintf(fp, "> %s\n", s);
	}
}

static void
text_write_edits(FILE *fp, struct sbk_message *msg)
{
	struct sbk_attachment	*att;
	struct sbk_edit		*edit;

	TAILQ_FOREACH_REVERSE(edit, msg->edits, sbk_edit_list, entries) {
		fprintf(fp, "Version: %d\n", edit->revision + 1);
		text_write_time_field(fp, "Sent", edit->time_sent);

		if (!sbk_is_outgoing_message(msg))
			text_write_time_field(fp, "Received", edit->time_recv);

		if (edit->attachments != NULL)
			TAILQ_FOREACH(att, edit->attachments, entries)
				text_write_attachment_field(fp, att);

		if (edit->quote != NULL)
			text_write_quote(fp, edit->quote);

		if (edit->text != NULL && *edit->text != '\0')
			fprintf(fp, "\n%s\n\n", edit->text);
		else
			putc('\n', fp);
	}
}

static int
text_write_message(FILE *fp, struct sbk_message *msg)
{
	struct sbk_attachment	*att;
	struct sbk_reaction	*rct;

	if (sbk_is_outgoing_message(msg))
		fputs("From: You\n", fp);
	else
		text_write_recipient_field(fp, "From", msg->recipient);

	text_write_time_field(fp, "Sent", msg->time_sent);

	if (!sbk_is_outgoing_message(msg))
		text_write_time_field(fp, "Received", msg->time_recv);

	if (msg->attachments != NULL)
		TAILQ_FOREACH(att, msg->attachments, entries)
			text_write_attachment_field(fp, att);

	if (msg->reactions != NULL)
		SIMPLEQ_FOREACH(rct, msg->reactions, entries)
			fprintf(fp, "Reaction: %s from %s\n",
			    rct->emoji,
			    sbk_get_recipient_display_name(rct->recipient));

	if (msg->edits != NULL) {
		fprintf(fp, "Edited: %d versions\n\n", msg->nedits);
		text_write_edits(fp, msg);
	} else {
		if (msg->quote != NULL)
			text_write_quote(fp, msg->quote);

		if (msg->text != NULL && *msg->text != '\0')
			fprintf(fp, "\n%s\n\n", msg->text);
		else
			fputs("\n", fp);
	}

	return 0;
}

static int
text_export_thread_messages(struct sbk_ctx *ctx, struct sbk_thread *thd,
    int dfd)
{
	struct sbk_message_list	*lst;
	struct sbk_message	*msg;
	FILE			*fp;
	int			 ret;

	if ((lst = sbk_get_messages_for_thread(ctx, thd)) == NULL)
		return -1;

	if (SIMPLEQ_EMPTY(lst)) {
		sbk_free_message_list(lst);
		return 0;
	}

	if ((fp = get_thread_file(thd, dfd, ".txt")) == NULL) {
		sbk_free_message_list(lst);
		return -1;
	}

	text_write_recipient_field(fp, "Conversation", thd->recipient);
	putc('\n', fp);

	ret = 0;
	SIMPLEQ_FOREACH(msg, lst, entries)
		if (text_write_message(fp, msg) == -1)
			ret = -1;

	fclose(fp);
	sbk_free_message_list(lst);
	return ret;
}

static int
export_messages(struct sbk_ctx *ctx, const char *outdir, int format)
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
		switch (format) {
		case FORMAT_CSV:
			if (csv_export_thread_messages(ctx, thd, dfd) == -1)
				ret = -1;
			break;
		case FORMAT_MAILDIR:
			if (maildir_export_thread_messages(ctx, thd, dfd) ==
			    -1)
				ret = -1;
			break;
		case FORMAT_TEXT:
			if (text_export_thread_messages(ctx, thd, dfd) == -1)
				ret = -1;
			break;
		}
	}

	sbk_free_thread_list(lst);
	close(dfd);
	return ret;
}

static enum cmd_status
cmd_export_messages(int argc, char **argv)
{
	struct sbk_ctx	*ctx;
	char		*backup, *outdir, *passfile, passphr[128];
	int		 c, format, ret;

	format = FORMAT_TEXT;
	passfile = NULL;

	while ((c = getopt(argc, argv, "f:p:")) != -1)
		switch (c) {
		case 'f':
			if (strcmp(optarg, "csv") == 0)
				format = FORMAT_CSV;
			else if (strcmp(optarg, "maildir") == 0)
				format = FORMAT_MAILDIR;
			else if (strcmp(optarg, "text") == 0)
				format = FORMAT_TEXT;
			else {
				warnx("%s: Invalid format", optarg);
				return CMD_ERROR;
			}
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

	ret = export_messages(ctx, outdir, format);
	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return (ret == -1) ? CMD_ERROR : CMD_OK;
}
