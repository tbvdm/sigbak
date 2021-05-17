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

enum {
	FORMAT_CSV,
	FORMAT_MAILDIR,
	FORMAT_TEXT
};

static EVP_ENCODE_CTX *evp_encode_ctx;

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
csv_write_messages(struct sbk_ctx *ctx, const char *outfile, int thread)
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
		if (csv_write_message(fp, msg) == -1)
			ret = -1;

	sbk_free_message_list(lst);

	if (fp != stdout)
		fclose(fp);

	return ret;
}

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
maildir_open_file(const char *maildir, const struct sbk_message *msg)
{
	FILE	*fp;
	char	*path;

	/* Intentionally create deterministic filenames */
	/* XXX Shouldn't write directly into cur */
	if (asprintf(&path, "%s/cur/%" PRIu64 ".%d-%d.localhost:2,S", maildir,
	    msg->time_recv, msg->id.type, msg->id.rowid) == -1) {
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

	for (i = 1; i < bufsize - 1; i++)
		buf[i] = chars[rand() % (sizeof chars - 1)];

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

	if (evp_encode_ctx == NULL) {
		if ((evp_encode_ctx = EVP_ENCODE_CTX_new()) == NULL) {
			warnx("Cannot allocate encoding context");
			return NULL;
		}
	}

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

	*outlen = EVP_EncodeBlock((unsigned char *)out, (unsigned char *)in,
	    inlen);
	return out;
}

static int
maildir_write_attachment(struct sbk_ctx *ctx, FILE *fp,
    struct sbk_attachment *att)
{
	char	*b64, *data, *s;
	size_t	 b64len, datalen, n;

	if ((data = sbk_get_file_data(ctx, att->file, &datalen)) == NULL) {
		warnx("Cannot get attachment data: %s", sbk_error(ctx));
		return -1;
	}

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
maildir_write_message(struct sbk_ctx *ctx, const char *maildir,
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

	if ((fp = maildir_open_file(maildir, msg)) == NULL)
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
			    "filename=%" PRId64 "-%" PRId64 "%s%s\n\n",
			    att->rowid,
			    att->attachmentid,
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

	if (evp_encode_ctx != NULL)
		EVP_ENCODE_CTX_free(evp_encode_ctx);

	sbk_free_message_list(lst);
	return ret;
}

static int
text_write_message(FILE *fp, struct sbk_message *msg)
{
	struct sbk_attachment	*att;
	struct sbk_reaction	*rct;
	const char		*addr, *name;

	name = sbk_get_recipient_display_name(msg->recipient);
	addr = (msg->recipient->type == SBK_CONTACT) ?
	    msg->recipient->contact->phone : "group";

	if (sbk_is_outgoing_message(msg))
		fputs("To: ", fp);
	else
		fputs("From: ", fp);

	fprintf(fp, "%s (%s)\n", name, addr);

	maildir_write_date_header(fp, "Sent", msg->time_sent);

	if (!sbk_is_outgoing_message(msg))
		maildir_write_date_header(fp, "Received", msg->time_recv);

	fprintf(fp, "Message id: %d-%d\n", msg->id.type, msg->id.rowid);
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

	if (msg->reactions != NULL)
		SIMPLEQ_FOREACH(rct, msg->reactions, entries)
			fprintf(fp, "Reaction: %s from %s\n",
			    rct->emoji,
			    sbk_get_recipient_display_name(rct->recipient));

	if (msg->text != NULL)
		fprintf(fp, "\n%s\n\n", msg->text);
	else
		fputs("\n", fp);

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
		if (text_write_message(fp, msg) == -1)
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
			if (strcmp(optarg, "csv") == 0)
				format = FORMAT_CSV;
			else if (strcmp(optarg, "maildir") == 0)
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
	case FORMAT_CSV:
		ret = csv_write_messages(ctx, dest, thread);
		break;
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
