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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sigbak.h"

static enum cmd_status cmd_export_messages(int, char **);
static void text_write_time_field(FILE *fp, const char *field, int64_t msec);

const struct cmd_entry cmd_export_messages_entry = {
	.name = "export-messages",
	.alias = "msg",
	.usage = "[-f format] [-p passfile] backup [directory]",
	.exec = cmd_export_messages
};

enum {
	FORMAT_CSV,
	FORMAT_TEXT,
	FORMAT_TEXT_SHORT,
	FORMAT_HTML
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
	char	*att_text;

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

	if (msg->attachments != NULL)
		TAILQ_FOREACH(att, msg->attachments, entries)
		{
			att_text=	get_attachment_field(att, FLAG_FILENAME_ID);	// always add ID to ensure a unique name
			if (att_text==NULL)
				att_text=	strdup("error: failed to get attachment field");

			csv_write_record(fp,
				msg->time_sent,
				msg->time_recv,
				msg->thread,
			    3,
			    0,
			    addr,
				sbk_get_recipient_display_name(msg->recipient),
			    att_text);
			free(att_text);
		} // TAILQ_FOREACH

	return 0;
}

static void
html_write_record(FILE *fp, uint64_t time_sent, uint64_t time_recv,
    int thread, int type, int nattachments, const char *addr,
    const char *name, const char *text)
{

	if (type>1)
		return;		// reactions not yet supported

	if (type==1)
	{	name=	"You";
		fprintf(fp, "<div class=\"message default sent\">\n", addr);
	}
	else
		fprintf(fp, "<div class=\"message default\">\n", addr);


	fprintf(fp, "  <div class=\"float_right details\">");
	text_write_time_field(fp, "Sent", time_sent);
	text_write_time_field(fp, "\n<br>Received", time_recv);
	fprintf(fp, "  </div>\n");

	fprintf(fp, "  <div class=\"from_name\">%s<br>&nbsp;</div>\n", name);	// name of sender
	
	fprintf(fp, "  <div class=\"text\">");	// message text
	while( (text) && (*text) )
	{	if (*text!='\n')			// handle line breaks
			putc(*text, fp);
		else
			fprintf(fp, "<br>\n");
		text++;
	}
	fprintf(fp, "</div>\n</div>\n");
}

static int
html_write_message(FILE *fp, struct sbk_message *msg)
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
		{
			nattachments++;

		} // TAILQ_FOREACH

	html_write_record(fp,
	    msg->time_sent,
	    msg->time_recv,
	    msg->thread,
	    sbk_is_outgoing_message(msg),
	    nattachments,
	    addr,
	    sbk_get_recipient_display_name(msg->recipient),
	    msg->text);

	return 0;
} // html_write_message()

static int
csv_export_thread(struct sbk_ctx *ctx, struct sbk_thread *thd, int dfd)
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
html_export_thread(struct sbk_ctx *ctx, struct sbk_thread *thd, int dfd)
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

	if ((fp = get_thread_file(thd, dfd, ".html")) == NULL) {
		sbk_free_message_list(lst);
		return -1;
	}

	fprintf(fp, "<!DOCTYPE html>\n<html>\n  <head>\n   <meta charset=\"utf-8\"/>\n   <title>Exported Data</title>\n   <link href=\"..\\style.css\" rel=\"stylesheet\"/>\n  </head>\n  <body>\n");	// file header
	
	fprintf(fp, "\n   <div class=\"page_body chat_page\">\n");	// div for messages
	

	ret = 0;
	SIMPLEQ_FOREACH(msg, lst, entries)
		if (html_write_message(fp, msg) == -1)
			ret = -1;

	fprintf(fp, "\n   </div>\n  </body>\n</html>\n");	// file header

	fclose(fp);
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
text_write_time_field(FILE *fp, const char *field, int64_t msec)
{
	static const char *days[] = {
	    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	static const char *months[] = {
	    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
	    "Oct", "Nov", "Dec" };

	struct tm	*tm;
	time_t		 tt;

	tt = msec / 1000;

	if ((tm = localtime(&tt)) == NULL) {
		warnx("localtime() failed");
		return;
	}

#ifdef HAVE_TM_GMTOFF
	fprintf(fp, "%s: %s, %d %s %d %02d:%02d:%02d %c%02ld%02ld\n",
	    field,
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
	    field,
	    days[tm->tm_wday],
	    tm->tm_mday,
	    months[tm->tm_mon],
	    tm->tm_year + 1900,
	    tm->tm_hour,
	    tm->tm_min,
	    tm->tm_sec);
#endif
}

char
*get_attachment_field(struct sbk_attachment *att, int flags)
{
	char *att_text=	NULL, *att_fname, *id_text;

	att_fname=	get_file_name(att, flags);
	if (att_fname==NULL)
		att_fname=	strdup("no filename");

	if (flags & FLAG_FILENAME_ID)
		id_text=	strdup("");
	else
		asprintf(&id_text, ", id %s", sbk_attachment_id_to_string(att));
	
	asprintf(&att_text, "%s (%s, %" PRIu64 " bytes%s)", att_fname,
		(att->content_type != NULL) ?
		att->content_type : "",
		att->size,
		id_text);
	free(id_text);
	free(att_fname);

	return att_text;
}

static void
text_write_attachment_field(FILE *fp, struct sbk_attachment *att)
{
	char *att_text;

	fputs("Attachment: ", fp);
	
	att_text=	get_attachment_field(att, 0);
	if (att_text==NULL)
		fputs("error: failed to get attachment field", fp);
	else
	{	fprintf(fp, "%s\n", att_text);
		free(att_text);
	}
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
text_export_thread(struct sbk_ctx *ctx, struct sbk_thread *thd, int dfd)
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

static const char *
text_short_format_time(int64_t msec)
{
	struct tm	*tm;
	time_t		 tt;
	static char	 buf[64];

	tt = msec / 1000;

	if ((tm = localtime(&tt)) == NULL) {
		warnx("localtime() failed");
		buf[0] = '\0';
		return buf;
	}

	snprintf(buf, sizeof buf, "%d-%02d-%02d %02d:%02d",
	    tm->tm_year + 1900,
	    tm->tm_mon + 1,
	    tm->tm_mday,
	    tm->tm_hour,
	    tm->tm_min);
	return buf;
}

static int
text_short_write_message(FILE *fp, struct sbk_message *msg)
{
	struct sbk_attachment	*att;
	const char		*name, *time;
	int			 details, natts;

	time = text_short_format_time(msg->time_sent);
	name = sbk_is_outgoing_message(msg) ? "You" :
	    sbk_get_recipient_display_name(msg->recipient);
	fprintf(fp, "%s %s:", time, name);

	details = 0;
	if (msg->quote != NULL) {
		name = sbk_get_recipient_display_name(msg->quote->recipient);
		time = text_short_format_time(msg->quote->id);
		fprintf(fp, " [reply to %s on %s", name, time);
		details = 1;
	}
	if (msg->edits != NULL) {
		fprintf(fp, "%sedited", details ? ", " : " [");
		details = 1;
	}
	if (msg->attachments != NULL) {
		natts = 0;
		TAILQ_FOREACH(att, msg->attachments, entries)
			natts++;
		if (natts > 0) {
			fprintf(fp, "%s%d attachment%s", details ? ", " : " [",
			    natts, (natts > 1) ? "s" : "");
			details = 1;
		}
	}
	if (details)
		putc(']', fp);

	if (msg->text != NULL && *msg->text != '\0')
		fprintf(fp, " %s\n", msg->text);
	else
		putc('\n', fp);

	return 0;
}

static int
text_short_export_thread(struct sbk_ctx *ctx, struct sbk_thread *thd, int dfd)
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

	ret = 0;
	SIMPLEQ_FOREACH(msg, lst, entries)
		if (text_short_write_message(fp, msg) == -1)
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
			if (csv_export_thread(ctx, thd, dfd) == -1)
				ret = -1;
			break;
		case FORMAT_TEXT:
			if (text_export_thread(ctx, thd, dfd) == -1)
				ret = -1;
			break;
		case FORMAT_TEXT_SHORT:
			if (text_short_export_thread(ctx, thd, dfd) == -1)
				ret = -1;
			break;
		case FORMAT_HTML:
			if (html_export_thread(ctx, thd, dfd) == -1)
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
			else if (strcmp(optarg, "text") == 0)
				format = FORMAT_TEXT;
			else if (strcmp(optarg, "text-short") == 0)
				format = FORMAT_TEXT_SHORT;
			else if (strcmp(optarg, "html") == 0)
				format = FORMAT_HTML;
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
		if (strcmp(passfile, "-") != 0 && unveil(passfile, "r") == -1)
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
