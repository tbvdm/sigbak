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

#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sbk.h"
#include "sigbak.h"

static int
text_write_mms(struct sbk_ctx *ctx, FILE *fp, struct sbk_mms *mms)
{
	struct sbk_attachment_list *lst;
	struct sbk_attachment *att;
	char	*name;
	time_t	 date;
	int	 isgroup;

	if (SBK_IS_OUTGOING_MESSAGE(mms->type))
		fputs("To: ", fp);
	else
		fputs("From: ", fp);

	if (sbk_is_group_address(mms->address)) {
		name = sbk_get_group_name(ctx, mms->address);
		isgroup = 1;
	} else {
		name = sbk_get_contact_name(ctx, mms->address);
		isgroup = 0;
	}

	if (name == NULL)
		fprintf(fp, "%s\n", isgroup ? "unknown group" : mms->address);
	else {
		fprintf(fp, "%s (%s)\n", name, isgroup ? "group" :
		    mms->address);
		free(name);
	}

	date = mms->date_sent / 1000;
	fprintf(fp, "Sent: %s", ctime(&date));

	if (!SBK_IS_OUTGOING_MESSAGE(mms->type)) {
		date = mms->date_recv / 1000;
		fprintf(fp, "Received: %s", ctime(&date));
	}

	fprintf(fp, "Type: %#x\n", mms->type);
	fprintf(fp, "Thread: %d\n", mms->thread);

	if (mms->nattachments > 0) {
		if ((lst = sbk_get_attachments(ctx, mms->id)) == NULL)
			return -1;

		SIMPLEQ_FOREACH(att, lst, entries) {
			fputs("Attachment: ", fp);
			if (att->filename == NULL)
				fputs("no filename", fp);
			else
				fprintf(fp, "\"%s\"", att->filename);
			fprintf(fp, " (%s, %" PRIu64 " bytes, id %" PRId64
			    ")\n", (att->content_type != NULL) ? att->content_type :
			    "", att->size, att->id);
		}

		sbk_free_attachment_list(lst);
	}

	if (mms->body != NULL)
		fprintf(fp, "\n%s\n\n", mms->body);
	else
		fputs("\n", fp);

	return 0;
}

static int
text_write_sms(struct sbk_ctx *ctx, FILE *fp, struct sbk_sms *sms)
{
	char	*name;
	time_t	 date;

	if (SBK_IS_OUTGOING_MESSAGE(sms->type))
		fputs("To: ", fp);
	else
		fputs("From: ", fp);

	if ((name = sbk_get_contact_name(ctx, sms->address)) == NULL)
		fprintf(fp, "%s\n", sms->address);
	else {
		fprintf(fp, "%s (%s)\n", name, sms->address);
		free(name);
	}

	date = sms->date_sent / 1000;
	fprintf(fp, "Sent: %s", ctime(&date));

	if (!SBK_IS_OUTGOING_MESSAGE(sms->type)) {
		date = sms->date_recv / 1000;
		fprintf(fp, "Received: %s", ctime(&date));
	}

	fprintf(fp, "Type: %#x\n", sms->type);
	fprintf(fp, "Thread: %d\n", sms->thread);

	if (sms->body != NULL)
		fprintf(fp, "\n%s\n\n", sms->body);
	else
		fputs("\n", fp);

	return 0;
}

static int
text_write_messages(struct sbk_ctx *ctx, const char *outfile)
{
	struct sbk_mms_list	*mmslst;
	struct sbk_sms_list	*smslst;
	struct sbk_mms		*mms;
	struct sbk_sms		*sms;
	FILE			*fp;

	if (outfile == NULL)
		fp = stdout;
	else if ((fp = fopen(outfile, "wx")) == NULL) {
		warn("fopen: %s", outfile);
		return -1;
	}

	if ((mmslst = sbk_get_mmses(ctx)) == NULL) {
		warnx("Cannot get mms messages: %s", sbk_error(ctx));
		return -1;
	}

	if ((smslst = sbk_get_smses(ctx)) == NULL) {
		warnx("Cannot get sms messages: %s", sbk_error(ctx));
		sbk_free_mms_list(mmslst);
		return -1;
	}

	mms = SIMPLEQ_FIRST(mmslst);
	sms = SIMPLEQ_FIRST(smslst);

	/* Print mms and sms messages in the order they were received */
	for (;;)
		if (mms == NULL) {
			if (sms == NULL)
				break; /* Done */
			else {
				text_write_sms(ctx, fp, sms);
				sms = SIMPLEQ_NEXT(sms, entries);
			}
		} else {
			if (sms == NULL || mms->date_recv < sms->date_recv) {
				text_write_mms(ctx, fp, mms);
				mms = SIMPLEQ_NEXT(mms, entries);
			} else {
				text_write_sms(ctx, fp, sms);
				sms = SIMPLEQ_NEXT(sms, entries);
			}
		}

	sbk_free_mms_list(mmslst);
	sbk_free_sms_list(smslst);

	if (fp != stdout)
		fclose(fp);

	return 0;
}

int
cmd_messages(int argc, char **argv)
{
	struct sbk_ctx	*ctx;
	char		*passfile, passphr[128], *outfile;
	int		 c, ret;

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
		outfile = NULL;
		break;
	case 2:
		outfile = argv[1];
		if (unveil(outfile, "wc") == -1)
			err(1, "unveil");
		break;
	default:
		goto usage;
	}

	if (passfile != NULL && unveil(passfile, "r") == -1)
		err(1, "unveil");

	if (unveil(argv[0], "r") == -1)
		err(1, "unveil");

	if (pledge("stdio rpath wpath cpath", NULL) == -1)
		err(1, "pledge");

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
	ret = text_write_messages(ctx, outfile);
	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return (ret == 0) ? 0 : 1;

usage:
	usage("messages", "[-p passfile] backup [file]");
}
