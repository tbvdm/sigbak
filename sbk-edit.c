/*
 * Copyright (c) 2024 Tim van der Molen <tim@kariliq.nl>
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

#include <err.h>
#include <stdlib.h>

#include "sbk-internal.h"

#define SBK_QUERY							\
	"SELECT "							\
	"_id, "								\
	"date_sent, "							\
	"date_received, "						\
	"body, "							\
	"quote_id, "							\
	"quote_author, "						\
	"quote_body, "							\
	"quote_mentions, "						\
	"revision_number "						\
	"FROM message "							\
	"WHERE _id = ?1 OR latest_revision_id = ?1 "			\
	"ORDER BY _id"

#define SBK_COLUMN__ID			0
#define SBK_COLUMN_DATE_SENT		1
#define SBK_COLUMN_DATE_RECEIVED	2
#define SBK_COLUMN_BODY			3
#define SBK_COLUMN_QUOTE_ID		4
#define SBK_COLUMN_QUOTE_AUTHOR		5
#define SBK_COLUMN_QUOTE_BODY		6
#define SBK_COLUMN_QUOTE_MENTIONS	7
#define SBK_COLUMN_REVISION_NUMBER	8

static void
sbk_free_edit(struct sbk_edit *edit)
{
	if (edit != NULL) {
		free(edit->text);
		sbk_free_attachment_list(edit->attachments);
		sbk_free_mention_list(edit->mentions);
		sbk_free_quote(edit->quote);
		free(edit);
	}
}

void
sbk_free_edit_list(struct sbk_edit_list *lst)
{
	struct sbk_edit *edit;

	if (lst != NULL) {
		while ((edit = TAILQ_FIRST(lst)) != NULL) {
			TAILQ_REMOVE(lst, edit, entries);
			sbk_free_edit(edit);
		}
		free(lst);
	}
}

static int
sbk_get_quote_for_edit(struct sbk_ctx *ctx, struct sbk_edit *edit,
    sqlite3_stmt *stm)
{
	return sbk_get_quote(ctx, &edit->quote, stm, SBK_COLUMN_QUOTE_ID,
	    SBK_COLUMN_QUOTE_AUTHOR, SBK_COLUMN_QUOTE_BODY,
	    SBK_COLUMN_QUOTE_MENTIONS, &edit->id);
}

static struct sbk_edit *
sbk_get_edit(struct sbk_ctx *ctx, sqlite3_stmt *stm)
{
	struct sbk_edit *edit;

	if ((edit = calloc(1, sizeof *edit)) == NULL) {
		warn(NULL);
		return NULL;
	}

	if (sbk_sqlite_column_text_copy(ctx, &edit->text, stm, SBK_COLUMN_BODY)
	    == -1)
		goto error;

	edit->id.table = SBK_SINGLE_TABLE;
	edit->id.row_id = sqlite3_column_int(stm, SBK_COLUMN__ID);
	edit->revision = sqlite3_column_int(stm, SBK_COLUMN_REVISION_NUMBER);
	edit->time_sent = sqlite3_column_int64(stm, SBK_COLUMN_DATE_SENT);
	edit->time_recv = sqlite3_column_int64(stm, SBK_COLUMN_DATE_RECEIVED);

	if (sbk_get_attachments_for_edit(ctx, edit) == -1)
		goto error;

	if (sbk_get_long_message(ctx, &edit->text, &edit->attachments) == -1)
		goto error;

	if (sbk_get_mentions_for_edit(ctx, edit) == -1)
		goto error;

	if (sbk_insert_mentions(&edit->text, edit->mentions) == -1) {
		warnx("Cannot insert mentions in edit");
		goto error;
	}

	if (sbk_get_quote_for_edit(ctx, edit, stm) == -1) {
		warnx("Cannot get quote for edit");
		goto error;
	}

	return edit;

error:
	sbk_free_edit(edit);
	return NULL;
}

int
sbk_get_edits(struct sbk_ctx *ctx, struct sbk_message *msg)
{
	struct sbk_edit	*edit;
	sqlite3_stmt	*stm;
	int		 ret;

	if (sbk_sqlite_prepare(ctx, &stm, SBK_QUERY) == -1)
		return -1;

	if (sbk_sqlite_bind_int(ctx, stm, 1, msg->id.row_id) == -1)
		goto error;

	if ((msg->edits = malloc(sizeof *msg->edits)) == NULL) {
		warn(NULL);
		goto error;
	}

	TAILQ_INIT(msg->edits);

	while ((ret = sbk_sqlite_step(ctx, stm)) == SQLITE_ROW) {
		if ((edit = sbk_get_edit(ctx, stm)) == NULL)
			goto error;
		TAILQ_INSERT_TAIL(msg->edits, edit, entries);
		msg->nedits++;
	}

	if (ret != SQLITE_DONE)
		goto error;

	/* Set times from the original message */
	if ((edit = TAILQ_FIRST(msg->edits)) != NULL) {
		msg->time_sent = edit->time_sent;
		msg->time_recv = edit->time_recv;
	}

	sqlite3_finalize(stm);
	return 0;

error:
	sbk_free_edit_list(msg->edits);
	msg->edits = NULL;
	sqlite3_finalize(stm);
	return -1;
}
