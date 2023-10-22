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

#include <err.h>
#include <inttypes.h>
#include <stdlib.h>

#include "sbk-internal.h"

/* For database versions < QUOTED_REPLIES */
#define SBK_SELECT_1							\
	"SELECT "							\
	"p._id, "							\
	"p.ct, "							\
	"p.pending_push, "						\
	"p.data_size, "							\
	"p.file_name, "							\
	"p.unique_id, "							\
	"m.date, "							\
	"m.date_received, "						\
	"0 AS quote, "							\
	"NULL AS latest_revision_id "					\
	"FROM part AS p "						\
	"LEFT JOIN mms AS m "						\
	"ON p.mid = m._id "

/* For database versions [QUOTED_REPLIES, THREAD_AND_MESSAGE_FOREIGN_KEYS) */
#define SBK_SELECT_2							\
	"SELECT "							\
	"p._id, "							\
	"p.ct, "							\
	"p.pending_push, "						\
	"p.data_size, "							\
	"p.file_name, "							\
	"p.unique_id, "							\
	"m.date, "							\
	"m.date_received, "						\
	"NULL AS latest_revision_id "					\
	"FROM part AS p "						\
	"LEFT JOIN mms AS m "						\
	"ON p.mid = m._id "

/*
 * For database versions [THREAD_AND_MESSAGE_FOREIGN_KEYS,
 * REACTION_FOREIGN_KEY_MIGRATION)
 */
#define SBK_SELECT_3							\
	"SELECT "							\
	"p._id, "							\
	"p.ct, "							\
	"p.pending_push, "						\
	"p.data_size, "							\
	"p.file_name, "							\
	"p.unique_id, "							\
	"m.date_sent, "							\
	"m.date_received, "						\
	"NULL AS latest_revision_id "					\
	"FROM part AS p "						\
	"LEFT JOIN mms AS m "						\
	"ON p.mid = m._id "

/*
 * For database versions [REACTION_FOREIGN_KEY_MIGRATION,
 * MESSAGE_RECIPIENTS_AND_EDIT_MESSAGE_MIGRATION)
 */
#define SBK_SELECT_4							\
	"SELECT "							\
	"p._id, "							\
	"p.ct, "							\
	"p.pending_push, "						\
	"p.data_size, "							\
	"p.file_name, "							\
	"p.unique_id, "							\
	"m.date_sent, "							\
	"m.date_received, "						\
	"NULL AS latest_revision_id "					\
	"FROM part AS p "						\
	"LEFT JOIN message AS m "					\
	"ON p.mid = m._id "

/* For database versions >= MESSAGE_RECIPIENTS_AND_EDIT_MESSAGE_MIGRATION */
#define SBK_SELECT_5							\
	"SELECT "							\
	"p._id, "							\
	"p.ct, "							\
	"p.pending_push, "						\
	"p.data_size, "							\
	"p.file_name, "							\
	"p.unique_id, "							\
	"m.date_sent, "							\
	"m.date_received "						\
	"FROM part AS p "						\
	"LEFT JOIN message AS m "					\
	"ON p.mid = m._id "

/* For database versions < REACTION_FOREIGN_KEY_MIGRATION */
#define SBK_WHERE_THREAD_1						\
	"WHERE p.mid IN (SELECT _id FROM mms WHERE thread_id = ?) "	\
	"AND latest_revision_id IS NULL "

/* For database versions >= REACTION_FOREIGN_KEY_MIGRATION */
#define SBK_WHERE_THREAD_2						\
	"WHERE p.mid IN (SELECT _id FROM message WHERE thread_id = ?) "	\
	"AND latest_revision_id IS NULL "

#define SBK_WHERE_MESSAGE						\
	"WHERE p.mid = ? AND quote = 0 "

#define SBK_WHERE_QUOTE							\
	"WHERE p.mid = ? AND quote = 1 "

#define SBK_ORDER							\
	"ORDER BY p.unique_id, p._id"

/* For database versions < THREAD_AND_MESSAGE_FOREIGN_KEYS */
#define SBK_QUERY_THREAD_1						\
	SBK_SELECT_2							\
	SBK_WHERE_THREAD_1						\
	SBK_ORDER

/*
 * For database versions [THREAD_AND_MESSAGE_FOREIGN_KEYS,
 * REACTION_FOREIGN_KEY_MIGRATION)
 */
#define SBK_QUERY_THREAD_2						\
	SBK_SELECT_3							\
	SBK_WHERE_THREAD_1						\
	SBK_ORDER

/*
 * For database versions [REACTION_FOREIGN_KEY_MIGRATION
 * MESSAGE_RECIPIENTS_AND_EDIT_MESSAGE_MIGRATION)
 */
#define SBK_QUERY_THREAD_3						\
	SBK_SELECT_4							\
	SBK_WHERE_THREAD_2						\
	SBK_ORDER

/* For database versions >= MESSAGE_RECIPIENTS_AND_EDIT_MESSAGE_MIGRATION */
#define SBK_QUERY_THREAD_4						\
	SBK_SELECT_5							\
	SBK_WHERE_THREAD_2						\
	SBK_ORDER

/* For database versions < QUOTED_REPLIES */
#define SBK_QUERY_MESSAGE_1						\
	SBK_SELECT_1							\
	SBK_WHERE_MESSAGE						\
	SBK_ORDER

/* For database versions [QUOTED_REPLIES, THREAD_AND_MESSAGE_FOREIGN_KEYS) */
#define SBK_QUERY_MESSAGE_2						\
	SBK_SELECT_2							\
	SBK_WHERE_MESSAGE						\
	SBK_ORDER

/*
 * For database versions [THREAD_AND_MESSAGE_FOREIGN_KEYS,
 * REACTION_FOREIGN_KEY_MIGRATION)
 */
#define SBK_QUERY_MESSAGE_3						\
	SBK_SELECT_3							\
	SBK_WHERE_MESSAGE						\
	SBK_ORDER

/* For database versions >= REACTION_FOREIGN_KEY_MIGRATION */
#define SBK_QUERY_MESSAGE_4						\
	SBK_SELECT_4							\
	SBK_WHERE_MESSAGE						\
	SBK_ORDER

/* For database versions < THREAD_AND_MESSAGE_FOREIGN_KEYS */
#define SBK_QUERY_QUOTE_1						\
	SBK_SELECT_2							\
	SBK_WHERE_QUOTE							\
	SBK_ORDER

/*
 * For database versions [THREAD_AND_MESSAGE_FOREIGN_KEYS,
 * REACTION_FOREIGN_KEY_MIGRATION)
 */
#define SBK_QUERY_QUOTE_2						\
	SBK_SELECT_3							\
	SBK_WHERE_QUOTE							\
	SBK_ORDER

/* For database versions >= REACTION_FOREIGN_KEY_MIGRATION */
#define SBK_QUERY_QUOTE_3						\
	SBK_SELECT_4							\
	SBK_WHERE_QUOTE							\
	SBK_ORDER

#define SBK_COLUMN__ID			0
#define SBK_COLUMN_CT			1
#define SBK_COLUMN_PENDING_PUSH		2
#define SBK_COLUMN_DATA_SIZE		3
#define SBK_COLUMN_FILE_NAME		4
#define SBK_COLUMN_UNIQUE_ID		5
#define SBK_COLUMN_DATE_SENT		6
#define SBK_COLUMN_DATE_RECEIVED	7

void
sbk_free_attachment(struct sbk_attachment *att)
{
	if (att != NULL) {
		free(att->filename);
		free(att->content_type);
		free(att);
	}
}

void
sbk_free_attachment_list(struct sbk_attachment_list *lst)
{
	struct sbk_attachment *att;

	if (lst != NULL) {
		while ((att = TAILQ_FIRST(lst)) != NULL) {
			TAILQ_REMOVE(lst, att, entries);
			sbk_free_attachment(att);
		}
		free(lst);
	}
}

static struct sbk_attachment *
sbk_get_attachment(struct sbk_ctx *ctx, sqlite3_stmt *stm)
{
	struct sbk_attachment *att;

	if ((att = calloc(1, sizeof *att)) == NULL) {
		warn(NULL);
		return NULL;
	}

	if (sbk_sqlite_column_text_copy(ctx, &att->filename, stm,
	    SBK_COLUMN_FILE_NAME) == -1)
		goto error;

	if (sbk_sqlite_column_text_copy(ctx, &att->content_type, stm,
	    SBK_COLUMN_CT) == -1)
		goto error;

	att->rowid = sqlite3_column_int64(stm, SBK_COLUMN__ID);
	att->attachmentid = sqlite3_column_int64(stm, SBK_COLUMN_UNIQUE_ID);
	att->status = sqlite3_column_int(stm, SBK_COLUMN_PENDING_PUSH);
	att->size = sqlite3_column_int64(stm, SBK_COLUMN_DATA_SIZE);
	att->time_sent = sqlite3_column_int64(stm, SBK_COLUMN_DATE_SENT);
	att->time_recv = sqlite3_column_int64(stm, SBK_COLUMN_DATE_RECEIVED);
	att->file = sbk_get_attachment_file(ctx, att->rowid,
	    att->attachmentid);

	if (att->file == NULL)
		warnx("Attachment %" PRId64 "-%" PRId64 " not available in "
		    "backup", att->rowid, att->attachmentid);
	else if (att->size != att->file->len)
		warnx("Attachment %" PRId64 "-%" PRId64 " has inconsistent "
		    "size", att->rowid, att->attachmentid);

	return att;

error:
	sbk_free_attachment(att);
	return NULL;
}

static struct sbk_attachment_list *
sbk_get_attachments(struct sbk_ctx *ctx, sqlite3_stmt *stm)
{
	struct sbk_attachment_list	*lst;
	struct sbk_attachment		*att;
	int				 ret;

	if ((lst = malloc(sizeof *lst)) == NULL) {
		warn(NULL);
		goto error;
	}

	TAILQ_INIT(lst);

	while ((ret = sbk_sqlite_step(ctx, stm)) == SQLITE_ROW) {
		if ((att = sbk_get_attachment(ctx, stm)) == NULL)
			goto error;
		TAILQ_INSERT_TAIL(lst, att, entries);
	}

	if (ret != SQLITE_DONE)
		goto error;

	sqlite3_finalize(stm);
	return lst;

error:
	sbk_free_attachment_list(lst);
	sqlite3_finalize(stm);
	return NULL;
}

struct sbk_attachment_list *
sbk_get_attachments_for_thread(struct sbk_ctx *ctx, struct sbk_thread *thd)
{
	sqlite3_stmt	*stm;
	const char	*query;

	if (sbk_create_database(ctx) == -1)
		return NULL;

	if (ctx->db_version >=
	    SBK_DB_VERSION_MESSAGE_RECIPIENTS_AND_EDIT_MESSAGE_MIGRATION)
		query = SBK_QUERY_THREAD_4;
	else if (ctx->db_version >=
	    SBK_DB_VERSION_REACTION_FOREIGN_KEY_MIGRATION)
		query = SBK_QUERY_THREAD_3;
	else if (ctx->db_version >=
	    SBK_DB_VERSION_THREAD_AND_MESSAGE_FOREIGN_KEYS)
		query = SBK_QUERY_THREAD_2;
	else
		query = SBK_QUERY_THREAD_1;

	if (sbk_sqlite_prepare(ctx, &stm, query) == -1)
		return NULL;

	if (sbk_sqlite_bind_int(ctx, stm, 1, thd->id) == -1) {
		sqlite3_finalize(stm);
		return NULL;
	}

	return sbk_get_attachments(ctx, stm);
}

int
sbk_get_attachments_for_message(struct sbk_ctx *ctx, struct sbk_message *msg)
{
	sqlite3_stmt	*stm;
	const char	*query;

	if (msg->id.type != SBK_MESSAGE_MMS)
		return 0;

	if (ctx->db_version >= SBK_DB_VERSION_REACTION_FOREIGN_KEY_MIGRATION)
		query = SBK_QUERY_MESSAGE_4;
	else if (ctx->db_version >=
	    SBK_DB_VERSION_THREAD_AND_MESSAGE_FOREIGN_KEYS)
		query = SBK_QUERY_MESSAGE_3;
	else if (ctx->db_version >= SBK_DB_VERSION_QUOTED_REPLIES)
		query = SBK_QUERY_MESSAGE_2;
	else
		query = SBK_QUERY_MESSAGE_1;

	if (sbk_sqlite_prepare(ctx, &stm, query) == -1)
		return -1;

	if (sbk_sqlite_bind_int(ctx, stm, 1, msg->id.rowid) == -1) {
		sqlite3_finalize(stm);
		return -1;
	}

	if ((msg->attachments = sbk_get_attachments(ctx, stm)) == NULL)
		return -1;

	return 0;
}

int
sbk_get_attachments_for_quote(struct sbk_ctx *ctx, struct sbk_quote *qte,
    struct sbk_message_id *mid)
{
	sqlite3_stmt	*stm;
	const char	*query;

	if (ctx->db_version >= SBK_DB_VERSION_REACTION_FOREIGN_KEY_MIGRATION)
		query = SBK_QUERY_QUOTE_3;
	else if (ctx->db_version >=
	    SBK_DB_VERSION_THREAD_AND_MESSAGE_FOREIGN_KEYS)
		query = SBK_QUERY_QUOTE_2;
	else
		query = SBK_QUERY_QUOTE_1;

	if (sbk_sqlite_prepare(ctx, &stm, query) == -1)
		return -1;

	if (sbk_sqlite_bind_int(ctx, stm, 1, mid->rowid) == -1) {
		sqlite3_finalize(stm);
		return -1;
	}

	if ((qte->attachments = sbk_get_attachments(ctx, stm)) == NULL)
		return -1;

	return 0;
}
