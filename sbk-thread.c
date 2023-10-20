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
#include <stdlib.h>

#include "sbk-internal.h"

/* For database versions < THREAD_AUTOINCREMENT */
#define SBK_QUERY_1							\
	"SELECT "							\
	"_id, "								\
	"date, "							\
	"message_count, "		/* meaningful_messages */	\
	"recipient_ids "		/* recipient_id */		\
	"FROM thread "							\
	"ORDER BY _id"

/*
 * For database versions
 * [THREAD_AUTOINCREMENT, THREAD_AND_MESSAGE_FOREIGN_KEYS)
 */
#define SBK_QUERY_2							\
	"SELECT "							\
	"_id, "								\
	"date, "							\
	"message_count, "		/* meaningful_messages */	\
	"thread_recipient_id "		/* recipient_id */		\
	"FROM thread "							\
	"ORDER BY _id"

/* For database versions >= THREAD_AND_MESSAGE_FOREIGN_KEYS */
#define SBK_QUERY_3							\
	"SELECT "							\
	"_id, "								\
	"date, "							\
	"meaningful_messages, "						\
	"recipient_id "							\
	"FROM thread "							\
	"ORDER BY _id"

#define SBK_COLUMN__ID			0
#define SBK_COLUMN_DATE			1
#define SBK_COLUMN_MEANINGFUL_MESSAGES	2
#define SBK_COLUMN_RECIPIENT_ID		3

void
sbk_free_thread_list(struct sbk_thread_list *lst)
{
	struct sbk_thread *thd;

	if (lst != NULL) {
		while ((thd = SIMPLEQ_FIRST(lst)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(lst, entries);
			free(thd);
		}
		free(lst);
	}
}

struct sbk_thread_list *
sbk_get_threads(struct sbk_ctx *ctx)
{
	struct sbk_thread_list	*lst;
	struct sbk_thread	*thd;
	sqlite3_stmt		*stm;
	const char		*query;
	int			 ret;

	if (sbk_create_database(ctx) == -1)
		return NULL;

	if ((lst = malloc(sizeof *lst)) == NULL) {
		warn(NULL);
		return NULL;
	}

	SIMPLEQ_INIT(lst);

	if (ctx->db_version < SBK_DB_VERSION_THREAD_AUTOINCREMENT)
		query = SBK_QUERY_1;
	else if (ctx->db_version <
	    SBK_DB_VERSION_THREAD_AND_MESSAGE_FOREIGN_KEYS)
		query = SBK_QUERY_2;
	else
		query = SBK_QUERY_3;

	if (sbk_sqlite_prepare(ctx, &stm, query) == -1)
		goto error;

	while ((ret = sbk_sqlite_step(ctx, stm)) == SQLITE_ROW) {
		if ((thd = malloc(sizeof *thd)) == NULL) {
			warn(NULL);
			goto error;
		}

		thd->recipient = sbk_get_recipient_from_id_from_column(ctx,
		    stm, SBK_COLUMN_RECIPIENT_ID);
		if (thd->recipient == NULL) {
			free(thd);
			goto error;
		}

		thd->id = sqlite3_column_int64(stm, SBK_COLUMN__ID);
		thd->date = sqlite3_column_int64(stm, SBK_COLUMN_DATE);
		thd->nmessages = sqlite3_column_int64(stm,
		    SBK_COLUMN_MEANINGFUL_MESSAGES);
		SIMPLEQ_INSERT_TAIL(lst, thd, entries);
	}

	if (ret != SQLITE_DONE)
		goto error;

	sqlite3_finalize(stm);
	return lst;

error:
	sbk_free_thread_list(lst);
	sqlite3_finalize(stm);
	return NULL;
}
