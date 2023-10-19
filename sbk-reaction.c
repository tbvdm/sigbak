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
#include <string.h>

#include "sbk-internal.h"

#define SBK_SELECT							\
	"SELECT "							\
	"author_id, "							\
	"emoji, "							\
	"date_sent, "							\
	"date_received "						\
	"FROM reaction "

/* For database versions < SINGLE_MESSAGE_TABLE_MIGRATION */
#define SBK_WHERE_1							\
	"WHERE message_id = ? AND is_mms = ? "

/* For database versions >= SINGLE_MESSAGE_TABLE_MIGRATION */
#define SBK_WHERE_2							\
	"WHERE message_id = ? "

#define SBK_ORDER							\
	"ORDER BY date_sent"

/* For database versions < SINGLE_MESSAGE_TABLE_MIGRATION */
#define SBK_QUERY_1							\
	SBK_SELECT							\
	SBK_WHERE_1							\
	SBK_ORDER

/* For database versions >= SINGLE_MESSAGE_TABLE_MIGRATION */
#define SBK_QUERY_2							\
	SBK_SELECT							\
	SBK_WHERE_2							\
	SBK_ORDER

#define SBK_COLUMN_AUTHOR_ID		0
#define SBK_COLUMN_EMOJI		1
#define SBK_COLUMN_DATE_SENT		2
#define SBK_COLUMN_DATE_RECEIVED	3

static void
sbk_free_reaction(struct sbk_reaction *rct)
{
	if (rct != NULL) {
		free(rct->emoji);
		free(rct);
	}
}

void
sbk_free_reaction_list(struct sbk_reaction_list *lst)
{
	struct sbk_reaction *rct;

	if (lst != NULL) {
		while ((rct = SIMPLEQ_FIRST(lst)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(lst, entries);
			sbk_free_reaction(rct);
		}
		free(lst);
	}
}

/*
 * For database versions >= REACTION_REFACTOR
 */

static struct sbk_reaction *
sbk_get_reaction(struct sbk_ctx *ctx, sqlite3_stmt *stm)
{
	struct sbk_reaction *rct;

	if ((rct = calloc(1, sizeof *rct)) == NULL) {
		warn(NULL);
		return NULL;
	}

	rct->recipient = sbk_get_recipient_from_column(ctx, stm,
	    SBK_COLUMN_AUTHOR_ID);
	if (rct->recipient == NULL)
		goto error;

	if (sbk_sqlite_column_text_copy(ctx, &rct->emoji, stm,
	    SBK_COLUMN_EMOJI) == -1)
		goto error;

	rct->time_sent = sqlite3_column_int64(stm, SBK_COLUMN_DATE_SENT);
	rct->time_recv = sqlite3_column_int64(stm, SBK_COLUMN_DATE_RECEIVED);

	return rct;

error:
	sbk_free_reaction(rct);
	return NULL;
}

static struct sbk_reaction_list *
sbk_get_reactions(struct sbk_ctx *ctx, sqlite3_stmt *stm)
{
	struct sbk_reaction_list	*lst;
	struct sbk_reaction		*rct;
	int				 ret;

	if ((lst = malloc(sizeof *lst)) == NULL) {
		warn(NULL);
		goto error;
	}

	SIMPLEQ_INIT(lst);

	while ((ret = sbk_sqlite_step(ctx, stm)) == SQLITE_ROW) {
		if ((rct = sbk_get_reaction(ctx, stm)) == NULL)
			goto error;
		SIMPLEQ_INSERT_TAIL(lst, rct, entries);
	}

	if (ret != SQLITE_DONE)
		goto error;

	sqlite3_finalize(stm);
	return lst;

error:
	sbk_free_reaction_list(lst);
	sqlite3_finalize(stm);
	return NULL;
}

int
sbk_get_reactions_from_table(struct sbk_ctx *ctx, struct sbk_message *msg)
{
	sqlite3_stmt	*stm;
	const char	*query;

	if (ctx->db_version < SBK_DB_VERSION_SINGLE_MESSAGE_TABLE_MIGRATION)
		query = SBK_QUERY_1;
	else
		query = SBK_QUERY_2;

	if (sbk_sqlite_prepare(ctx, &stm, query) == -1)
		return -1;

	if (sbk_sqlite_bind_int(ctx, stm, 1, msg->id.rowid) == -1) {
		sqlite3_finalize(stm);
		return -1;
	}

	if (ctx->db_version < SBK_DB_VERSION_SINGLE_MESSAGE_TABLE_MIGRATION)
		if (sbk_sqlite_bind_int(ctx, stm, 2,
		    msg->id.type == SBK_MESSAGE_MMS) == -1) {
			sqlite3_finalize(stm);
			return -1;
		}

	if ((msg->reactions = sbk_get_reactions(ctx, stm)) == NULL)
		return -1;

	return 0;
}

/*
 * For database versions < REACTION_REFACTOR
 */

static Signal__ReactionList *
sbk_unpack_reaction_list_message(const void *buf, size_t len)
{
	Signal__ReactionList *msg;

	if ((msg = signal__reaction_list__unpack(NULL, len, buf)) == NULL)
		warnx("Cannot unpack reaction list");

	return msg;
}

static void
sbk_free_reaction_list_message(Signal__ReactionList *msg)
{
	if (msg != NULL)
		signal__reaction_list__free_unpacked(msg, NULL);
}

int
sbk_get_reactions_from_column(struct sbk_ctx *ctx,
    struct sbk_reaction_list **lst, sqlite3_stmt *stm, int idx)
{
	struct sbk_reaction	*rct;
	struct sbk_recipient_id	 id;
	Signal__ReactionList	*msg;
	const void		*blob;
	size_t			 i;
	int			 len;

	*lst = NULL;

	if (sqlite3_column_type(stm, idx) != SQLITE_BLOB) {
		/* No reactions */
		return 0;
	}

	if ((blob = sqlite3_column_blob(stm, idx)) == NULL) {
		sbk_sqlite_warn(ctx, "Cannot get reactions column");
		return -1;
	}

	if ((len = sqlite3_column_bytes(stm, idx)) < 0) {
		sbk_sqlite_warn(ctx, "Cannot get reactions size");
		return -1;
	}

	if ((msg = sbk_unpack_reaction_list_message(blob, len)) == NULL)
		return -1;

	if ((*lst = malloc(sizeof **lst)) == NULL) {
		warn(NULL);
		goto error1;
	}

	SIMPLEQ_INIT(*lst);

	for (i = 0; i < msg->n_reactions; i++) {
		if ((rct = malloc(sizeof *rct)) == NULL) {
			warn(NULL);
			goto error1;
		}

		id.new = msg->reactions[i]->author;
		id.old = NULL;

		if ((rct->recipient = sbk_get_recipient(ctx, &id)) == NULL)
			goto error2;

		if ((rct->emoji = strdup(msg->reactions[i]->emoji)) == NULL) {
			warn(NULL);
			goto error2;
		}

		rct->time_sent = msg->reactions[i]->senttime;
		rct->time_recv = msg->reactions[i]->receivedtime;
		SIMPLEQ_INSERT_TAIL(*lst, rct, entries);
	}

	sbk_free_reaction_list_message(msg);
	return 0;

error2:
	free(rct);

error1:
	sbk_free_reaction_list(*lst);
	sbk_free_reaction_list_message(msg);
	*lst = NULL;
	return -1;
}
