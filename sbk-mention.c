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

void
sbk_free_mention_list(struct sbk_mention_list *lst)
{
	struct sbk_mention *mnt;

	if (lst != NULL) {
		while ((mnt = SIMPLEQ_FIRST(lst)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(lst, entries);
			free(mnt);
		}
		free(lst);
	}
}

#define SBK_MENTIONS_QUERY						\
	"SELECT "							\
	"recipient_id "							\
	"FROM mention "							\
	"WHERE message_id = ? "						\
	"ORDER BY range_start"

static struct sbk_mention *
sbk_get_mention(struct sbk_ctx *ctx, sqlite3_stmt *stm)
{
	struct sbk_mention *mnt;

	if ((mnt = malloc(sizeof *mnt)) == NULL) {
		warn(NULL);
		return NULL;
	}

	mnt->recipient = sbk_get_recipient_from_column(ctx, stm, 0);
	if (mnt->recipient == NULL) {
		free(mnt);
		return NULL;
	}

	return mnt;
}

int
sbk_get_mentions(struct sbk_ctx *ctx, struct sbk_message *msg)
{
	struct sbk_mention	*mnt;
	sqlite3_stmt		*stm;
	int			 ret;

	msg->mentions = NULL;

	if (msg->id.type != SBK_MESSAGE_MMS ||
	    ctx->db_version < SBK_DB_VERSION_MENTIONS)
		return 0;

	if (sbk_sqlite_prepare(ctx, &stm, SBK_MENTIONS_QUERY) == -1)
		return -1;

	if (sbk_sqlite_bind_int(ctx, stm, 1, msg->id.rowid) == -1)
		goto error;

	if ((msg->mentions = malloc(sizeof *msg->mentions)) == NULL) {
		warn(NULL);
		goto error;
	}

	SIMPLEQ_INIT(msg->mentions);

	while ((ret = sbk_sqlite_step(ctx, stm)) == SQLITE_ROW) {
		if ((mnt = sbk_get_mention(ctx, stm)) == NULL)
			goto error;
		SIMPLEQ_INSERT_TAIL(msg->mentions, mnt, entries);
	}

	if (ret != SQLITE_DONE)
		goto error;

	sqlite3_finalize(stm);
	return 0;

error:
	sbk_free_mention_list(msg->mentions);
	msg->mentions = NULL;
	sqlite3_finalize(stm);
	return -1;
}

int
sbk_insert_mentions(char **text, struct sbk_mention_list *lst,
    struct sbk_message_id *mid)
{
	struct sbk_mention *mnt;
	char		*newtext, *newtextpos, *placeholderpos, *textpos;
	const char	*name;
	size_t		 copylen, newtextlen, placeholderlen, prefixlen;

	if (lst == NULL || SIMPLEQ_EMPTY(lst))
		return 0;

	newtext = NULL;
	placeholderlen = strlen(SBK_MENTION_PLACEHOLDER);
	prefixlen = strlen(SBK_MENTION_PREFIX);

	/* Calculate length of new text */
	newtextlen = strlen(*text);
	SIMPLEQ_FOREACH(mnt, lst, entries) {
		if (newtextlen < placeholderlen)
			goto error;
		name = sbk_get_recipient_display_name(mnt->recipient);
		/* Subtract placeholder, add mention */
		newtextlen = newtextlen - placeholderlen + prefixlen +
		    strlen(name);
	}

	if ((newtext = malloc(newtextlen + 1)) == NULL) {
		warn(NULL);
		return -1;
	}

	textpos = *text;
	newtextpos = newtext;

	/* Write new text, replacing placeholders with mentions */
	SIMPLEQ_FOREACH(mnt, lst, entries) {
		placeholderpos = strstr(textpos, SBK_MENTION_PLACEHOLDER);
		if (placeholderpos == NULL)
			goto error;

		copylen = placeholderpos - textpos;
		memcpy(newtextpos, textpos, copylen);
		textpos += copylen + placeholderlen;
		newtextpos += copylen;

		memcpy(newtextpos, SBK_MENTION_PREFIX, prefixlen);
		newtextpos += prefixlen;

		name = sbk_get_recipient_display_name(mnt->recipient);
		copylen = strlen(name);
		memcpy(newtextpos, name, copylen);
		newtextpos += copylen;
	}

	/* Sanity check: there should be no placeholders left */
	if (strstr(textpos, SBK_MENTION_PLACEHOLDER) != NULL)
		goto error;

	copylen = strlen(textpos);
	memcpy(newtextpos, textpos, copylen);
	newtextpos += copylen;
	*newtextpos = '\0';

	free(*text);
	*text = newtext;

	return 0;

error:
	warnx("Invalid mention in message %d-%d", mid->type, mid->rowid);
	free(newtext);
	return 0;
}

static Signal__BodyRangeList *
sbk_unpack_quote_mention_list_message(const void *buf, size_t len)
{
	Signal__BodyRangeList *msg;

	if ((msg = signal__body_range_list__unpack(NULL, len, buf)) == NULL)
		warnx("Cannot unpack quoted mention list");

	return msg;
}

static void
sbk_free_quote_mention_list_message(Signal__BodyRangeList *msg)
{
	if (msg != NULL)
		signal__body_range_list__free_unpacked(msg, NULL);
}

int
sbk_get_quote_mentions(struct sbk_ctx *ctx, struct sbk_mention_list **lst,
    sqlite3_stmt *stm, int idx, struct sbk_message_id *mid)
{
	Signal__BodyRangeList	*msg;
	struct sbk_mention	*mnt;
	struct sbk_recipient	*rcp;
	const void		*blob;
	size_t			 i;
	int			 len;

	*lst = NULL;

	if (sqlite3_column_type(stm, idx) != SQLITE_BLOB) {
		/* No mentions */
		return 0;
	}

	if ((blob = sqlite3_column_blob(stm, idx)) == NULL) {
		sbk_sqlite_warn(ctx, "Cannot get quoted mentions column");
		return -1;
	}

	if ((len = sqlite3_column_bytes(stm, idx)) < 0) {
		sbk_sqlite_warn(ctx, "Cannot get quoted mentions size");
		return -1;
	}

	if ((msg = sbk_unpack_quote_mention_list_message(blob, len)) == NULL)
		return -1;

	if ((*lst = malloc(sizeof **lst)) == NULL) {
		warn(NULL);
		goto error;
	}

	SIMPLEQ_INIT(*lst);

	for (i = 0; i < msg->n_ranges; i++) {
		if (msg->ranges[i]->associated_value_case !=
		    SIGNAL__BODY_RANGE_LIST__BODY_RANGE__ASSOCIATED_VALUE_MENTION_UUID)
			continue;

		if (msg->ranges[i]->mentionuuid == NULL) {
			warnx("Quoted mention without uuid in message %d-%d",
			    mid->type, mid->rowid);
			continue;
		}

		rcp = sbk_get_recipient_from_uuid(ctx,
		    msg->ranges[i]->mentionuuid);
		if (rcp == NULL)
			warnx("Cannot find recipient for quoted mention uuid "
			    "%s in message %d-%d", msg->ranges[i]->mentionuuid,
			    mid->type, mid->rowid);

		if ((mnt = malloc(sizeof *mnt)) == NULL) {
			warn(NULL);
			goto error;
		}

		mnt->recipient = rcp;
		SIMPLEQ_INSERT_TAIL(*lst, mnt, entries);
	}

	sbk_free_quote_mention_list_message(msg);
	return 0;

error:
	sbk_free_quote_mention_list_message(msg);
	sbk_free_mention_list(*lst);
	*lst = NULL;
	return -1;
}
