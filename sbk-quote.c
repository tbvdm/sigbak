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

#include "config.h"

#include <stdlib.h>

#include "sbk-internal.h"

void
sbk_free_quote(struct sbk_quote *qte)
{
	if (qte != NULL) {
		free(qte->text);
		sbk_free_attachment_list(qte->attachments);
		sbk_free_mention_list(qte->mentions);
		free(qte);
	}
}

int
sbk_get_quote(struct sbk_ctx *ctx, struct sbk_quote **qtep, sqlite3_stmt *stm,
    int id_idx, int author_idx, int body_idx, int mentions_idx,
    struct sbk_message_id *mid)
{
	struct sbk_quote *qte;

	if (sqlite3_column_int64(stm, id_idx) == 0 &&
	    sqlite3_column_int64(stm, author_idx) == 0) {
		/* No quote */
		return 0;
	}

	if ((qte = calloc(1, sizeof *qte)) == NULL) {
		warn(NULL);
		return -1;
	}

	qte->id = sqlite3_column_int64(stm, id_idx);

	qte->recipient = sbk_get_recipient_from_id_from_column(ctx, stm,
	    author_idx);
	if (qte->recipient == NULL)
		goto error;

	if (sbk_sqlite_column_text_copy(ctx, &qte->text, stm, body_idx) == -1)
		goto error;

	if (sbk_get_attachments_for_quote(ctx, qte, mid) == -1)
		goto error;

	if (sbk_get_long_message(ctx, &qte->text, &qte->attachments) == -1)
		goto error;

	if (sbk_get_mentions_for_quote(ctx, &qte->mentions, stm, mentions_idx)
	    == -1) {
		warnx("Cannot get mentions for quote");
		goto error;
	}

	if (sbk_insert_mentions(&qte->text, qte->mentions) == -1) {
		warnx("Cannot insert mentions in quote");
		goto error;
	}

	*qtep = qte;
	return 0;

error:
	sbk_free_quote(qte);
	return -1;
}
