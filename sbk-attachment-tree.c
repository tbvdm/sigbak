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

static int sbk_cmp_attachment_entries(struct sbk_attachment_entry *,
    struct sbk_attachment_entry *);

RB_GENERATE_STATIC(sbk_attachment_tree, sbk_attachment_entry, entries,
    sbk_cmp_attachment_entries)

void
sbk_free_attachment_tree(struct sbk_ctx *ctx)
{
	struct sbk_attachment_entry *entry;

	while ((entry = RB_ROOT(&ctx->attachments)) != NULL) {
		RB_REMOVE(sbk_attachment_tree, &ctx->attachments, entry);
		sbk_free_file(entry->file);
		free(entry);
	}
}

static int
sbk_cmp_attachment_entries(struct sbk_attachment_entry *a,
    struct sbk_attachment_entry *b)
{
	if (a->id.row_id < b->id.row_id)
		return -1;

	if (a->id.row_id > b->id.row_id)
		return 1;

	return (a->id.unique_id < b->id.unique_id) ? -1 :
	    (a->id.unique_id > b->id.unique_id);
}

int
sbk_insert_attachment_entry(struct sbk_ctx *ctx, Signal__BackupFrame *frm,
    struct sbk_file *file)
{
	struct sbk_attachment_entry *entry;

	if (!frm->attachment->has_rowid)
		goto invalid;

	if (!frm->attachment->has_attachmentid) {
		if (ctx->db_version <
		    SBK_DB_VERSION_REMOVE_ATTACHMENT_UNIQUE_ID)
			goto invalid;
		frm->attachment->attachmentid = 0;
	}

	if ((entry = malloc(sizeof *entry)) == NULL) {
		warn(NULL);
		sbk_free_file(file);
		return -1;
	}

	entry->id.row_id = frm->attachment->rowid;
	entry->id.unique_id = frm->attachment->attachmentid;
	entry->file = file;
	RB_INSERT(sbk_attachment_tree, &ctx->attachments, entry);
	return 0;

invalid:
	warnx("Invalid attachment frame");
	sbk_free_file(file);
	return -1;
}

struct sbk_file *
sbk_get_attachment_file(struct sbk_ctx *ctx,
    const struct sbk_attachment_id *id)
{
	struct sbk_attachment_entry find, *result;

	find.id = *id;
	result = RB_FIND(sbk_attachment_tree, &ctx->attachments, &find);
	return (result != NULL) ? result->file : NULL;
}
