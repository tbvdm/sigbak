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

/* For database versions < RECIPIENT_IDS */
#define SBK_QUERY_1							\
	"SELECT "							\
	"r.recipient_ids, "						\
	"NULL, "			/* e164 */			\
	"NULL, "			/* aci */			\
	"NULL, "			/* email */			\
	"r.signal_profile_name, "	/* profile_given_name */	\
	"NULL, "			/* profile_family_name */	\
	"NULL, "			/* profile_joined_name */	\
	"r.system_display_name, "	/* system_joined_name */	\
	"r.system_phone_label, "					\
	"g.group_id, "							\
	"g.title "							\
	"FROM recipient_preferences AS r "				\
	"LEFT JOIN groups AS g "					\
	"ON r.recipient_ids = g.group_id"

/* For database versions [RECIPIENT_IDS, SPLIT_PROFILE_NAMES) */
#define SBK_QUERY_2							\
	"SELECT "							\
	"r._id, "							\
	"r.phone, "			/* e164 */			\
	"r.uuid, "			/* aci */			\
	"r.email, "							\
	"r.signal_profile_name, "	/* profile_given_name */	\
	"NULL, "			/* profile_family_name */	\
	"NULL, "			/* profile_joined_name */	\
	"r.system_display_name, "	/* system_joined_name */	\
	"r.system_phone_label, "					\
	"g.group_id, "							\
	"g.title "							\
	"FROM recipient AS r "						\
	"LEFT JOIN groups AS g "					\
	"ON r._id = g.recipient_id"

/* For database versions [SPLIT_PROFILE_NAMES, RESET_PNI_COLUMN) */
#define SBK_QUERY_3							\
	"SELECT "							\
	"r._id, "							\
	"r.phone, "			/* e164 */			\
	"r.uuid, "			/* aci */			\
	"r.email, "							\
	"r.signal_profile_name, "	/* profile_given_name */	\
	"r.profile_family_name, "					\
	"r.profile_joined_name, "					\
	"r.system_display_name, "	/* system_joined_name */	\
	"r.system_phone_label, "					\
	"g.group_id, "							\
	"g.title "							\
	"FROM recipient AS r "						\
	"LEFT JOIN groups AS g "					\
	"ON r._id = g.recipient_id"

/* For database versions [RESET_PNI_COLUMN, RECIPIENT_TABLE_VALIDATIONS) */
#define SBK_QUERY_4							\
	"SELECT "							\
	"r._id, "							\
	"r.phone, "			/* e164 */			\
	"r.aci, "							\
	"r.email, "							\
	"r.signal_profile_name, "	/* profile_given_name */	\
	"r.profile_family_name, "					\
	"r.profile_joined_name, "					\
	"r.system_display_name, "	/* system_joined_name */	\
	"r.system_phone_label, "					\
	"g.group_id, "							\
	"g.title "							\
	"FROM recipient AS r "						\
	"LEFT JOIN groups AS g "					\
	"ON r._id = g.recipient_id"

/* For database versions >= RECIPIENT_TABLE_VALIDATIONS */
#define SBK_QUERY_5							\
	"SELECT "							\
	"r._id, "							\
	"r.e164, "							\
	"r.aci, "							\
	"r.email, "							\
	"r.profile_given_name, "					\
	"r.profile_family_name, "					\
	"r.profile_joined_name, "					\
	"r.system_joined_name, "					\
	"r.system_phone_label, "					\
	"g.group_id, "							\
	"g.title "							\
	"FROM recipient AS r "						\
	"LEFT JOIN groups AS g "					\
	"ON r._id = g.recipient_id"

#define SBK_COLUMN__ID			0
#define SBK_COLUMN_E164			1
#define SBK_COLUMN_ACI			2
#define SBK_COLUMN_EMAIL		3
#define SBK_COLUMN_PROFILE_GIVEN_NAME	4
#define SBK_COLUMN_PROFILE_FAMILY_NAME	5
#define SBK_COLUMN_PROFILE_JOINED_NAME	6
#define SBK_COLUMN_SYSTEM_JOINED_NAME	7
#define SBK_COLUMN_SYSTEM_PHONE_LABEL	8
#define SBK_COLUMN_GROUP_ID		9
#define SBK_COLUMN_TITLE		10

static int sbk_cmp_recipient_entries(struct sbk_recipient_entry *,
    struct sbk_recipient_entry *);

RB_GENERATE_STATIC(sbk_recipient_tree, sbk_recipient_entry, entries,
    sbk_cmp_recipient_entries)

static void
sbk_free_recipient_entry(struct sbk_recipient_entry *ent)
{
	if (ent == NULL)
		return;

	switch (ent->recipient.type) {
	case SBK_CONTACT:
		if (ent->recipient.contact != NULL) {
			free(ent->recipient.contact->aci);
			free(ent->recipient.contact->phone);
			free(ent->recipient.contact->email);
			free(ent->recipient.contact->system_joined_name);
			free(ent->recipient.contact->system_phone_label);
			free(ent->recipient.contact->profile_given_name);
			free(ent->recipient.contact->profile_family_name);
			free(ent->recipient.contact->profile_joined_name);
			free(ent->recipient.contact);
		}
		break;
	case SBK_GROUP:
		if (ent->recipient.group != NULL) {
			free(ent->recipient.group->name);
			free(ent->recipient.group);
		}
		break;
	}

	free(ent->id.old);
	free(ent);
}

void
sbk_free_recipient_tree(struct sbk_ctx *ctx)
{
	struct sbk_recipient_entry *ent;

	while ((ent = RB_ROOT(&ctx->recipients)) != NULL) {
		RB_REMOVE(sbk_recipient_tree, &ctx->recipients, ent);
		sbk_free_recipient_entry(ent);
	}
}

static int
sbk_cmp_recipient_entries(struct sbk_recipient_entry *e,
    struct sbk_recipient_entry *f)
{
	if (e->id.old != NULL)
		return strcmp(e->id.old, f->id.old);
	else
		return (e->id.new < f->id.new) ? -1 : (e->id.new > f->id.new);
}

static int
sbk_get_recipient_id_from_column(struct sbk_ctx *ctx,
    struct sbk_recipient_id *id, sqlite3_stmt *stm, int idx)
{
	if (ctx->db_version < SBK_DB_VERSION_RECIPIENT_IDS) {
		id->new = -1;
		if (sbk_sqlite_column_text_copy(ctx, &id->old, stm, idx) == -1)
			return -1;
		if (id->old == NULL) {
			warnx("Invalid recipient id");
			return -1;
		}
	} else {
		id->new = sqlite3_column_int(stm, idx);
		id->old = NULL;
	}

	return 0;
}

static struct sbk_recipient_entry *
sbk_get_recipient_entry(struct sbk_ctx *ctx, sqlite3_stmt *stm)
{
	struct sbk_recipient_entry	*ent;
	struct sbk_contact		*con;
	struct sbk_group		*grp;

	if ((ent = calloc(1, sizeof *ent)) == NULL) {
		warn(NULL);
		return NULL;
	}

	if (sbk_get_recipient_id_from_column(ctx, &ent->id, stm,
	    SBK_COLUMN__ID) == -1)
		goto error;

	if (sqlite3_column_type(stm, SBK_COLUMN_GROUP_ID) == SQLITE_NULL)
		ent->recipient.type = SBK_CONTACT;
	else
		ent->recipient.type = SBK_GROUP;

	switch (ent->recipient.type) {
	case SBK_CONTACT:
		con = ent->recipient.contact = calloc(1, sizeof *con);
		if (con == NULL) {
			warn(NULL);
			goto error;
		}

		if (ctx->db_version < SBK_DB_VERSION_RECIPIENT_IDS) {
			if (strchr(ent->id.old, '@') != NULL) {
				con->email = strdup(ent->id.old);
				if (con->email == NULL) {
					warn(NULL);
					goto error;
				}
			} else {
				con->phone = strdup(ent->id.old);
				if (con->phone == NULL) {
					warn(NULL);
					goto error;
				}
			}
		} else {
			if (sbk_sqlite_column_text_copy(ctx, &con->phone,
			    stm, SBK_COLUMN_E164) == -1)
				goto error;

			if (sbk_sqlite_column_text_copy(ctx, &con->email,
			    stm, SBK_COLUMN_EMAIL) == -1)
				goto error;
		}

		if (sbk_sqlite_column_text_copy(ctx, &con->aci,
		    stm, SBK_COLUMN_ACI) == -1)
			goto error;

		if (sbk_sqlite_column_text_copy(ctx, &con->system_joined_name,
		    stm, SBK_COLUMN_SYSTEM_JOINED_NAME) == -1)
			goto error;

		if (sbk_sqlite_column_text_copy(ctx, &con->system_phone_label,
		    stm, SBK_COLUMN_SYSTEM_PHONE_LABEL) == -1)
			goto error;

		if (sbk_sqlite_column_text_copy(ctx, &con->profile_given_name,
		    stm, SBK_COLUMN_PROFILE_GIVEN_NAME) == -1)
			goto error;

		if (sbk_sqlite_column_text_copy(ctx, &con->profile_family_name,
		    stm, SBK_COLUMN_PROFILE_FAMILY_NAME) == -1)
			goto error;

		if (sbk_sqlite_column_text_copy(ctx, &con->profile_joined_name,
		    stm, SBK_COLUMN_PROFILE_JOINED_NAME) == -1)
			goto error;

		break;

	case SBK_GROUP:
		grp = ent->recipient.group = calloc(1, sizeof *grp);
		if (grp == NULL) {
			warn(NULL);
			goto error;
		}

		if (sbk_sqlite_column_text_copy(ctx, &grp->name,
		    stm, SBK_COLUMN_TITLE) == -1)
			goto error;

		break;
	}

	return ent;

error:
	sbk_free_recipient_entry(ent);
	return NULL;
}

static int
sbk_build_recipient_tree(struct sbk_ctx *ctx)
{
	struct sbk_recipient_entry	*ent;
	sqlite3_stmt			*stm;
	const char			*query;
	int				 ret;

	if (!RB_EMPTY(&ctx->recipients))
		return 0;

	if (sbk_create_database(ctx) == -1)
		return -1;

	if (ctx->db_version < SBK_DB_VERSION_RECIPIENT_IDS)
		query = SBK_QUERY_1;
	else if (ctx->db_version < SBK_DB_VERSION_SPLIT_PROFILE_NAMES)
		query = SBK_QUERY_2;
	else if (ctx->db_version < SBK_DB_VERSION_RESET_PNI_COLUMN)
		query = SBK_QUERY_3;
	else if (ctx->db_version < SBK_DB_VERSION_RECIPIENT_TABLE_VALIDATIONS)
		query = SBK_QUERY_4;
	else
		query = SBK_QUERY_5;

	if (sbk_sqlite_prepare(ctx, &stm, query) == -1)
		return -1;

	while ((ret = sbk_sqlite_step(ctx, stm)) == SQLITE_ROW) {
		if ((ent = sbk_get_recipient_entry(ctx, stm)) == NULL)
			goto error;
		RB_INSERT(sbk_recipient_tree, &ctx->recipients, ent);
	}

	if (ret != SQLITE_DONE)
		goto error;

	sqlite3_finalize(stm);
	return 0;

error:
	sbk_free_recipient_tree(ctx);
	sqlite3_finalize(stm);
	return -1;
}

struct sbk_recipient *
sbk_get_recipient_from_id(struct sbk_ctx *ctx, struct sbk_recipient_id *id)
{
	struct sbk_recipient_entry find, *result;

	if (sbk_build_recipient_tree(ctx) == -1)
		return NULL;

	find.id = *id;
	result = RB_FIND(sbk_recipient_tree, &ctx->recipients, &find);

	if (result == NULL) {
		warnx("Cannot find recipient");
		return NULL;
	}

	return &result->recipient;
}

struct sbk_recipient *
sbk_get_recipient_from_id_from_column(struct sbk_ctx *ctx, sqlite3_stmt *stm,
    int idx)
{
	struct sbk_recipient	*rcp;
	struct sbk_recipient_id	 id;

	if (sbk_get_recipient_id_from_column(ctx, &id, stm, idx) == -1)
		return NULL;

	rcp = sbk_get_recipient_from_id(ctx, &id);
	free(id.old);
	return rcp;
}

struct sbk_recipient *
sbk_get_recipient_from_aci(struct sbk_ctx *ctx, const char *aci)
{
	struct sbk_recipient_entry *ent;

	RB_FOREACH(ent, sbk_recipient_tree, &ctx->recipients)
		if (ent->recipient.type == SBK_CONTACT &&
		    ent->recipient.contact->aci != NULL &&
		    strcmp(aci, ent->recipient.contact->aci) == 0)
			return &ent->recipient;

	return NULL;
}
