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

/* For database versions < REACTIONS */
#define SBK_SELECT_SMS_1						\
	"SELECT "							\
	"0, "								\
	"_id, "								\
	"date_sent, "							\
	"date AS date_received, "					\
	"thread_id, "							\
	"address, "			/* recipient_id */		\
	"type, "							\
	"body, "							\
	"0, "				/* mms.quote_id */		\
	"NULL, "			/* mms.quote_author */		\
	"NULL, "			/* mms.quote_body */		\
	"NULL, "			/* mms.quote_mentions */	\
	"NULL "				/* reactions */			\
	"FROM sms "

/* For database versions [REACTIONS, THREAD_AND_MESSAGE_FOREIGN_KEYS) */
#define SBK_SELECT_SMS_2						\
	"SELECT "							\
	"0, "								\
	"_id, "								\
	"date_sent, "							\
	"date AS date_received, "					\
	"thread_id, "							\
	"address, "			/* recipient_id */		\
	"type, "							\
	"body, "							\
	"0, "				/* mms.quote_id */		\
	"NULL, "			/* mms.quote_author */		\
	"NULL, "			/* mms.quote_body */		\
	"NULL, "			/* mms.quote_mentions */	\
	"reactions "							\
	"FROM sms "

/*
 * For database versions [THREAD_AND_MESSAGE_FOREIGN_KEYS,
 * SINGLE_MESSAGE_TABLE_MIGRATION)
 */
#define SBK_SELECT_SMS_3						\
	"SELECT "							\
	"0, "								\
	"_id, "								\
	"date_sent, "							\
	"date_received, "						\
	"thread_id, "							\
	"recipient_id, "						\
	"type, "							\
	"body, "							\
	"0, "				/* mms.quote_id */		\
	"NULL, "			/* mms.quote_author */		\
	"NULL, "			/* mms.quote_body */		\
	"NULL, "			/* mms.quote_mentions */	\
	"NULL "				/* reactions */			\
	"FROM sms "

/* For database versions < QUOTED_REPLIES */
#define SBK_SELECT_MMS_1						\
	"SELECT "							\
	"1, "								\
	"_id, "								\
	"date, "			/* date_sent */			\
	"date_received, "						\
	"thread_id, "							\
	"address, "			/* recipient_id */		\
	"msg_box, "			/* type */			\
	"body, "							\
	"0, "				/* quote_id */			\
	"NULL, "			/* quote_author */		\
	"NULL, "			/* quote_body */		\
	"NULL, "			/* quote_mentions */		\
	"NULL "				/* reactions */			\
	"FROM mms "

/* For database versions [QUOTED_REPLIES, REACTIONS) */
#define SBK_SELECT_MMS_2						\
	"SELECT "							\
	"1, "								\
	"_id, "								\
	"date, "			/* date_sent */			\
	"date_received, "						\
	"thread_id, "							\
	"address, "			/* recipient_id */		\
	"msg_box, "			/* type */			\
	"body, "							\
	"quote_id, "							\
	"quote_author, "						\
	"quote_body, "							\
	"NULL, "			/* quote_mentions */		\
	"NULL "				/* reactions */			\
	"FROM mms "

/* For database versions [REACTIONS, MENTIONS) */
#define SBK_SELECT_MMS_3						\
	"SELECT "							\
	"1, "								\
	"_id, "								\
	"date, "			/* date_sent */			\
	"date_received, "						\
	"thread_id, "							\
	"address, "			/* recipient_id */		\
	"msg_box, "			/* type */			\
	"body, "							\
	"quote_id, "							\
	"quote_author, "						\
	"quote_body, "							\
	"NULL, "			/* quote_mentions */		\
	"reactions "							\
	"FROM mms "

/* For database versions [MENTIONS, THREAD_AND_MESSAGE_FOREIGN_KEYS) */
#define SBK_SELECT_MMS_4						\
	"SELECT "							\
	"1, "								\
	"_id, "								\
	"date, "			/* date_sent */			\
	"date_received, "						\
	"thread_id, "							\
	"address, "			/* recipient_id */		\
	"msg_box, "			/* type */			\
	"body, "							\
	"quote_id, "							\
	"quote_author, "						\
	"quote_body, "							\
	"quote_mentions, "						\
	"reactions "							\
	"FROM mms "

/*
 * For database versions [THREAD_AND_MESSAGE_FOREIGN_KEYS,
 * SINGLE_MESSAGE_TABLE_MIGRATION)
 */
#define SBK_SELECT_MMS_5						\
	"SELECT "							\
	"1, "								\
	"_id, "								\
	"date_sent, "							\
	"date_received, "						\
	"thread_id, "							\
	"recipient_id, "						\
	"type, "							\
	"body, "							\
	"quote_id, "							\
	"quote_author, "						\
	"quote_body, "							\
	"quote_mentions, "						\
	"NULL "				/* reactions */			\
	"FROM mms "

/*
 * For database versions [SINGLE_MESSAGE_TABLE_MIGRATION,
 * REACTION_FOREIGN_KEY_MIGRATION)
 */
#define SBK_SELECT_1							\
	SBK_SELECT_MMS_5

/*
 * For database versions [REACTION_FOREIGN_KEY_MIGRATION,
 * MESSAGE_RECIPIENTS_AND_EDIT_MESSAGE_MIGRATION)
 */
#define SBK_SELECT_2							\
	"SELECT "							\
	"1, "								\
	"_id, "								\
	"date_sent, "							\
	"date_received, "						\
	"thread_id, "							\
	"recipient_id, "						\
	"type, "							\
	"body, "							\
	"quote_id, "							\
	"quote_author, "						\
	"quote_body, "							\
	"quote_mentions, "						\
	"NULL "				/* reactions */			\
	"FROM message "

/*
 * For database versions >= MESSAGE_RECIPIENTS_AND_EDIT_MESSAGE_MIGRATION
 *
 * The iif() expression below is based on the outgoingClause variable in
 * V185_MessageRecipientsAndEditMessageMigration.kt in the Signal-Android
 * repository.
 */
#define SBK_SELECT_3							\
	"SELECT "							\
	"1, "								\
	"_id, "								\
	"date_sent, "							\
	"date_received, "						\
	"thread_id, "							\
	"iif(type & " STRINGIFY(SBK_BASE_TYPE_MASK) " IN ("		\
	    STRINGIFY(SBK_OUTGOING_AUDIO_CALL_TYPE) ", "		\
	    STRINGIFY(SBK_OUTGOING_VIDEO_CALL_TYPE) ", "		\
	    STRINGIFY(SBK_BASE_OUTBOX_TYPE) ", "			\
	    STRINGIFY(SBK_BASE_SENDING_TYPE) ", "			\
	    STRINGIFY(SBK_BASE_SENT_TYPE) ", "				\
	    STRINGIFY(SBK_BASE_SENT_FAILED_TYPE) ", "			\
	    STRINGIFY(SBK_BASE_PENDING_SECURE_SMS_FALLBACK) ", "	\
	    STRINGIFY(SBK_BASE_PENDING_INSECURE_SMS_FALLBACK) "), "	\
	    "to_recipient_id, from_recipient_id), "			\
	"type, "							\
	"body, "							\
	"quote_id, "							\
	"quote_author, "						\
	"quote_body, "							\
	"quote_mentions, "						\
	"NULL "				/* reactions */			\
	"FROM message "

#define SBK_WHERE_THREAD						\
	"WHERE thread_id = ?1 "

#define SBK_ORDER							\
	"ORDER BY date_received"

/* For database versions < QUOTED_REPLIES */
#define SBK_QUERY_1							\
	SBK_SELECT_SMS_1						\
	SBK_WHERE_THREAD						\
	"UNION ALL "							\
	SBK_SELECT_MMS_1						\
	SBK_WHERE_THREAD						\
	SBK_ORDER

/* For database versions [QUOTED_REPLIES, REACTIONS) */
#define SBK_QUERY_2							\
	SBK_SELECT_SMS_1						\
	SBK_WHERE_THREAD						\
	"UNION ALL "							\
	SBK_SELECT_MMS_2						\
	SBK_WHERE_THREAD						\
	SBK_ORDER

/* For database versions [REACTIONS, MENTIONS) */
#define SBK_QUERY_3							\
	SBK_SELECT_SMS_2						\
	SBK_WHERE_THREAD						\
	"UNION ALL "							\
	SBK_SELECT_MMS_3						\
	SBK_WHERE_THREAD						\
	SBK_ORDER

/* For database versions [MENTIONS, THREAD_AND_MESSAGE_FOREIGN_KEYS) */
#define SBK_QUERY_4							\
	SBK_SELECT_SMS_2						\
	SBK_WHERE_THREAD						\
	"UNION ALL "							\
	SBK_SELECT_MMS_4						\
	SBK_WHERE_THREAD						\
	SBK_ORDER

/*
 * For database versions [THREAD_AND_MESSAGE_FOREIGN_KEYS,
 * SINGLE_MESSAGE_TABLE_MIGRATION)
 */
#define SBK_QUERY_5							\
	SBK_SELECT_SMS_3						\
	SBK_WHERE_THREAD						\
	"UNION ALL "							\
	SBK_SELECT_MMS_5						\
	SBK_WHERE_THREAD						\
	SBK_ORDER

/*
 * For database versions [SINGLE_MESSAGE_TABLE_MIGRATION,
 * REACTION_FOREIGN_KEY_MIGRATION)
 */
#define SBK_QUERY_6							\
	SBK_SELECT_1							\
	SBK_WHERE_THREAD						\
	SBK_ORDER

/*
 * For database versions [REACTION_FOREIGN_KEY_MIGRATION,
 * MESSAGE_RECIPIENTS_AND_EDIT_MESSAGE_MIGRATION)
 */
#define SBK_QUERY_7							\
	SBK_SELECT_2							\
	SBK_WHERE_THREAD						\
	SBK_ORDER

/* For database versions >= MESSAGE_RECIPIENTS_AND_EDIT_MESSAGE_MIGRATION */
#define SBK_QUERY_8							\
	SBK_SELECT_3							\
	SBK_WHERE_THREAD						\
	SBK_ORDER

#define SBK_COLUMN_TABLE		0
#define SBK_COLUMN__ID			1
#define SBK_COLUMN_DATE_SENT		2
#define SBK_COLUMN_DATE_RECEIVED	3
#define SBK_COLUMN_THREAD_ID		4
#define SBK_COLUMN_RECIPIENT_ID		5
#define SBK_COLUMN_TYPE			6
#define SBK_COLUMN_BODY			7
#define SBK_COLUMN_QUOTE_ID		8
#define SBK_COLUMN_QUOTE_AUTHOR		9
#define SBK_COLUMN_QUOTE_BODY		10
#define SBK_COLUMN_QUOTE_MENTIONS	11
#define SBK_COLUMN_REACTIONS		12

static void
sbk_free_quote(struct sbk_quote *qte)
{
	if (qte != NULL) {
		free(qte->text);
		sbk_free_attachment_list(qte->attachments);
		sbk_free_mention_list(qte->mentions);
		free(qte);
	}
}

static void
sbk_free_message(struct sbk_message *msg)
{
	if (msg != NULL) {
		free(msg->text);
		sbk_free_attachment_list(msg->attachments);
		sbk_free_mention_list(msg->mentions);
		sbk_free_reaction_list(msg->reactions);
		sbk_free_quote(msg->quote);
		free(msg);
	}
}

void
sbk_free_message_list(struct sbk_message_list *lst)
{
	struct sbk_message *msg;

	if (lst != NULL) {
		while ((msg = SIMPLEQ_FIRST(lst)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(lst, entries);
			sbk_free_message(msg);
		}
		free(lst);
	}
}

int
sbk_is_outgoing_message(const struct sbk_message *msg)
{
	switch (msg->type & SBK_BASE_TYPE_MASK) {
	case SBK_OUTGOING_AUDIO_CALL_TYPE:
	case SBK_OUTGOING_VIDEO_CALL_TYPE:
	case SBK_BASE_OUTBOX_TYPE:
	case SBK_BASE_SENDING_TYPE:
	case SBK_BASE_SENT_TYPE:
	case SBK_BASE_SENT_FAILED_TYPE:
	case SBK_BASE_PENDING_SECURE_SMS_FALLBACK:
	case SBK_BASE_PENDING_INSECURE_SMS_FALLBACK:
		return 1;
	default:
		return 0;
	}
}

static int
sbk_get_body(struct sbk_message *msg)
{
	const char *fmt;

	fmt = NULL;

	if (msg->type & SBK_ENCRYPTION_REMOTE_FAILED_BIT)
		fmt = "Bad encrypted message";
	else if (msg->type & SBK_ENCRYPTION_REMOTE_NO_SESSION_BIT)
		fmt = "Message encrypted for non-existing session";
	else if (msg->type & SBK_ENCRYPTION_REMOTE_DUPLICATE_BIT)
		fmt = "Duplicate message";
	else if ((msg->type & SBK_ENCRYPTION_REMOTE_LEGACY_BIT) ||
	    (msg->type & SBK_ENCRYPTION_REMOTE_BIT))
		fmt = "Encrypted message sent from an older version of Signal "
		    "that is no longer supported";
	else if (msg->type & SBK_GROUP_UPDATE_BIT) {
		if (sbk_is_outgoing_message(msg))
			fmt = "You updated the group";
		else
			fmt = "%s updated the group";
	} else if (msg->type & SBK_GROUP_QUIT_BIT) {
		if (sbk_is_outgoing_message(msg))
			fmt = "You have left the group";
		else
			fmt = "%s has left the group";
	} else if (msg->type & SBK_END_SESSION_BIT) {
		if (sbk_is_outgoing_message(msg))
			fmt = "You reset the secure session";
		else
			fmt = "%s reset the secure session";
	} else if (msg->type & SBK_KEY_EXCHANGE_IDENTITY_VERIFIED_BIT) {
		if (sbk_is_outgoing_message(msg))
			fmt = "You marked your safety number with %s verified";
		else
			fmt = "You marked your safety number with %s verified "
			    "from another device";
	} else if (msg->type & SBK_KEY_EXCHANGE_IDENTITY_DEFAULT_BIT) {
		if (sbk_is_outgoing_message(msg))
			fmt = "You marked your safety number with %s "
			    "unverified";
		else
			fmt = "You marked your safety number with %s "
			    "unverified from another device";
	} else if (msg->type & SBK_KEY_EXCHANGE_CORRUPTED_BIT)
		fmt = "Corrupt key exchange message";
	else if (msg->type & SBK_KEY_EXCHANGE_INVALID_VERSION_BIT)
		fmt = "Key exchange message for invalid protocol version";
	else if (msg->type & SBK_KEY_EXCHANGE_BUNDLE_BIT)
		fmt = "Message with new safety number";
	else if (msg->type & SBK_KEY_EXCHANGE_IDENTITY_UPDATE_BIT)
		fmt = "Your safety number with %s has changed";
	else if (msg->type & SBK_KEY_EXCHANGE_BIT)
		fmt = "Key exchange message";
	else
		switch (msg->type & SBK_BASE_TYPE_MASK) {
		case SBK_INCOMING_AUDIO_CALL_TYPE:
		case SBK_INCOMING_VIDEO_CALL_TYPE:
			fmt = "%s called you";
			break;
		case SBK_OUTGOING_AUDIO_CALL_TYPE:
		case SBK_OUTGOING_VIDEO_CALL_TYPE:
			fmt = "Called %s";
			break;
		case SBK_MISSED_AUDIO_CALL_TYPE:
			fmt = "Missed audio call from %s";
			break;
		case SBK_JOINED_TYPE:
			fmt = "%s is on Signal";
			break;
		case SBK_UNSUPPORTED_MESSAGE_TYPE:
			fmt = "Unsupported message sent from a newer version "
			    "of Signal";
			break;
		case SBK_INVALID_MESSAGE_TYPE:
			fmt = "Invalid message";
			break;
		case SBK_PROFILE_CHANGE_TYPE:
			fmt = "%s changed their profile";
			break;
		case SBK_MISSED_VIDEO_CALL_TYPE:
			fmt = "Missed video call from %s";
			break;
		case SBK_GV1_MIGRATION_TYPE:
			fmt = "This group was updated to a new group";
			break;
		case SBK_BOOST_REQUEST_TYPE:
			fmt = "Like this new feature? Help support Signal "
			    "with a one-time donation.";
			break;
		}

	if (fmt == NULL)
		return 0;

	free(msg->text);

	if (asprintf(&msg->text, fmt,
	    sbk_get_recipient_display_name(msg->recipient)) == -1) {
		msg->text = NULL;
		return -1;
	}

	return 0;
}

static void
sbk_remove_attachment(struct sbk_message *msg, struct sbk_attachment *att)
{
	TAILQ_REMOVE(msg->attachments, att, entries);
	sbk_free_attachment(att);
	if (TAILQ_EMPTY(msg->attachments)) {
		sbk_free_attachment_list(msg->attachments);
		msg->attachments = NULL;
	}
}

static int
sbk_get_long_message(struct sbk_ctx *ctx, struct sbk_message *msg)
{
	struct sbk_attachment	*att;
	char			*longmsg;
	int			 found;

	/* Look for a long-message attachment */
	found = 0;
	TAILQ_FOREACH(att, msg->attachments, entries)
		if (att->content_type != NULL &&
		    strcmp(att->content_type, SBK_LONG_TEXT_TYPE) == 0) {
			found = 1;
			break;
		}

	if (!found)
		return 0;

	if (att->file == NULL) {
		warnx("Long-message attachment for message %d-%d not "
		    "available in backup", msg->id.type, msg->id.rowid);
		return 0;
	}

	if ((longmsg = sbk_get_file_data_as_string(ctx, att->file)) == NULL)
		return -1;

	free(msg->text);
	msg->text = longmsg;

	/* Do not expose the long-message attachment */
	sbk_remove_attachment(msg, att);

	return 0;
}

static int
sbk_get_quote(struct sbk_ctx *ctx, struct sbk_message *msg, sqlite3_stmt *stm)
{
	struct sbk_quote *qte;

	if (sqlite3_column_int64(stm, SBK_COLUMN_QUOTE_ID) == 0 &&
	    sqlite3_column_int64(stm, SBK_COLUMN_QUOTE_AUTHOR) == 0) {
		/* No quote */
		return 0;
	}

	if ((qte = calloc(1, sizeof *qte)) == NULL) {
		warn(NULL);
		return -1;
	}

	qte->id = sqlite3_column_int64(stm, SBK_COLUMN_QUOTE_ID);

	qte->recipient = sbk_get_recipient_from_id_from_column(ctx, stm,
	    SBK_COLUMN_QUOTE_AUTHOR);
	if (qte->recipient == NULL)
		goto error;

	if (sbk_sqlite_column_text_copy(ctx, &qte->text, stm,
	    SBK_COLUMN_QUOTE_BODY) == -1)
		goto error;

	if (sbk_get_attachments_for_quote(ctx, qte, &msg->id) == -1)
		goto error;

	if (sbk_get_mentions_for_quote(ctx, &qte->mentions, stm,
	    SBK_COLUMN_QUOTE_MENTIONS) == -1) {
		warnx("Cannot get mentions for quote in message %d-%d",
		    msg->id.type, msg->id.rowid);
		goto error;
	}

	if (sbk_insert_mentions(&qte->text, qte->mentions) == -1) {
		warnx("Cannot insert mentions in quote in message %d-%d",
		    msg->id.type, msg->id.rowid);
		goto error;
	}

	msg->quote = qte;
	return 0;

error:
	sbk_free_quote(qte);
	return -1;
}

static struct sbk_message *
sbk_get_message(struct sbk_ctx *ctx, sqlite3_stmt *stm)
{
	struct sbk_message *msg;

	if ((msg = calloc(1, sizeof *msg)) == NULL) {
		warn(NULL);
		return NULL;
	}

	msg->id.type = (sqlite3_column_int(stm, SBK_COLUMN_TABLE) == 0) ?
	    SBK_MESSAGE_SMS : SBK_MESSAGE_MMS;
	msg->id.rowid = sqlite3_column_int(stm, SBK_COLUMN__ID);

	msg->recipient = sbk_get_recipient_from_id_from_column(ctx, stm,
	    SBK_COLUMN_RECIPIENT_ID);
	if (msg->recipient == NULL)
		goto error;

	if (sbk_sqlite_column_text_copy(ctx, &msg->text, stm, SBK_COLUMN_BODY)
	    == -1)
		goto error;

	msg->time_sent = sqlite3_column_int64(stm, SBK_COLUMN_DATE_SENT);
	msg->time_recv = sqlite3_column_int64(stm, SBK_COLUMN_DATE_RECEIVED);
	msg->type = sqlite3_column_int(stm, SBK_COLUMN_TYPE);
	msg->thread = sqlite3_column_int(stm, SBK_COLUMN_THREAD_ID);

	if (sbk_get_body(msg) == -1)
		goto error;

	if (msg->id.type == SBK_MESSAGE_MMS) {
		if (sbk_get_attachments_for_message(ctx, msg) == -1)
			goto error;

		if (sbk_get_long_message(ctx, msg) == -1)
			goto error;

		if (sbk_get_mentions_for_message(ctx, msg) == -1)
			goto error;

		if (sbk_insert_mentions(&msg->text, msg->mentions) == -1) {
			warnx("Cannot insert mentions in message %d-%d",
			    msg->id.type, msg->id.rowid);
			goto error;
		}

		if (sbk_get_quote(ctx, msg, stm) == -1)
			goto error;
	}

	if (ctx->db_version >= SBK_DB_VERSION_REACTION_REFACTOR) {
		if (sbk_get_reactions_from_table(ctx, msg) == -1)
			goto error;
	} else {
		if (sbk_get_reactions_from_column(ctx, &msg->reactions, stm,
		    SBK_COLUMN_REACTIONS) == -1)
			goto error;
	}

	return msg;

error:
	sbk_free_message(msg);
	return NULL;
}

static struct sbk_message_list *
sbk_get_messages(struct sbk_ctx *ctx, sqlite3_stmt *stm)
{
	struct sbk_message_list	*lst;
	struct sbk_message	*msg;
	int			 ret;

	if ((lst = malloc(sizeof *lst)) == NULL) {
		warn(NULL);
		goto error;
	}

	SIMPLEQ_INIT(lst);

	while ((ret = sbk_sqlite_step(ctx, stm)) == SQLITE_ROW) {
		if ((msg = sbk_get_message(ctx, stm)) == NULL)
			goto error;
		SIMPLEQ_INSERT_TAIL(lst, msg, entries);
	}

	if (ret != SQLITE_DONE)
		goto error;

	sqlite3_finalize(stm);
	return lst;

error:
	sbk_free_message_list(lst);
	sqlite3_finalize(stm);
	return NULL;
}

struct sbk_message_list *
sbk_get_messages_for_thread(struct sbk_ctx *ctx, struct sbk_thread *thd)
{
	sqlite3_stmt	*stm;
	const char	*query;

	if (sbk_create_database(ctx) == -1)
		return NULL;

	if (ctx->db_version >=
	    SBK_DB_VERSION_MESSAGE_RECIPIENTS_AND_EDIT_MESSAGE_MIGRATION)
		query = SBK_QUERY_8;
	else if (ctx->db_version >=
	    SBK_DB_VERSION_REACTION_FOREIGN_KEY_MIGRATION)
		query = SBK_QUERY_7;
	else if (ctx->db_version >=
	    SBK_DB_VERSION_SINGLE_MESSAGE_TABLE_MIGRATION)
		query = SBK_QUERY_6;
	else if (ctx->db_version >=
	    SBK_DB_VERSION_THREAD_AND_MESSAGE_FOREIGN_KEYS)
		query = SBK_QUERY_5;
	else if (ctx->db_version >= SBK_DB_VERSION_MENTIONS)
		query = SBK_QUERY_4;
	else if (ctx->db_version >= SBK_DB_VERSION_REACTIONS)
		query = SBK_QUERY_3;
	else if (ctx->db_version >= SBK_DB_VERSION_QUOTED_REPLIES)
		query = SBK_QUERY_2;
	else
		query = SBK_QUERY_1;

	if (sbk_sqlite_prepare(ctx, &stm, query) == -1)
		return NULL;

	if (sbk_sqlite_bind_int(ctx, stm, 1, thd->id) == -1) {
		sqlite3_finalize(stm);
		return NULL;
	}

	return sbk_get_messages(ctx, stm);
}
