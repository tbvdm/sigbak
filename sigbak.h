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

#ifndef SIGBAK_H
#define SIGBAK_H

#include <stdint.h>
#include <stdio.h>

#include "backup.pb-c.h"
#include "database.pb-c.h"

#include "compat.h"

/*
 * Types for sms and mms messages
 *
 * Based on src/org/thoughtcrime/securesms/database/MmsSmsColumns.java in the
 * Signal-Android repository
 */

/* Base types */
#define SBK_BASE_TYPE_MASK			0x1f

#define SBK_INCOMING_AUDIO_CALL_TYPE		1
#define SBK_OUTGOING_AUDIO_CALL_TYPE		2
#define SBK_MISSED_AUDIO_CALL_TYPE		3
#define SBK_JOINED_TYPE				4
#define SBK_UNSUPPORTED_MESSAGE_TYPE		5
#define SBK_INVALID_MESSAGE_TYPE		6
#define SBK_PROFILE_CHANGE_TYPE			7
#define SBK_MISSED_VIDEO_CALL_TYPE		8
#define SBK_GV1_MIGRATION_TYPE			9
#define SBK_INCOMING_VIDEO_CALL_TYPE		10
#define SBK_OUTGOING_VIDEO_CALL_TYPE		11

#define SBK_BASE_INBOX_TYPE			20
#define SBK_BASE_OUTBOX_TYPE			21
#define SBK_BASE_SENDING_TYPE			22
#define SBK_BASE_SENT_TYPE			23
#define SBK_BASE_SENT_FAILED_TYPE		24
#define SBK_BASE_PENDING_SECURE_SMS_FALLBACK	25
#define SBK_BASE_PENDING_INSECURE_SMS_FALLBACK	26
#define SBK_BASE_DRAFT_TYPE			27

/* Message attributes */
#define SBK_MESSAGE_ATTRIBUTE_MASK		0xe0
#define SBK_MESSAGE_FORCE_SMS_BIT		0x40

/* Key exchange information */
#define SBK_KEY_EXCHANGE_MASK			0xff00
#define SBK_KEY_EXCHANGE_BIT			0x8000
#define SBK_KEY_EXCHANGE_IDENTITY_VERIFIED_BIT	0x4000
#define SBK_KEY_EXCHANGE_IDENTITY_DEFAULT_BIT	0x2000
#define SBK_KEY_EXCHANGE_CORRUPTED_BIT		0x1000
#define SBK_KEY_EXCHANGE_INVALID_VERSION_BIT	0x800
#define SBK_KEY_EXCHANGE_BUNDLE_BIT		0x400
#define SBK_KEY_EXCHANGE_IDENTITY_UPDATE_BIT	0x200
#define SBK_KEY_EXCHANGE_CONTENT_FORMAT		0x100

/* Secure message information */
#define SBK_SECURE_MESSAGE_BIT			0x800000
#define SBK_END_SESSION_BIT			0x400000
#define SBK_PUSH_MESSAGE_BIT			0x200000

/* Group message information */
#define SBK_GROUP_UPDATE_BIT			0x10000
#define SBK_GROUP_QUIT_BIT			0x20000
#define SBK_EXPIRATION_TIMER_UPDATE_BIT		0x40000

/* Encrypted storage information */
#define SBK_ENCRYPTION_MASK			0xff000000
#define SBK_ENCRYPTION_SYMMETRIC_BIT		0x80000000 /* Deprecated */
#define SBK_ENCRYPTION_ASYMMETRIC_BIT		0x40000000 /* Deprecated */
#define SBK_ENCRYPTION_REMOTE_BIT		0x20000000
#define SBK_ENCRYPTION_REMOTE_FAILED_BIT	0x10000000
#define SBK_ENCRYPTION_REMOTE_NO_SESSION_BIT	0x8000000
#define SBK_ENCRYPTION_REMOTE_DUPLICATE_BIT	0x4000000
#define SBK_ENCRYPTION_REMOTE_LEGACY_BIT	0x2000000

/* Attachment transfer states */
#define SBK_ATTACHMENT_TRANSFER_DONE	0
#define SBK_ATTACHMENT_TRANSFER_STARTED	1
#define SBK_ATTACHMENT_TRANSFER_PENDING	2
#define SBK_ATTACHMENT_TRANSFER_FAILED	3

/* Content type of the long-text attachment of a long message */
#define SBK_LONG_TEXT_TYPE	"text/x-signal-plain"

#ifndef nitems
#define nitems(a) (sizeof (a) / sizeof (a)[0])
#endif

struct sbk_ctx;

struct sbk_file;

struct sbk_contact {
	char		*phone;
	char		*email;
	char		*system_display_name;
	char		*system_phone_label;
	char		*profile_given_name;
	char		*profile_family_name;
	char		*profile_joined_name;
};

struct sbk_group {
	char		*name;
};

struct sbk_recipient {
	enum {
		SBK_CONTACT,
		SBK_GROUP
	} type;
	struct sbk_contact	*contact;
	struct sbk_group	*group;
};

struct sbk_attachment {
	int64_t		 rowid;
	int64_t		 attachmentid;
	int		 status;
	char		*filename;
	char		*content_type;
	uint64_t	 size;
	struct sbk_file	*file;
	TAILQ_ENTRY(sbk_attachment) entries;
};

TAILQ_HEAD(sbk_attachment_list, sbk_attachment);

struct sbk_mention {
	struct sbk_recipient *recipient;
	SIMPLEQ_ENTRY(sbk_mention) entries;
};

SIMPLEQ_HEAD(sbk_mention_list, sbk_mention);

struct sbk_reaction {
	struct sbk_recipient *recipient;
	uint64_t	 time_sent;
	uint64_t	 time_recv;
	char		*emoji;
	SIMPLEQ_ENTRY(sbk_reaction) entries;
};

SIMPLEQ_HEAD(sbk_reaction_list, sbk_reaction);

struct sbk_message_id {
	enum {
		SBK_MESSAGE_SMS,
		SBK_MESSAGE_MMS
	}		 type;
	int		 rowid;
};

struct sbk_message {
	struct sbk_message_id id;
	struct sbk_recipient *recipient;
	uint64_t	 time_sent;
	uint64_t	 time_recv;
	int		 type;
	int		 thread;
	char		*text;
	struct sbk_attachment_list *attachments;
	struct sbk_mention_list *mentions;
	struct sbk_reaction_list *reactions;
	SIMPLEQ_ENTRY(sbk_message) entries;
};

SIMPLEQ_HEAD(sbk_message_list, sbk_message);

struct sbk_thread {
	struct sbk_recipient *recipient;
	uint64_t	 id;
	uint64_t	 date;
	uint64_t	 nmessages;
	SIMPLEQ_ENTRY(sbk_thread) entries;
};

SIMPLEQ_HEAD(sbk_thread_list, sbk_thread);

struct sbk_ctx	*sbk_ctx_new(void);
void		 sbk_ctx_free(struct sbk_ctx *);

int		 sbk_open(struct sbk_ctx *, const char *, const char *);
void		 sbk_close(struct sbk_ctx *);
int		 sbk_eof(struct sbk_ctx *);
int		 sbk_rewind(struct sbk_ctx *);

Signal__BackupFrame *sbk_get_frame(struct sbk_ctx *, struct sbk_file **);
int		 sbk_write_file(struct sbk_ctx *, struct sbk_file *, FILE *);
char		*sbk_get_file_data(struct sbk_ctx *, struct sbk_file *,
		    size_t *);
void		 sbk_free_frame(Signal__BackupFrame *);
void		 sbk_free_file(struct sbk_file *);

struct sbk_attachment_list *sbk_get_all_attachments(struct sbk_ctx *);
struct sbk_attachment_list *sbk_get_attachments_for_thread(struct sbk_ctx *,
		    int);
void		 sbk_free_attachment_list(struct sbk_attachment_list *);

struct sbk_message_list *sbk_get_all_messages(struct sbk_ctx *);
struct sbk_message_list *sbk_get_messages_for_thread(struct sbk_ctx *, int);
void		 sbk_free_message_list(struct sbk_message_list *);
int		 sbk_is_outgoing_message(const struct sbk_message *);

struct sbk_thread_list *sbk_get_threads(struct sbk_ctx *);
void		 sbk_free_thread_list(struct sbk_thread_list *);

const char	*sbk_get_recipient_display_name(const struct sbk_recipient *);

int		 sbk_write_database(struct sbk_ctx *, const char *);

const char	*sbk_error(struct sbk_ctx *);

const char	*mime_get_extension(const char *);

int		 get_passphrase(const char *, char *, size_t);
int		 unveil_dirname(const char *, const char *);
void		 usage(const char *, const char *) __dead;

int		 cmd_attachments(int, char **);
int		 cmd_avatars(int, char **);
int		 cmd_check(int, char **);
int		 cmd_dump(int, char **);
int		 cmd_messages(int, char **);
int		 cmd_sqlite(int, char **);
int		 cmd_stickers(int, char **);
int		 cmd_threads(int, char **);

#endif
