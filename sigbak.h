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

/*
 * Types for sms and mms messages
 *
 * Based on src/org/thoughtcrime/securesms/database/MmsSmsColumns.java in the
 * Signal-Android repository
 */

/* Base types */
#define SBK_BASE_TYPE_MASK			0x1f

#define SBK_INCOMING_CALL_TYPE			1
#define SBK_OUTGOING_CALL_TYPE			2
#define SBK_MISSED_CALL_TYPE			3
#define SBK_JOINED_TYPE				4
#define SBK_UNSUPPORTED_MESSAGE_TYPE		5

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

#define SBK_IS_OUTGOING_MESSAGE(type)					\
    (((type) & SBK_BASE_TYPE_MASK) == SBK_OUTGOING_CALL_TYPE ||		\
    ((type) & SBK_BASE_TYPE_MASK) == SBK_BASE_OUTBOX_TYPE ||		\
    ((type) & SBK_BASE_TYPE_MASK) == SBK_BASE_SENDING_TYPE ||		\
    ((type) & SBK_BASE_TYPE_MASK) == SBK_BASE_SENT_TYPE ||		\
    ((type) & SBK_BASE_TYPE_MASK) == SBK_BASE_SENT_FAILED_TYPE ||	\
    ((type) & SBK_BASE_TYPE_MASK) == SBK_BASE_PENDING_SECURE_SMS_FALLBACK || \
    ((type) & SBK_BASE_TYPE_MASK) == SBK_BASE_PENDING_INSECURE_SMS_FALLBACK)

enum sbk_file_type {
	SBK_ATTACHMENT,
	SBK_AVATAR
};

struct sbk_ctx;

struct sbk_file;

struct sbk_sms {
	int		 id;
	char		*address;
	uint64_t	 date_recv;
	uint64_t	 date_sent;
	int		 thread;
	int		 type;
	char		*body;
	SIMPLEQ_ENTRY(sbk_sms) entries;
};

SIMPLEQ_HEAD(sbk_sms_list, sbk_sms);

struct sbk_mms {
	int		 id;
	char		*address;
	uint64_t	 date_recv;
	uint64_t	 date_sent;
	int		 thread;
	int		 type;
	char		*body;
	int		 nattachments;
	SIMPLEQ_ENTRY(sbk_mms) entries;
};

SIMPLEQ_HEAD(sbk_mms_list, sbk_mms);

struct sbk_attachment {
	int64_t		 id;
	char		*filename;
	char		*content_type;
	uint64_t	 size;
	SIMPLEQ_ENTRY(sbk_attachment) entries;
};

SIMPLEQ_HEAD(sbk_attachment_list, sbk_attachment);

struct sbk_ctx	*sbk_ctx_new(void);
void		 sbk_ctx_free(struct sbk_ctx *);

int		 sbk_open(struct sbk_ctx *, const char *, const char *);
void		 sbk_close(struct sbk_ctx *);
int		 sbk_eof(struct sbk_ctx *);
int		 sbk_rewind(struct sbk_ctx *);

Signal__BackupFrame *sbk_get_frame(struct sbk_ctx *);
void		 sbk_free_frame(Signal__BackupFrame *);
int		 sbk_has_file_data(Signal__BackupFrame *);
int		 sbk_skip_file_data(struct sbk_ctx *, Signal__BackupFrame *);

struct sbk_file	*sbk_get_file(struct sbk_ctx *);
void		 sbk_free_file(struct sbk_file *);
enum sbk_file_type sbk_get_file_type(struct sbk_file *);
const char	*sbk_get_file_name(struct sbk_file *);
size_t		 sbk_get_file_size(struct sbk_file *);
int		 sbk_write_file(struct sbk_ctx *, struct sbk_file *, FILE *);

struct sbk_sms_list *sbk_get_smses(struct sbk_ctx *);
void		 sbk_free_sms_list(struct sbk_sms_list *);

struct sbk_mms_list *sbk_get_mmses(struct sbk_ctx *);
void		 sbk_free_mms_list(struct sbk_mms_list *);

struct sbk_attachment_list *sbk_get_attachments(struct sbk_ctx *, int);
void		 sbk_free_attachment_list(struct sbk_attachment_list *);

char		*sbk_get_contact_name(struct sbk_ctx *, const char *);
char		*sbk_get_group_name(struct sbk_ctx *, const char *);
int		 sbk_is_group_address(const char *);

int		 sbk_write_database(struct sbk_ctx *, const char *);

const char	*sbk_error(struct sbk_ctx *);

void		*mem_protobuf_malloc(void *, size_t);
void		 mem_protobuf_free(void *, void *);

int		 mem_sqlite_init(void *);
void		 mem_sqlite_shutdown(void *);
void		*mem_sqlite_malloc(int);
void		*mem_sqlite_realloc(void *, int);
void		 mem_sqlite_free(void *);
int		 mem_sqlite_size(void *);
int		 mem_sqlite_roundup(int);

int		 get_passphrase(const char *, char *, size_t);
int		 unveil_dirname(const char *, const char *);
void		 usage(const char *, const char *) __dead;

int		 cmd_attachments(int, char **);
int		 cmd_avatars(int, char **);
int		 cmd_dump(int, char **);
int		 cmd_messages(int, char **);
int		 cmd_sqlite(int, char **);

#endif
