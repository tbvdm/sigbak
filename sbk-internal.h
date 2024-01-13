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

#ifndef SBK_INTERNAL_H
#define SBK_INTERNAL_H

#include <sys/tree.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <sqlite3.h>

#include "sbk.h"

#define SBK_IV_LEN		16
#define SBK_KEY_LEN		32
#define SBK_CIPHER_KEY_LEN	32
#define SBK_MAC_KEY_LEN		32
#define SBK_DERIV_KEY_LEN	(SBK_CIPHER_KEY_LEN + SBK_MAC_KEY_LEN)
#define SBK_MAC_LEN		10
#define SBK_ROUNDS		250000
#define SBK_HKDF_INFO		"Backup Export"

#define SBK_MENTION_PLACEHOLDER	"\357\277\274"	/* U+FFFC */
#define SBK_MENTION_PREFIX	"@"

/* Based on SignalDatabaseMigrations.kt in the Signal-Android repository */
#define SBK_DB_VERSION_QUOTED_REPLIES			  7
#define SBK_DB_VERSION_RECIPIENT_IDS			 24
#define SBK_DB_VERSION_REACTIONS			 37
#define SBK_DB_VERSION_SPLIT_PROFILE_NAMES		 43
#define SBK_DB_VERSION_MENTIONS				 68
#define SBK_DB_VERSION_THREAD_AUTOINCREMENT		108
#define SBK_DB_VERSION_REACTION_REFACTOR		121
#define SBK_DB_VERSION_THREAD_AND_MESSAGE_FOREIGN_KEYS	166
#define SBK_DB_VERSION_SINGLE_MESSAGE_TABLE_MIGRATION	168
#define SBK_DB_VERSION_REACTION_FOREIGN_KEY_MIGRATION	174
#define SBK_DB_VERSION_MESSAGE_RECIPIENTS_AND_EDIT_MESSAGE_MIGRATION 185
#define SBK_DB_VERSION_RESET_PNI_COLUMN			200
#define SBK_DB_VERSION_RECIPIENT_TABLE_VALIDATIONS	201

#define XSTRINGIFY(x)	#x
#define STRINGIFY(x)	XSTRINGIFY(x)

enum sbk_frame_state {
	SBK_FIRST_FRAME,	/* We're about to read the first frame */
	SBK_LAST_FRAME,		/* We've read the last frame */
	SBK_OTHER_FRAME		/* We're somewhere in between */
};

struct sbk_file {
	off_t		 pos;
	uint32_t	 len;
	uint32_t	 counter;
};

struct sbk_attachment_entry {
	struct sbk_attachment_id id;
	struct sbk_file	*file;
	RB_ENTRY(sbk_attachment_entry) entries;
};

RB_HEAD(sbk_attachment_tree, sbk_attachment_entry);

struct sbk_recipient_id {
	char		*old;	/* For older databases */
	int		 new;	/* For newer databases */
};

struct sbk_recipient_entry {
	struct sbk_recipient_id id;
	struct sbk_recipient recipient;
	RB_ENTRY(sbk_recipient_entry) entries;
};

RB_HEAD(sbk_recipient_tree, sbk_recipient_entry);

struct sbk_ctx {
	FILE		*fp;
	sqlite3		*db;
	unsigned int	 backup_version;
	unsigned int	 db_version;
	struct sbk_attachment_tree attachments;
	struct sbk_recipient_tree recipients;
	EVP_CIPHER_CTX	*cipher_ctx;
	HMAC_CTX	*hmac_ctx;
	unsigned char	 cipher_key[SBK_CIPHER_KEY_LEN];
	unsigned char	 mac_key[SBK_MAC_KEY_LEN];
	unsigned char	 iv[SBK_IV_LEN];
	uint32_t	 counter;
	uint32_t	 counter_start;
	enum sbk_frame_state state;
	unsigned char	*ibuf;
	size_t		 ibufsize;
	unsigned char	*obuf;
	size_t		 obufsize;
};

/* sbk-attachment-tree.c */
void	 sbk_free_attachment_tree(struct sbk_ctx *);
struct sbk_file *sbk_get_attachment_file(struct sbk_ctx *,
	    const struct sbk_attachment_id *);
int	 sbk_insert_attachment_entry(struct sbk_ctx *, Signal__BackupFrame *,
	    struct sbk_file *);

/* sbk-attachment.c */
void	 sbk_free_attachment(struct sbk_attachment *);
int	 sbk_get_attachments_for_edit(struct sbk_ctx *, struct sbk_edit *);
int	 sbk_get_attachments_for_message(struct sbk_ctx *,
	    struct sbk_message *);
int	 sbk_get_attachments_for_quote(struct sbk_ctx *, struct sbk_quote *,
	    struct sbk_message_id *);

/* sbk-database.c */
int	 sbk_create_database(struct sbk_ctx *);

/* sbk-edit.c */
void	 sbk_free_edit_list(struct sbk_edit_list *);
int	 sbk_get_edits(struct sbk_ctx *, struct sbk_message *);

/* sbk-file.c */
char	*sbk_get_file_data_as_string(struct sbk_ctx *, struct sbk_file *);

/* sbk-frame.c */
Signal__BackupFrame *sbk_get_first_frame(struct sbk_ctx *);

/* sbk-mention.c */
void	 sbk_free_mention_list(struct sbk_mention_list *);
int	 sbk_get_mentions_for_edit(struct sbk_ctx *, struct sbk_edit *);
int	 sbk_get_mentions_for_message(struct sbk_ctx *, struct sbk_message *);
int	 sbk_get_mentions_for_quote(struct sbk_ctx *,
	    struct sbk_mention_list **, sqlite3_stmt *, int);
int	 sbk_insert_mentions(char **, struct sbk_mention_list *);

/* sbk-message.c */
int	 sbk_get_long_message(struct sbk_ctx *, char **,
	    struct sbk_attachment_list **);

/* sbk-quote.c */
void	 sbk_free_quote(struct sbk_quote *);
int	 sbk_get_quote(struct sbk_ctx *, struct sbk_quote **, sqlite3_stmt *,
	    int, int, int, int, struct sbk_message_id *);

/* sbk-reaction.c */
void	 sbk_free_reaction_list(struct sbk_reaction_list *);
int	 sbk_get_reactions_from_column(struct sbk_ctx *,
	    struct sbk_reaction_list **, sqlite3_stmt *, int);
int	 sbk_get_reactions_from_table(struct sbk_ctx *, struct sbk_message *);

/* sbk-read.c */
int	 sbk_decrypt_final(struct sbk_ctx *, size_t *, const unsigned char *);
int	 sbk_decrypt_init(struct sbk_ctx *, uint32_t);
int	 sbk_decrypt_update(struct sbk_ctx *, size_t, size_t *);
int	 sbk_grow_buffers(struct sbk_ctx *, size_t);
int	 sbk_read(struct sbk_ctx *, void *, size_t);

/* sbk-recipient-tree.c */
void	 sbk_free_recipient_tree(struct sbk_ctx *);
struct sbk_recipient *sbk_get_recipient_from_aci(struct sbk_ctx *,
	    const char *);
struct sbk_recipient *sbk_get_recipient_from_id(struct sbk_ctx *,
	    struct sbk_recipient_id *);
struct sbk_recipient *sbk_get_recipient_from_id_from_column(struct sbk_ctx *,
	    sqlite3_stmt *, int);

/* sbk-sqlite.c */
int	 sbk_sqlite_bind_blob(struct sbk_ctx *, sqlite3_stmt *, int,
	    const void *, size_t);
int	 sbk_sqlite_bind_double(struct sbk_ctx *, sqlite3_stmt *, int, double);
int	 sbk_sqlite_bind_int(struct sbk_ctx *, sqlite3_stmt *, int, int);
int	 sbk_sqlite_bind_int64(struct sbk_ctx *, sqlite3_stmt *, int,
	    sqlite3_int64);
int	 sbk_sqlite_bind_null(struct sbk_ctx *, sqlite3_stmt *, int);
int	 sbk_sqlite_bind_text(struct sbk_ctx *, sqlite3_stmt *, int,
	    const char *);
int	 sbk_sqlite_column_text_copy(struct sbk_ctx *, char **, sqlite3_stmt *,
	    int);
int	 sbk_sqlite_exec(struct sbk_ctx *, const char *);
int	 sbk_sqlite_open(sqlite3 **, const char *);
int	 sbk_sqlite_prepare(struct sbk_ctx *, sqlite3_stmt **, const char *);
int	 sbk_sqlite_step(struct sbk_ctx *, sqlite3_stmt *);
void	 sbk_sqlite_warn(struct sbk_ctx *, const char *, ...);
void	 sbk_sqlite_warnd(sqlite3 *, const char *, ...);

#endif
