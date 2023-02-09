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

#include <sys/tree.h>

#include <err.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <sqlite3.h>

#include "sigbak.h"

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

enum sbk_frame_state {
	SBK_FIRST_FRAME,	/* We're about to read the first frame */
	SBK_LAST_FRAME,		/* We've read the last frame */
	SBK_OTHER_FRAME		/* We're somewhere in between */
};

struct sbk_file {
	long		 pos;
	uint32_t	 len;
	uint32_t	 counter;
};

struct sbk_attachment_entry {
	int64_t		 rowid;
	int64_t		 attachmentid;
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

static int	sbk_cmp_attachment_entries(struct sbk_attachment_entry *,
		    struct sbk_attachment_entry *);
static int	sbk_cmp_recipient_entries(struct sbk_recipient_entry *,
		    struct sbk_recipient_entry *);

RB_GENERATE_STATIC(sbk_attachment_tree, sbk_attachment_entry, entries,
    sbk_cmp_attachment_entries)

RB_GENERATE_STATIC(sbk_recipient_tree, sbk_recipient_entry, entries,
    sbk_cmp_recipient_entries)

static void
sbk_sqlite_vwarnd(sqlite3 *db, const char *fmt, va_list ap)
{
	char *msg;

	if (fmt == NULL)
		warnx("%s", sqlite3_errmsg(db));
	else {
		if (vasprintf(&msg, fmt, ap) == -1) {
			warnx("vasprintf() failed");
			return;
		}
		warnx("%s: %s", msg, sqlite3_errmsg(db));
		free(msg);
	}
}

static void
sbk_sqlite_warnd(sqlite3 *db, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sbk_sqlite_vwarnd(db, fmt, ap);
	va_end(ap);
}

static void
sbk_sqlite_warn(struct sbk_ctx *ctx, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sbk_sqlite_vwarnd(ctx->db, fmt, ap);
	va_end(ap);
}

static int
sbk_enlarge_buffers(struct sbk_ctx *ctx, size_t size)
{
	unsigned char *buf;

	if (ctx->ibufsize < size) {
		if ((buf = realloc(ctx->ibuf, size)) == NULL) {
			warn(NULL);
			return -1;
		}
		ctx->ibuf = buf;
		ctx->ibufsize = size;
	}

	if (size > SIZE_MAX - EVP_MAX_BLOCK_LENGTH) {
		warnx("Buffer size too large");
		return -1;
	}

	size += EVP_MAX_BLOCK_LENGTH;

	if (ctx->obufsize < size) {
		if ((buf = realloc(ctx->obuf, size)) == NULL) {
			warn(NULL);
			return -1;
		}
		ctx->obuf = buf;
		ctx->obufsize = size;
	}

	return 0;
}

static int
sbk_decrypt_init(struct sbk_ctx *ctx, uint32_t counter)
{
	if (!HMAC_Init_ex(ctx->hmac_ctx, NULL, 0, NULL, NULL)) {
		warnx("Cannot initialise MAC context");
		return -1;
	}

	ctx->iv[0] = counter >> 24;
	ctx->iv[1] = counter >> 16;
	ctx->iv[2] = counter >> 8;
	ctx->iv[3] = counter;

	if (!EVP_DecryptInit_ex(ctx->cipher_ctx, NULL, NULL, ctx->cipher_key,
	    ctx->iv)) {
		warnx("Cannot initialise cipher context");
		return -1;
	}

	return 0;
}

static int
sbk_decrypt_update(struct sbk_ctx *ctx, size_t ibuflen, size_t *obuflen)
{
	int len;

	if (!HMAC_Update(ctx->hmac_ctx, ctx->ibuf, ibuflen)) {
		warnx("Cannot compute MAC");
		return -1;
	}

	if (!EVP_DecryptUpdate(ctx->cipher_ctx, ctx->obuf, &len, ctx->ibuf,
	    ibuflen)) {
		warnx("Cannot decrypt data");
		return -1;
	}

	*obuflen = len;
	return 0;
}

static int
sbk_decrypt_final(struct sbk_ctx *ctx, size_t *obuflen,
    const unsigned char *theirmac)
{
	unsigned char	ourmac[EVP_MAX_MD_SIZE];
	unsigned int	ourmaclen;
	int		len;

	if (!HMAC_Final(ctx->hmac_ctx, ourmac, &ourmaclen)) {
		warnx("Cannot compute MAC");
		return -1;
	}

	if (memcmp(ourmac, theirmac, SBK_MAC_LEN) != 0) {
		warnx("MAC mismatch");
		return -1;
	}

	if (!EVP_DecryptFinal_ex(ctx->cipher_ctx, ctx->obuf + *obuflen,
	    &len)) {
		warnx("Cannot decrypt data");
		return -1;
	}

	*obuflen += len;
	return 0;
}

static int
sbk_read(struct sbk_ctx *ctx, void *ptr, size_t size)
{
	if (fread(ptr, size, 1, ctx->fp) != 1) {
		if (ferror(ctx->fp))
			warn(NULL);
		else
			warnx("Unexpected end of file");
		return -1;
	}

	return 0;
}

static int
sbk_read_frame(struct sbk_ctx *ctx, size_t *frmlen)
{
	int32_t		len;
	unsigned char	lenbuf[4];

	if (sbk_read(ctx, lenbuf, sizeof lenbuf) == -1)
		return -1;

	len = (lenbuf[0] << 24) | (lenbuf[1] << 16) | (lenbuf[2] << 8) |
	    lenbuf[3];

	if (len <= 0) {
		warnx("Invalid frame size");
		return -1;
	}

	if (sbk_enlarge_buffers(ctx, len) == -1)
		return -1;

	if (sbk_read(ctx, ctx->ibuf, len) == -1)
		return -1;

	*frmlen = len;
	return 0;
}

static int
sbk_has_file_data(Signal__BackupFrame *frm)
{
	return frm->attachment != NULL || frm->avatar != NULL ||
	    frm->sticker != NULL;
}

static int
sbk_skip_file_data(struct sbk_ctx *ctx, Signal__BackupFrame *frm)
{
	uint32_t len;

	if (frm->attachment != NULL && frm->attachment->has_length)
		len = frm->attachment->length;
	else if (frm->avatar != NULL && frm->avatar->has_length)
		len = frm->avatar->length;
	else if (frm->sticker != NULL && frm->sticker->has_length)
		len = frm->sticker->length;
	else {
		warnx("Invalid frame");
		return -1;
	}

	if (fseek(ctx->fp, len + SBK_MAC_LEN, SEEK_CUR) == -1) {
		warn("Cannot seek");
		return -1;
	}

	ctx->counter++;
	return 0;
}

static Signal__BackupFrame *
sbk_unpack_frame(unsigned char *buf, size_t len)
{
	Signal__BackupFrame *frm;

	if ((frm = signal__backup_frame__unpack(NULL, len, buf)) == NULL)
		warnx("Cannot unpack frame");

	return frm;
}

static struct sbk_file *
sbk_get_file(struct sbk_ctx *ctx, Signal__BackupFrame *frm)
{
	struct sbk_file *file;

	if ((file = malloc(sizeof *file)) == NULL) {
		warn(NULL);
		return NULL;
	}

	if ((file->pos = ftell(ctx->fp)) == -1) {
		warn(NULL);
		goto error;
	}

	if (frm->attachment != NULL) {
		if (!frm->attachment->has_length) {
			warnx("Invalid attachment frame");
			goto error;
		}
		file->len = frm->attachment->length;
	} else if (frm->avatar != NULL) {
		if (!frm->avatar->has_length) {
			warnx("Invalid avatar frame");
			goto error;
		}
		file->len = frm->avatar->length;
	} else if (frm->sticker != NULL) {
		if (!frm->sticker->has_length) {
			warnx("Invalid sticker frame");
			goto error;
		}
		file->len = frm->sticker->length;
	}

	file->counter = ctx->counter;
	return file;

error:
	sbk_free_file(file);
	return NULL;
}

Signal__BackupFrame *
sbk_get_frame(struct sbk_ctx *ctx, struct sbk_file **file)
{
	Signal__BackupFrame	*frm;
	size_t			 ibuflen, obuflen;
	unsigned char		*mac;

	if (file != NULL)
		*file = NULL;

	if (ctx->state == SBK_LAST_FRAME)
		return NULL;

	if (sbk_read_frame(ctx, &ibuflen) == -1)
		return NULL;

	/* The first frame is not encrypted */
	if (ctx->state == SBK_FIRST_FRAME) {
		ctx->state = SBK_OTHER_FRAME;
		return sbk_unpack_frame(ctx->ibuf, ibuflen);
	}

	if (ibuflen <= SBK_MAC_LEN) {
		warnx("Invalid frame size");
		return NULL;
	}

	ibuflen -= SBK_MAC_LEN;
	mac = ctx->ibuf + ibuflen;

	if (sbk_decrypt_init(ctx, ctx->counter) == -1)
		return NULL;

	if (sbk_decrypt_update(ctx, ibuflen, &obuflen) == -1)
		return NULL;

	if (sbk_decrypt_final(ctx, &obuflen, mac) == -1)
		return NULL;

	if ((frm = sbk_unpack_frame(ctx->obuf, obuflen)) == NULL)
		return NULL;

	if (frm->has_end)
		ctx->state = SBK_LAST_FRAME;

	ctx->counter++;

	if (sbk_has_file_data(frm)) {
		if (file == NULL) {
			if (sbk_skip_file_data(ctx, frm) == -1) {
				sbk_free_frame(frm);
				return NULL;
			}
		} else {
			if ((*file = sbk_get_file(ctx, frm)) == NULL) {
				sbk_free_frame(frm);
				return NULL;
			}
			if (sbk_skip_file_data(ctx, frm) == -1) {
				sbk_free_frame(frm);
				sbk_free_file(*file);
				return NULL;
			}
		}
	}

	return frm;
}

void
sbk_free_frame(Signal__BackupFrame *frm)
{
	if (frm != NULL)
		signal__backup_frame__free_unpacked(frm, NULL);
}

void
sbk_free_file(struct sbk_file *file)
{
	free(file);
}

int
sbk_write_file(struct sbk_ctx *ctx, struct sbk_file *file, FILE *fp)
{
	size_t		ibuflen, len, obuflen;
	unsigned char	mac[SBK_MAC_LEN];

	if (sbk_enlarge_buffers(ctx, BUFSIZ) == -1)
		return -1;

	if (fseek(ctx->fp, file->pos, SEEK_SET) == -1) {
		warn("Cannot seek");
		return -1;
	}

	if (sbk_decrypt_init(ctx, file->counter) == -1)
		return -1;

	if (!HMAC_Update(ctx->hmac_ctx, ctx->iv, SBK_IV_LEN)) {
		warnx("Cannot compute MAC");
		return -1;
	}

	for (len = file->len; len > 0; len -= ibuflen) {
		ibuflen = (len < BUFSIZ) ? len : BUFSIZ;

		if (sbk_read(ctx, ctx->ibuf, ibuflen) == -1)
			return -1;

		if (sbk_decrypt_update(ctx, ibuflen, &obuflen) == -1)
			return -1;

		if (fp != NULL && fwrite(ctx->obuf, obuflen, 1, fp) != 1) {
			warn("Cannot write file");
			return -1;
		}
	}

	if (sbk_read(ctx, mac, sizeof mac) == -1)
		return -1;

	obuflen = 0;

	if (sbk_decrypt_final(ctx, &obuflen, mac) == -1)
		return -1;

	if (obuflen > 0 && fp != NULL && fwrite(ctx->obuf, obuflen, 1, fp) !=
	    1) {
		warn("Cannot write file");
		return -1;
	}

	return 0;
}

static char *
sbk_decrypt_file_data(struct sbk_ctx *ctx, struct sbk_file *file,
    size_t *buflen, int terminate)
{
	size_t		 ibuflen, len, obuflen, obufsize;
	unsigned char	 mac[SBK_MAC_LEN];
	char		*obuf, *ptr;

	if (buflen != NULL)
		*buflen = 0;

	if (sbk_enlarge_buffers(ctx, BUFSIZ) == -1)
		return NULL;

	if (fseek(ctx->fp, file->pos, SEEK_SET) == -1) {
		warn("Cannot seek");
		return NULL;
	}

	if (terminate)
		terminate = 1;

	if ((size_t)file->len > SIZE_MAX - EVP_MAX_BLOCK_LENGTH - terminate) {
		warnx("File too large");
		return NULL;
	}

	obufsize = file->len + EVP_MAX_BLOCK_LENGTH + terminate;

	if ((obuf = malloc(obufsize)) == NULL) {
		warn(NULL);
		return NULL;
	}

	if (sbk_decrypt_init(ctx, file->counter) == -1)
		goto error;

	if (!HMAC_Update(ctx->hmac_ctx, ctx->iv, SBK_IV_LEN)) {
		warnx("Cannot compute MAC");
		goto error;
	}

	ptr = obuf;

	for (len = file->len; len > 0; len -= ibuflen) {
		ibuflen = (len < BUFSIZ) ? len : BUFSIZ;

		if (sbk_read(ctx, ctx->ibuf, ibuflen) == -1)
			goto error;

		if (sbk_decrypt_update(ctx, ibuflen, &obuflen) == -1)
			goto error;

		memcpy(ptr, ctx->obuf, obuflen);
		ptr += obuflen;
	}

	if (sbk_read(ctx, mac, sizeof mac) == -1)
		goto error;

	obuflen = 0;

	if (sbk_decrypt_final(ctx, &obuflen, mac) == -1)
		goto error;

	if (obuflen > 0) {
		memcpy(ptr, ctx->obuf, obuflen);
		ptr += obuflen;
	}

	if (terminate)
		*ptr = '\0';

	if (buflen != NULL)
		*buflen = ptr - obuf;

	return obuf;

error:
	free(obuf);
	return NULL;
}

char *
sbk_get_file_data(struct sbk_ctx *ctx, struct sbk_file *file, size_t *len)
{
	return sbk_decrypt_file_data(ctx, file, len, 0);
}

static char *
sbk_get_file_data_as_string(struct sbk_ctx *ctx, struct sbk_file *file)
{
	return sbk_decrypt_file_data(ctx, file, NULL, 1);
}

static int
sbk_sqlite_bind_blob(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx,
    const void *val, size_t len)
{
	if (sqlite3_bind_blob(stm, idx, val, len, SQLITE_STATIC) !=
	    SQLITE_OK) {
		sbk_sqlite_warn(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_bind_double(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx,
    double val)
{
	if (sqlite3_bind_double(stm, idx, val) != SQLITE_OK) {
		sbk_sqlite_warn(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_bind_int(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx, int val)
{
	if (sqlite3_bind_int(stm, idx, val) != SQLITE_OK) {
		sbk_sqlite_warn(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_bind_int64(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx,
    sqlite3_int64 val)
{
	if (sqlite3_bind_int64(stm, idx, val) != SQLITE_OK) {
		sbk_sqlite_warn(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_bind_null(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx)
{
	if (sqlite3_bind_null(stm, idx) != SQLITE_OK) {
		sbk_sqlite_warn(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_bind_text(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx,
    const char *val)
{
	if (sqlite3_bind_text(stm, idx, val, -1, SQLITE_STATIC) != SQLITE_OK) {
		sbk_sqlite_warn(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_column_text_copy(struct sbk_ctx *ctx, char **buf, sqlite3_stmt *stm,
    int idx)
{
#ifdef notyet
	const unsigned char	*txt;
	int			 len;

	*buf = NULL;

	if (sqlite3_column_type(stm, idx) == SQLITE_NULL)
		return 0;

	if ((txt = sqlite3_column_text(stm, idx)) == NULL) {
		sbk_sqlite_warn(ctx, "Cannot get column text");
		return -1;
	}

	if ((len = sqlite3_column_bytes(stm, idx)) < 0) {
		sbk_sqlite_warn(ctx, "Cannot get column size");
		return -1;
	}

	if ((*buf = malloc((size_t)len + 1)) == NULL) {
		warn(NULL);
		return -1;
	}

	memcpy(*buf, txt, (size_t)len + 1);
	return len;
#else
	const unsigned char *txt;

	*buf = NULL;

	if (sqlite3_column_type(stm, idx) == SQLITE_NULL)
		return 0;

	if ((txt = sqlite3_column_text(stm, idx)) == NULL) {
		sbk_sqlite_warn(ctx, "Cannot get column text");
		return -1;
	}

	if ((*buf = strdup((const char *)txt)) == NULL) {
		warn(NULL);
		return -1;
	}

	return 0;
#endif
}

static int
sbk_sqlite_open(sqlite3 **db, const char *path)
{
	if (sqlite3_open(path, db) != SQLITE_OK) {
		sbk_sqlite_warnd(*db, "Cannot open database");
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_prepare(struct sbk_ctx *ctx, sqlite3_stmt **stm, const char *query)
{
	if (sqlite3_prepare_v2(ctx->db, query, -1, stm, NULL) != SQLITE_OK) {
		sbk_sqlite_warn(ctx, "Cannot prepare SQL statement");
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_step(struct sbk_ctx *ctx, sqlite3_stmt *stm)
{
	int ret;

	ret = sqlite3_step(stm);
	if (ret != SQLITE_ROW && ret != SQLITE_DONE)
		sbk_sqlite_warn(ctx, "Cannot execute SQL statement");

	return ret;
}

static int
sbk_sqlite_exec(struct sbk_ctx *ctx, const char *sql)
{
	char *errmsg;

	if (sqlite3_exec(ctx->db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
		warnx("Cannot execute SQL statement: %s", errmsg);
		sqlite3_free(errmsg);
		return -1;
	}

	return 0;
}

static int
sbk_cmp_attachment_entries(struct sbk_attachment_entry *a,
    struct sbk_attachment_entry *b)
{
	if (a->rowid < b->rowid)
		return -1;

	if (a->rowid > b->rowid)
		return 1;

	return (a->attachmentid < b->attachmentid) ? -1 :
	    (a->attachmentid > b->attachmentid);
}

static int
sbk_insert_attachment_entry(struct sbk_ctx *ctx, Signal__BackupFrame *frm,
    struct sbk_file *file)
{
	struct sbk_attachment_entry *entry;

	if (!frm->attachment->has_rowid ||
	    !frm->attachment->has_attachmentid) {
		warnx("Invalid attachment frame");
		sbk_free_file(file);
		return -1;
	}

	if ((entry = malloc(sizeof *entry)) == NULL) {
		warn(NULL);
		sbk_free_file(file);
		return -1;
	}

	entry->rowid = frm->attachment->rowid;
	entry->attachmentid = frm->attachment->attachmentid;
	entry->file = file;
	RB_INSERT(sbk_attachment_tree, &ctx->attachments, entry);
	return 0;
}

static struct sbk_file *
sbk_get_attachment_file(struct sbk_ctx *ctx, int64_t rowid,
    int64_t attachmentid)
{
	struct sbk_attachment_entry find, *result;

	find.rowid = rowid;
	find.attachmentid = attachmentid;
	result = RB_FIND(sbk_attachment_tree, &ctx->attachments, &find);
	return (result != NULL) ? result->file : NULL;
}

static void
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
sbk_bind_param(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx,
    Signal__SqlStatement__SqlParameter *par)
{
	if (par->stringparamter != NULL)
		return sbk_sqlite_bind_text(ctx, stm, idx,
		    par->stringparamter);

	if (par->has_integerparameter)
		return sbk_sqlite_bind_int64(ctx, stm, idx,
		    par->integerparameter);

	if (par->has_doubleparameter)
		return sbk_sqlite_bind_double(ctx, stm, idx,
		    par->doubleparameter);

	if (par->has_blobparameter)
		return sbk_sqlite_bind_blob(ctx, stm, idx,
		    par->blobparameter.data, par->blobparameter.len);

	if (par->has_nullparameter)
		return sbk_sqlite_bind_null(ctx, stm, idx);

	warnx("Unknown SQL parameter type");
	return -1;
}

static int
sbk_exec_statement(struct sbk_ctx *ctx, Signal__SqlStatement *sql)
{
	sqlite3_stmt	*stm;
	size_t		 i;

	if (sql->statement == NULL) {
		warnx("Invalid SQL frame");
		return -1;
	}

	/* Don't try to create tables with reserved names */
	if (strncasecmp(sql->statement, "create table sqlite_", 20) == 0)
		return 0;

	if (sbk_sqlite_prepare(ctx, &stm, sql->statement) == -1)
		return -1;

	for (i = 0; i < sql->n_parameters; i++)
		if (sbk_bind_param(ctx, stm, i + 1, sql->parameters[i]) == -1)
			goto error;

	if (sbk_sqlite_step(ctx, stm) != SQLITE_DONE)
		goto error;

	sqlite3_finalize(stm);
	return 0;

error:
	sqlite3_finalize(stm);
	return -1;
}

static int
sbk_set_database_version(struct sbk_ctx *ctx, Signal__DatabaseVersion *ver)
{
	char	*sql;
	int	 ret;

	if (!ver->has_version) {
		warnx("Invalid version frame");
		return -1;
	}

	ctx->db_version = ver->version;

	if (asprintf(&sql, "PRAGMA user_version = %" PRIu32, ver->version) ==
	    -1) {
		warnx("asprintf() failed");
		return -1;
	}

	ret = sbk_sqlite_exec(ctx, sql);
	free(sql);
	return ret;
}

static int
sbk_create_database(struct sbk_ctx *ctx)
{
	Signal__BackupFrame	*frm;
	struct sbk_file		*file;
	int			 ret;

	if (ctx->db != NULL)
		return 0;

	if (sbk_sqlite_open(&ctx->db, ":memory:") == -1)
		goto error;

	if (sbk_rewind(ctx) == -1)
		goto error;

	if (sbk_sqlite_exec(ctx, "BEGIN TRANSACTION") == -1)
		goto error;

	ret = 0;

	while ((frm = sbk_get_frame(ctx, &file)) != NULL) {
		if (frm->version != NULL)
			ret = sbk_set_database_version(ctx, frm->version);
		else if (frm->statement != NULL)
			ret = sbk_exec_statement(ctx, frm->statement);
		else if (frm->attachment != NULL)
			ret = sbk_insert_attachment_entry(ctx, frm, file);
		else
			sbk_free_file(file);

		sbk_free_frame(frm);

		if (ret == -1)
			goto error;
	}

	if (sbk_sqlite_exec(ctx, "END TRANSACTION") == -1)
		goto error;

	if (ctx->state != SBK_LAST_FRAME)
		goto error;

	return 0;

error:
	sbk_free_attachment_tree(ctx);
	sqlite3_close(ctx->db);
	ctx->db = NULL;
	return -1;
}

int
sbk_write_database(struct sbk_ctx *ctx, const char *path)
{
	sqlite3		*db;
	sqlite3_backup	*bak;
	int		 ret;

	if (sbk_create_database(ctx) == -1)
		return -1;

	if (sbk_sqlite_open(&db, path) == -1)
		goto error;

	if ((bak = sqlite3_backup_init(db, "main", ctx->db, "main")) == NULL) {
		sbk_sqlite_warnd(db, "Cannot write database");
		goto error;
	}

	if ((ret = sqlite3_backup_step(bak, -1)) != SQLITE_DONE) {
		warnx("Cannot write database: %s", sqlite3_errstr(ret));
		sqlite3_backup_finish(bak);
		goto error;
	}

	sqlite3_backup_finish(bak);

	if (sqlite3_close(db) != SQLITE_OK) {
		sbk_sqlite_warnd(db, "Cannot close database");
		return -1;
	}

	return 0;

error:
	sqlite3_close(db);
	return -1;
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

static void
sbk_free_recipient_entry(struct sbk_recipient_entry *ent)
{
	if (ent == NULL)
		return;

	switch (ent->recipient.type) {
	case SBK_CONTACT:
		if (ent->recipient.contact != NULL) {
			free(ent->recipient.contact->uuid);
			free(ent->recipient.contact->phone);
			free(ent->recipient.contact->email);
			free(ent->recipient.contact->system_display_name);
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

static void
sbk_free_recipient_tree(struct sbk_ctx *ctx)
{
	struct sbk_recipient_entry *ent;

	while ((ent = RB_ROOT(&ctx->recipients)) != NULL) {
		RB_REMOVE(sbk_recipient_tree, &ctx->recipients, ent);
		sbk_free_recipient_entry(ent);
	}
}

/* For database versions < RECIPIENT_IDS */
#define SBK_RECIPIENTS_QUERY_1						\
	"SELECT "							\
	"r.recipient_ids, "						\
	"NULL, "			/* uuid */			\
	"NULL, "			/* phone */			\
	"NULL, "			/* email */			\
	"r.system_display_name, "					\
	"r.system_phone_label, "					\
	"r.signal_profile_name, "					\
	"NULL, "			/* profile_family_name */	\
	"NULL, "			/* profile_joined_name */	\
	"g.group_id, "							\
	"g.title "							\
	"FROM recipient_preferences AS r "				\
	"LEFT JOIN groups AS g "					\
	"ON r.recipient_ids = g.group_id"

/* For database versions [RECIPIENT_IDS, SPLIT_PROFILE_NAMES) */
#define SBK_RECIPIENTS_QUERY_2						\
	"SELECT "							\
	"r._id, "							\
	"r.uuid, "							\
	"r.phone, "							\
	"r.email, "							\
	"r.system_display_name, "					\
	"r.system_phone_label, "					\
	"r.signal_profile_name, "					\
	"NULL, "			/* profile_family_name */	\
	"NULL, "			/* profile_joined_name */	\
	"g.group_id, "							\
	"g.title "							\
	"FROM recipient AS r "						\
	"LEFT JOIN groups AS g "					\
	"ON r._id = g.recipient_id"

/* For database versions >= SPLIT_PROFILE_NAMES */
#define SBK_RECIPIENTS_QUERY_3						\
	"SELECT "							\
	"r._id, "							\
	"r.uuid, "							\
	"r.phone, "							\
	"r.email, "							\
	"r.system_display_name, "					\
	"r.system_phone_label, "					\
	"r.signal_profile_name, "					\
	"r.profile_family_name, "					\
	"r.profile_joined_name, "					\
	"g.group_id, "							\
	"g.title "							\
	"FROM recipient AS r "						\
	"LEFT JOIN groups AS g "					\
	"ON r._id = g.recipient_id"

#define SBK_RECIPIENTS_COLUMN__ID			0
#define SBK_RECIPIENTS_COLUMN_UUID			1
#define SBK_RECIPIENTS_COLUMN_PHONE			2
#define SBK_RECIPIENTS_COLUMN_EMAIL			3
#define SBK_RECIPIENTS_COLUMN_SYSTEM_DISPLAY_NAME	4
#define SBK_RECIPIENTS_COLUMN_SYSTEM_PHONE_LABEL	5
#define SBK_RECIPIENTS_COLUMN_SIGNAL_PROFILE_NAME	6
#define SBK_RECIPIENTS_COLUMN_PROFILE_FAMILY_NAME	7
#define SBK_RECIPIENTS_COLUMN_PROFILE_JOINED_NAME	8
#define SBK_RECIPIENTS_COLUMN_GROUP_ID			9
#define SBK_RECIPIENTS_COLUMN_TITLE			10

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
	    SBK_RECIPIENTS_COLUMN__ID) == -1)
		goto error;

	if (sqlite3_column_type(stm, SBK_RECIPIENTS_COLUMN_GROUP_ID) ==
	    SQLITE_NULL)
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
			    stm, SBK_RECIPIENTS_COLUMN_PHONE) == -1)
				goto error;

			if (sbk_sqlite_column_text_copy(ctx, &con->email,
			    stm, SBK_RECIPIENTS_COLUMN_EMAIL) == -1)
				goto error;
		}

		if (sbk_sqlite_column_text_copy(ctx, &con->uuid,
		    stm, SBK_RECIPIENTS_COLUMN_UUID) == -1)
			goto error;

		if (sbk_sqlite_column_text_copy(ctx, &con->system_display_name,
		    stm, SBK_RECIPIENTS_COLUMN_SYSTEM_DISPLAY_NAME) == -1)
			goto error;

		if (sbk_sqlite_column_text_copy(ctx, &con->system_phone_label,
		    stm, SBK_RECIPIENTS_COLUMN_SYSTEM_PHONE_LABEL) == -1)
			goto error;

		if (sbk_sqlite_column_text_copy(ctx, &con->profile_given_name,
		    stm, SBK_RECIPIENTS_COLUMN_SIGNAL_PROFILE_NAME) == -1)
			goto error;

		if (sbk_sqlite_column_text_copy(ctx, &con->profile_family_name,
		    stm, SBK_RECIPIENTS_COLUMN_PROFILE_FAMILY_NAME) == -1)
			goto error;

		if (sbk_sqlite_column_text_copy(ctx, &con->profile_joined_name,
		    stm, SBK_RECIPIENTS_COLUMN_PROFILE_JOINED_NAME) == -1)
			goto error;

		break;

	case SBK_GROUP:
		grp = ent->recipient.group = calloc(1, sizeof *grp);
		if (grp == NULL) {
			warn(NULL);
			goto error;
		}

		if (sbk_sqlite_column_text_copy(ctx, &grp->name,
		    stm, SBK_RECIPIENTS_COLUMN_TITLE) == -1)
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
		query = SBK_RECIPIENTS_QUERY_1;
	else if (ctx->db_version < SBK_DB_VERSION_SPLIT_PROFILE_NAMES)
		query = SBK_RECIPIENTS_QUERY_2;
	else
		query = SBK_RECIPIENTS_QUERY_3;

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

static struct sbk_recipient *
sbk_get_recipient(struct sbk_ctx *ctx, struct sbk_recipient_id *id)
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

static struct sbk_recipient *
sbk_get_recipient_from_column(struct sbk_ctx *ctx, sqlite3_stmt *stm,
    int idx)
{
	struct sbk_recipient	*rcp;
	struct sbk_recipient_id	 id;

	if (sbk_get_recipient_id_from_column(ctx, &id, stm, idx) == -1)
		return NULL;

	rcp = sbk_get_recipient(ctx, &id);
	free(id.old);
	return rcp;
}

static struct sbk_recipient *
sbk_get_recipient_from_uuid(struct sbk_ctx *ctx, const char *uuid)
{
	struct sbk_recipient_entry *ent;

	RB_FOREACH(ent, sbk_recipient_tree, &ctx->recipients)
		if (ent->recipient.type == SBK_CONTACT &&
		    ent->recipient.contact->uuid != NULL &&
		    strcmp(uuid, ent->recipient.contact->uuid) == 0)
			return &ent->recipient;

	return NULL;
}

const char *
sbk_get_recipient_display_name(const struct sbk_recipient *rcp)
{
	if (rcp != NULL)
		switch (rcp->type) {
		case SBK_CONTACT:
			if (rcp->contact->system_display_name != NULL)
				return rcp->contact->system_display_name;
			if (rcp->contact->profile_joined_name != NULL)
				return rcp->contact->profile_joined_name;
			if (rcp->contact->profile_given_name != NULL)
				return rcp->contact->profile_given_name;
			if (rcp->contact->phone != NULL)
				return rcp->contact->phone;
			if (rcp->contact->email != NULL)
				return rcp->contact->email;
			break;
		case SBK_GROUP:
			if (rcp->group->name != NULL)
				return rcp->group->name;
			break;
		}

	return "Unknown";
}

static void
sbk_free_attachment(struct sbk_attachment *att)
{
	if (att != NULL) {
		free(att->filename);
		free(att->content_type);
		free(att);
	}
}

void
sbk_free_attachment_list(struct sbk_attachment_list *lst)
{
	struct sbk_attachment *att;

	if (lst != NULL) {
		while ((att = TAILQ_FIRST(lst)) != NULL) {
			TAILQ_REMOVE(lst, att, entries);
			sbk_free_attachment(att);
		}
		free(lst);
	}
}

/* For database versions < QUOTED_REPLIES */
#define SBK_ATTACHMENTS_SELECT_1					\
	"SELECT "							\
	"p._id, "							\
	"p.ct, "							\
	"p.pending_push, "						\
	"p.data_size, "							\
	"p.file_name, "							\
	"p.unique_id, "							\
	"m.date, "							\
	"m.date_received, "						\
	"0 AS quote "							\
	"FROM part AS p "						\
	"LEFT JOIN mms AS m "						\
	"ON p.mid = m._id "

/* For database versions [QUOTED_REPLIES, THREAD_AND_MESSAGE_FOREIGN_KEYS) */
#define SBK_ATTACHMENTS_SELECT_2					\
	"SELECT "							\
	"p._id, "							\
	"p.ct, "							\
	"p.pending_push, "						\
	"p.data_size, "							\
	"p.file_name, "							\
	"p.unique_id, "							\
	"m.date, "							\
	"m.date_received "						\
	"FROM part AS p "						\
	"LEFT JOIN mms AS m "						\
	"ON p.mid = m._id "

/*
 * For database versions
 * [THREAD_AND_MESSAGE_FOREIGN_KEYS, REACTION_FOREIGN_KEY_MIGRATION)
 */
#define SBK_ATTACHMENTS_SELECT_3					\
	"SELECT "							\
	"p._id, "							\
	"p.ct, "							\
	"p.pending_push, "						\
	"p.data_size, "							\
	"p.file_name, "							\
	"p.unique_id, "							\
	"m.date_sent, "							\
	"m.date_received "						\
	"FROM part AS p "						\
	"LEFT JOIN mms AS m "						\
	"ON p.mid = m._id "

/* For database versions >= REACTION_FOREIGN_KEY_MIGRATION */
#define SBK_ATTACHMENTS_SELECT_4					\
	"SELECT "							\
	"p._id, "							\
	"p.ct, "							\
	"p.pending_push, "						\
	"p.data_size, "							\
	"p.file_name, "							\
	"p.unique_id, "							\
	"m.date_sent, "							\
	"m.date_received "						\
	"FROM part AS p "						\
	"LEFT JOIN message AS m "					\
	"ON p.mid = m._id "

/* For database versions < REACTION_FOREIGN_KEY_MIGRATION */
#define SBK_ATTACHMENTS_WHERE_THREAD_1					\
	"WHERE p.mid IN (SELECT _id FROM mms WHERE thread_id = ?) "

/* For database versions >= REACTION_FOREIGN_KEY_MIGRATION */
#define SBK_ATTACHMENTS_WHERE_THREAD_2					\
	"WHERE p.mid IN (SELECT _id FROM message WHERE thread_id = ?) "

#define SBK_ATTACHMENTS_WHERE_MESSAGE					\
	"WHERE p.mid = ? AND quote = 0 "

#define SBK_ATTACHMENTS_WHERE_QUOTE					\
	"WHERE p.mid = ? AND quote = 1 "

#define SBK_ATTACHMENTS_ORDER						\
	"ORDER BY p.unique_id, p._id"

/* For database versions < THREAD_AND_MESSAGE_FOREIGN_KEYS */
#define SBK_ATTACHMENTS_QUERY_THREAD_1					\
	SBK_ATTACHMENTS_SELECT_2					\
	SBK_ATTACHMENTS_WHERE_THREAD_1					\
	SBK_ATTACHMENTS_ORDER

/*
 * For database versions
 * [THREAD_AND_MESSAGE_FOREIGN_KEYS, REACTION_FOREIGN_KEY_MIGRATION)
 */
#define SBK_ATTACHMENTS_QUERY_THREAD_2					\
	SBK_ATTACHMENTS_SELECT_3					\
	SBK_ATTACHMENTS_WHERE_THREAD_1					\
	SBK_ATTACHMENTS_ORDER

/* For database versions >= REACTION_FOREIGN_KEY_MIGRATION */
#define SBK_ATTACHMENTS_QUERY_THREAD_3					\
	SBK_ATTACHMENTS_SELECT_4					\
	SBK_ATTACHMENTS_WHERE_THREAD_2					\
	SBK_ATTACHMENTS_ORDER

/* For database versions < QUOTED_REPLIES */
#define SBK_ATTACHMENTS_QUERY_MESSAGE_1					\
	SBK_ATTACHMENTS_SELECT_1					\
	SBK_ATTACHMENTS_WHERE_MESSAGE					\
	SBK_ATTACHMENTS_ORDER

/* For database versions [QUOTED_REPLIES, THREAD_AND_MESSAGE_FOREIGN_KEYS) */
#define SBK_ATTACHMENTS_QUERY_MESSAGE_2					\
	SBK_ATTACHMENTS_SELECT_2					\
	SBK_ATTACHMENTS_WHERE_MESSAGE					\
	SBK_ATTACHMENTS_ORDER

/*
 * For database versions [THREAD_AND_MESSAGE_FOREIGN_KEYS,
 * REACTION_FOREIGN_KEY_MIGRATION)
 */
#define SBK_ATTACHMENTS_QUERY_MESSAGE_3					\
	SBK_ATTACHMENTS_SELECT_3					\
	SBK_ATTACHMENTS_WHERE_MESSAGE					\
	SBK_ATTACHMENTS_ORDER

/* For database versions >= REACTION_FOREIGN_KEY_MIGRATION */
#define SBK_ATTACHMENTS_QUERY_MESSAGE_4					\
	SBK_ATTACHMENTS_SELECT_4					\
	SBK_ATTACHMENTS_WHERE_MESSAGE					\
	SBK_ATTACHMENTS_ORDER

/* For database versions < THREAD_AND_MESSAGE_FOREIGN_KEYS */
#define SBK_ATTACHMENTS_QUERY_QUOTE_1					\
	SBK_ATTACHMENTS_SELECT_2					\
	SBK_ATTACHMENTS_WHERE_QUOTE					\
	SBK_ATTACHMENTS_ORDER

/*
 * For database versions [THREAD_AND_MESSAGE_FOREIGN_KEYS,
 * REACTION_FOREIGN_KEY_MIGRATION)
 */
#define SBK_ATTACHMENTS_QUERY_QUOTE_2					\
	SBK_ATTACHMENTS_SELECT_3					\
	SBK_ATTACHMENTS_WHERE_QUOTE					\
	SBK_ATTACHMENTS_ORDER

/* For database versions >= REACTION_FOREIGN_KEY_MIGRATION */
#define SBK_ATTACHMENTS_QUERY_QUOTE_3					\
	SBK_ATTACHMENTS_SELECT_4					\
	SBK_ATTACHMENTS_WHERE_QUOTE					\
	SBK_ATTACHMENTS_ORDER

#define SBK_ATTACHMENTS_COLUMN__ID		0
#define SBK_ATTACHMENTS_COLUMN_CT		1
#define SBK_ATTACHMENTS_COLUMN_PENDING_PUSH	2
#define SBK_ATTACHMENTS_COLUMN_DATA_SIZE	3
#define SBK_ATTACHMENTS_COLUMN_FILE_NAME	4
#define SBK_ATTACHMENTS_COLUMN_UNIQUE_ID	5
#define SBK_ATTACHMENTS_COLUMN_DATE_SENT	6
#define SBK_ATTACHMENTS_COLUMN_DATE_RECEIVED	7

static struct sbk_attachment *
sbk_get_attachment(struct sbk_ctx *ctx, sqlite3_stmt *stm)
{
	struct sbk_attachment *att;

	if ((att = calloc(1, sizeof *att)) == NULL) {
		warn(NULL);
		return NULL;
	}

	if (sbk_sqlite_column_text_copy(ctx, &att->filename, stm,
	    SBK_ATTACHMENTS_COLUMN_FILE_NAME) == -1)
		goto error;

	if (sbk_sqlite_column_text_copy(ctx, &att->content_type, stm,
	    SBK_ATTACHMENTS_COLUMN_CT) == -1)
		goto error;

	att->rowid = sqlite3_column_int64(stm, SBK_ATTACHMENTS_COLUMN__ID);
	att->attachmentid = sqlite3_column_int64(stm,
	    SBK_ATTACHMENTS_COLUMN_UNIQUE_ID);
	att->status = sqlite3_column_int(stm,
	    SBK_ATTACHMENTS_COLUMN_PENDING_PUSH);
	att->size = sqlite3_column_int64(stm,
	    SBK_ATTACHMENTS_COLUMN_DATA_SIZE);
	att->time_sent = sqlite3_column_int64(stm,
	    SBK_ATTACHMENTS_COLUMN_DATE_SENT);
	att->time_recv = sqlite3_column_int64(stm,
	    SBK_ATTACHMENTS_COLUMN_DATE_RECEIVED);
	att->file = sbk_get_attachment_file(ctx, att->rowid,
	    att->attachmentid);

	if (att->file == NULL)
		warnx("Attachment %" PRId64 "-%" PRId64 " not available in "
		    "backup", att->rowid, att->attachmentid);
	else if (att->size != att->file->len)
		warnx("Attachment %" PRId64 "-%" PRId64 " has inconsistent "
		    "size", att->rowid, att->attachmentid);

	return att;

error:
	sbk_free_attachment(att);
	return NULL;
}

static struct sbk_attachment_list *
sbk_get_attachments(struct sbk_ctx *ctx, sqlite3_stmt *stm)
{
	struct sbk_attachment_list	*lst;
	struct sbk_attachment		*att;
	int				 ret;

	if ((lst = malloc(sizeof *lst)) == NULL) {
		warn(NULL);
		goto error;
	}

	TAILQ_INIT(lst);

	while ((ret = sbk_sqlite_step(ctx, stm)) == SQLITE_ROW) {
		if ((att = sbk_get_attachment(ctx, stm)) == NULL)
			goto error;
		TAILQ_INSERT_TAIL(lst, att, entries);
	}

	if (ret != SQLITE_DONE)
		goto error;

	sqlite3_finalize(stm);
	return lst;

error:
	sbk_free_attachment_list(lst);
	sqlite3_finalize(stm);
	return NULL;
}

struct sbk_attachment_list *
sbk_get_attachments_for_thread(struct sbk_ctx *ctx, struct sbk_thread *thd)
{
	sqlite3_stmt	*stm;
	const char	*query;

	if (sbk_create_database(ctx) == -1)
		return NULL;

	if (ctx->db_version < SBK_DB_VERSION_THREAD_AND_MESSAGE_FOREIGN_KEYS)
		query = SBK_ATTACHMENTS_QUERY_THREAD_1;
	else if (ctx->db_version <
	    SBK_DB_VERSION_REACTION_FOREIGN_KEY_MIGRATION)
		query = SBK_ATTACHMENTS_QUERY_THREAD_2;
	else
		query = SBK_ATTACHMENTS_QUERY_THREAD_3;

	if (sbk_sqlite_prepare(ctx, &stm, query) == -1)
		return NULL;

	if (sbk_sqlite_bind_int(ctx, stm, 1, thd->id) == -1) {
		sqlite3_finalize(stm);
		return NULL;
	}

	return sbk_get_attachments(ctx, stm);
}

static int
sbk_get_attachments_for_quote(struct sbk_ctx *ctx, struct sbk_quote *qte,
    struct sbk_message_id *mid)
{
	sqlite3_stmt	*stm;
	const char	*query;

	if (ctx->db_version < SBK_DB_VERSION_THREAD_AND_MESSAGE_FOREIGN_KEYS)
		query = SBK_ATTACHMENTS_QUERY_QUOTE_1;
	else if (ctx->db_version <
	    SBK_DB_VERSION_REACTION_FOREIGN_KEY_MIGRATION)
		query = SBK_ATTACHMENTS_QUERY_QUOTE_2;
	else
		query = SBK_ATTACHMENTS_QUERY_QUOTE_3;

	if (sbk_sqlite_prepare(ctx, &stm, query) == -1)
		return -1;

	if (sbk_sqlite_bind_int(ctx, stm, 1, mid->rowid) == -1) {
		sqlite3_finalize(stm);
		return -1;
	}

	if ((qte->attachments = sbk_get_attachments(ctx, stm)) == NULL)
		return -1;

	return 0;
}

static int
sbk_get_attachments_for_message(struct sbk_ctx *ctx, struct sbk_message *msg)
{
	sqlite3_stmt	*stm;
	const char	*query;

	if (msg->id.type != SBK_MESSAGE_MMS)
		return 0;

	if (ctx->db_version < SBK_DB_VERSION_QUOTED_REPLIES)
		query = SBK_ATTACHMENTS_QUERY_MESSAGE_1;
	else if (ctx->db_version <
	    SBK_DB_VERSION_THREAD_AND_MESSAGE_FOREIGN_KEYS)
		query = SBK_ATTACHMENTS_QUERY_MESSAGE_2;
	else if (ctx->db_version <
	    SBK_DB_VERSION_REACTION_FOREIGN_KEY_MIGRATION)
		query = SBK_ATTACHMENTS_QUERY_MESSAGE_3;
	else
		query = SBK_ATTACHMENTS_QUERY_MESSAGE_4;

	if (sbk_sqlite_prepare(ctx, &stm, query) == -1)
		return -1;

	if (sbk_sqlite_bind_int(ctx, stm, 1, msg->id.rowid) == -1) {
		sqlite3_finalize(stm);
		return -1;
	}

	if ((msg->attachments = sbk_get_attachments(ctx, stm)) == NULL)
		return -1;

	return 0;
}

static void
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

static int
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

static int
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

int
sbk_is_outgoing_message(const struct sbk_message *msg)
{
	switch (msg->type & SBK_BASE_TYPE_MASK) {
	case SBK_OUTGOING_AUDIO_CALL_TYPE:
	case SBK_BASE_OUTBOX_TYPE:
	case SBK_BASE_SENDING_TYPE:
	case SBK_BASE_SENT_TYPE:
	case SBK_BASE_SENT_FAILED_TYPE:
	case SBK_BASE_PENDING_SECURE_SMS_FALLBACK:
	case SBK_BASE_PENDING_INSECURE_SMS_FALLBACK:
	case SBK_OUTGOING_VIDEO_CALL_TYPE:
		return 1;
	default:
		return 0;
	}
}

static void
sbk_free_reaction(struct sbk_reaction *rct)
{
	if (rct != NULL) {
		free(rct->emoji);
		free(rct);
	}
}

static void
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

static int
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

/*
 * For database versions >= REACTION_REFACTOR
 */

#define SBK_REACTIONS_SELECT						\
	"SELECT "							\
	"author_id, "							\
	"emoji, "							\
	"date_sent, "							\
	"date_received "						\
	"FROM reaction "

/* For database versions < SINGLE_MESSAGE_TABLE_MIGRATION */
#define SBK_REACTIONS_WHERE_1						\
	"WHERE message_id = ? AND is_mms = ? "

/* For database versions >= SINGLE_MESSAGE_TABLE_MIGRATION */
#define SBK_REACTIONS_WHERE_2						\
	"WHERE message_id = ? "

#define SBK_REACTIONS_ORDER						\
	"ORDER BY date_sent"

/* For database versions < SINGLE_MESSAGE_TABLE_MIGRATION */
#define SBK_REACTIONS_QUERY_1						\
	SBK_REACTIONS_SELECT						\
	SBK_REACTIONS_WHERE_1						\
	SBK_REACTIONS_ORDER

/* For database versions >= SINGLE_MESSAGE_TABLE_MIGRATION */
#define SBK_REACTIONS_QUERY_2						\
	SBK_REACTIONS_SELECT						\
	SBK_REACTIONS_WHERE_2						\
	SBK_REACTIONS_ORDER

#define SBK_REACTIONS_COLUMN_AUTHOR_ID		0
#define SBK_REACTIONS_COLUMN_EMOJI		1
#define SBK_REACTIONS_COLUMN_DATE_SENT		2
#define SBK_REACTIONS_COLUMN_DATE_RECEIVED	3

static struct sbk_reaction *
sbk_get_reaction(struct sbk_ctx *ctx, sqlite3_stmt *stm)
{
	struct sbk_reaction *rct;

	if ((rct = calloc(1, sizeof *rct)) == NULL) {
		warn(NULL);
		return NULL;
	}

	rct->recipient = sbk_get_recipient_from_column(ctx, stm,
	    SBK_REACTIONS_COLUMN_AUTHOR_ID);
	if (rct->recipient == NULL)
		goto error;

	if (sbk_sqlite_column_text_copy(ctx, &rct->emoji, stm,
	    SBK_REACTIONS_COLUMN_EMOJI) == -1)
		goto error;

	rct->time_sent = sqlite3_column_int64(stm,
	    SBK_REACTIONS_COLUMN_DATE_SENT);
	rct->time_recv = sqlite3_column_int64(stm,
	    SBK_REACTIONS_COLUMN_DATE_RECEIVED);

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

static int
sbk_get_reactions_from_table(struct sbk_ctx *ctx, struct sbk_message *msg)
{
	sqlite3_stmt	*stm;
	const char	*query;

	if (ctx->db_version < SBK_DB_VERSION_SINGLE_MESSAGE_TABLE_MIGRATION)
		query = SBK_REACTIONS_QUERY_1;
	else
		query = SBK_REACTIONS_QUERY_2;

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

/* For database versions < REACTIONS */
#define SBK_MESSAGES_SELECT_SMS_1					\
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
#define SBK_MESSAGES_SELECT_SMS_2					\
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
 * For database versions
 * [THREAD_AND_MESSAGE_FOREIGN_KEYS, SINGLE_MESSAGE_TABLE_MIGRATION)
 */
#define SBK_MESSAGES_SELECT_SMS_3					\
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
#define SBK_MESSAGES_SELECT_MMS_1					\
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
#define SBK_MESSAGES_SELECT_MMS_2					\
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
#define SBK_MESSAGES_SELECT_MMS_3					\
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
#define SBK_MESSAGES_SELECT_MMS_4					\
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
 * For database versions
 * [THREAD_AND_MESSAGE_FOREIGN_KEYS, SINGLE_MESSAGE_TABLE_MIGRATION)
 */
#define SBK_MESSAGES_SELECT_MMS_5					\
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
 * For database versions
 * [SINGLE_MESSAGE_TABLE_MIGRATION, REACTION_FOREIGN_KEY_MIGRATION)
 */
#define SBK_MESSAGES_SELECT_1						\
	SBK_MESSAGES_SELECT_MMS_5

/* For database versions >= REACTION_FOREIGN_KEY_MIGRATION */
#define SBK_MESSAGES_SELECT_2						\
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

#define SBK_MESSAGES_WHERE_THREAD					\
	"WHERE thread_id = ?1 "

#define SBK_MESSAGES_ORDER						\
	"ORDER BY date_received"

/* For database versions < QUOTED_REPLIES */
#define SBK_MESSAGES_QUERY_1						\
	SBK_MESSAGES_SELECT_SMS_1					\
	SBK_MESSAGES_WHERE_THREAD					\
	"UNION ALL "							\
	SBK_MESSAGES_SELECT_MMS_1					\
	SBK_MESSAGES_WHERE_THREAD					\
	SBK_MESSAGES_ORDER

/* For database versions [QUOTED_REPLIES, REACTIONS) */
#define SBK_MESSAGES_QUERY_2						\
	SBK_MESSAGES_SELECT_SMS_1					\
	SBK_MESSAGES_WHERE_THREAD					\
	"UNION ALL "							\
	SBK_MESSAGES_SELECT_MMS_2					\
	SBK_MESSAGES_WHERE_THREAD					\
	SBK_MESSAGES_ORDER

/* For database versions [REACTIONS, MENTIONS) */
#define SBK_MESSAGES_QUERY_3						\
	SBK_MESSAGES_SELECT_SMS_2					\
	SBK_MESSAGES_WHERE_THREAD					\
	"UNION ALL "							\
	SBK_MESSAGES_SELECT_MMS_3					\
	SBK_MESSAGES_WHERE_THREAD					\
	SBK_MESSAGES_ORDER

/* For database versions [MENTIONS, THREAD_AND_MESSAGE_FOREIGN_KEYS) */
#define SBK_MESSAGES_QUERY_4						\
	SBK_MESSAGES_SELECT_SMS_2					\
	SBK_MESSAGES_WHERE_THREAD					\
	"UNION ALL "							\
	SBK_MESSAGES_SELECT_MMS_4					\
	SBK_MESSAGES_WHERE_THREAD					\
	SBK_MESSAGES_ORDER

/*
 * For database versions
 * [THREAD_AND_MESSAGE_FOREIGN_KEYS, SINGLE_MESSAGE_TABLE_MIGRATION)
 */
#define SBK_MESSAGES_QUERY_5						\
	SBK_MESSAGES_SELECT_SMS_3					\
	SBK_MESSAGES_WHERE_THREAD					\
	"UNION ALL "							\
	SBK_MESSAGES_SELECT_MMS_5					\
	SBK_MESSAGES_WHERE_THREAD					\
	SBK_MESSAGES_ORDER

/*
 * For database versions
 * [SINGLE_MESSAGE_TABLE_MIGRATION, REACTION_FOREIGN_KEY_MIGRATION)
 */
#define SBK_MESSAGES_QUERY_6						\
	SBK_MESSAGES_SELECT_1						\
	SBK_MESSAGES_WHERE_THREAD					\
	SBK_MESSAGES_ORDER

/* For database versions >= REACTION_FOREIGN_KEY_MIGRATION */
#define SBK_MESSAGES_QUERY_7						\
	SBK_MESSAGES_SELECT_2						\
	SBK_MESSAGES_WHERE_THREAD					\
	SBK_MESSAGES_ORDER

#define SBK_MESSAGES_COLUMN_TABLE		0
#define SBK_MESSAGES_COLUMN__ID			1
#define SBK_MESSAGES_COLUMN_DATE_SENT		2
#define SBK_MESSAGES_COLUMN_DATE_RECEIVED	3
#define SBK_MESSAGES_COLUMN_THREAD_ID		4
#define SBK_MESSAGES_COLUMN_RECIPIENT_ID	5
#define SBK_MESSAGES_COLUMN_TYPE		6
#define SBK_MESSAGES_COLUMN_BODY		7
#define SBK_MESSAGES_COLUMN_QUOTE_ID		8
#define SBK_MESSAGES_COLUMN_QUOTE_AUTHOR	9
#define SBK_MESSAGES_COLUMN_QUOTE_BODY		10
#define SBK_MESSAGES_COLUMN_QUOTE_MENTIONS	11
#define SBK_MESSAGES_COLUMN_REACTIONS		12

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

static int
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

static int
sbk_get_quote(struct sbk_ctx *ctx, struct sbk_message *msg, sqlite3_stmt *stm)
{
	struct sbk_quote *qte;

	if (sqlite3_column_int64(stm, SBK_MESSAGES_COLUMN_QUOTE_ID) == 0 &&
	    sqlite3_column_int64(stm, SBK_MESSAGES_COLUMN_QUOTE_AUTHOR) == 0) {
		/* No quote */
		return 0;
	}

	if ((qte = calloc(1, sizeof *qte)) == NULL) {
		warn(NULL);
		return -1;
	}

	qte->id = sqlite3_column_int64(stm, SBK_MESSAGES_COLUMN_QUOTE_ID);

	qte->recipient = sbk_get_recipient_from_column(ctx, stm,
	    SBK_MESSAGES_COLUMN_QUOTE_AUTHOR);
	if (qte->recipient == NULL)
		goto error;

	if (sbk_sqlite_column_text_copy(ctx, &qte->text, stm,
	    SBK_MESSAGES_COLUMN_QUOTE_BODY) == -1)
		goto error;

	if (sbk_get_attachments_for_quote(ctx, qte, &msg->id) == -1)
		goto error;

	if (sbk_get_quote_mentions(ctx, &qte->mentions, stm,
	    SBK_MESSAGES_COLUMN_QUOTE_MENTIONS, &msg->id) == -1)
		goto error;

	if (sbk_insert_mentions(&qte->text, qte->mentions, &msg->id) == -1)
		goto error;

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

	msg->id.type =
	    (sqlite3_column_int(stm, SBK_MESSAGES_COLUMN_TABLE) == 0) ?
	    SBK_MESSAGE_SMS : SBK_MESSAGE_MMS;
	msg->id.rowid = sqlite3_column_int(stm, SBK_MESSAGES_COLUMN__ID);

	msg->recipient = sbk_get_recipient_from_column(ctx, stm,
	    SBK_MESSAGES_COLUMN_RECIPIENT_ID);
	if (msg->recipient == NULL)
		goto error;

	if (sbk_sqlite_column_text_copy(ctx, &msg->text, stm,
	    SBK_MESSAGES_COLUMN_BODY) == -1)
		goto error;

	msg->time_sent = sqlite3_column_int64(stm,
	    SBK_MESSAGES_COLUMN_DATE_SENT);
	msg->time_recv = sqlite3_column_int64(stm,
	    SBK_MESSAGES_COLUMN_DATE_RECEIVED);
	msg->type = sqlite3_column_int(stm, SBK_MESSAGES_COLUMN_TYPE);
	msg->thread = sqlite3_column_int(stm, SBK_MESSAGES_COLUMN_THREAD_ID);

	if (sbk_get_body(msg) == -1)
		goto error;

	if (msg->id.type == SBK_MESSAGE_MMS) {
		if (sbk_get_attachments_for_message(ctx, msg) == -1)
			goto error;

		if (sbk_get_long_message(ctx, msg) == -1)
			goto error;

		if (sbk_get_mentions(ctx, msg) == -1)
			goto error;

		if (sbk_insert_mentions(&msg->text, msg->mentions, &msg->id) ==
		    -1)
			goto error;

		if (sbk_get_quote(ctx, msg, stm) == -1)
			goto error;
	}

	if (ctx->db_version < SBK_DB_VERSION_REACTION_REFACTOR) {
		if (sbk_get_reactions_from_column(ctx, &msg->reactions, stm,
		    SBK_MESSAGES_COLUMN_REACTIONS) == -1)
			goto error;
	} else {
		if (sbk_get_reactions_from_table(ctx, msg) == -1)
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

	if (ctx->db_version < SBK_DB_VERSION_QUOTED_REPLIES)
		query = SBK_MESSAGES_QUERY_1;
	else if (ctx->db_version < SBK_DB_VERSION_REACTIONS)
		query = SBK_MESSAGES_QUERY_2;
	else if (ctx->db_version < SBK_DB_VERSION_MENTIONS)
		query = SBK_MESSAGES_QUERY_3;
	else if (ctx->db_version <
	    SBK_DB_VERSION_THREAD_AND_MESSAGE_FOREIGN_KEYS)
		query = SBK_MESSAGES_QUERY_4;
	else if (ctx->db_version <
	    SBK_DB_VERSION_SINGLE_MESSAGE_TABLE_MIGRATION)
		query = SBK_MESSAGES_QUERY_5;
	else if (ctx->db_version <
	    SBK_DB_VERSION_REACTION_FOREIGN_KEY_MIGRATION)
		query = SBK_MESSAGES_QUERY_6;
	else
		query = SBK_MESSAGES_QUERY_7;

	if (sbk_sqlite_prepare(ctx, &stm, query) == -1)
		return NULL;

	if (sbk_sqlite_bind_int(ctx, stm, 1, thd->id) == -1) {
		sqlite3_finalize(stm);
		return NULL;
	}

	return sbk_get_messages(ctx, stm);
}

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

/* For database versions < THREAD_AUTOINCREMENT */
#define SBK_THREADS_QUERY_1						\
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
#define SBK_THREADS_QUERY_2						\
	"SELECT "							\
	"_id, "								\
	"date, "							\
	"message_count, "		/* meaningful_messages */	\
	"thread_recipient_id "		/* recipient_id */		\
	"FROM thread "							\
	"ORDER BY _id"

/* For database versions >= THREAD_AND_MESSAGE_FOREIGN_KEYS */
#define SBK_THREADS_QUERY_3						\
	"SELECT "							\
	"_id, "								\
	"date, "							\
	"meaningful_messages, "						\
	"recipient_id "							\
	"FROM thread "							\
	"ORDER BY _id"

#define SBK_THREADS_COLUMN__ID			0
#define SBK_THREADS_COLUMN_DATE			1
#define SBK_THREADS_COLUMN_MEANINGFUL_MESSAGES	2
#define SBK_THREADS_COLUMN_RECIPIENT_ID		3

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
		query = SBK_THREADS_QUERY_1;
	else if (ctx->db_version <
	    SBK_DB_VERSION_THREAD_AND_MESSAGE_FOREIGN_KEYS)
		query = SBK_THREADS_QUERY_2;
	else
		query = SBK_THREADS_QUERY_3;

	if (sbk_sqlite_prepare(ctx, &stm, query) == -1)
		goto error;

	while ((ret = sbk_sqlite_step(ctx, stm)) == SQLITE_ROW) {
		if ((thd = malloc(sizeof *thd)) == NULL) {
			warn(NULL);
			goto error;
		}

		thd->recipient = sbk_get_recipient_from_column(ctx, stm,
		    SBK_THREADS_COLUMN_RECIPIENT_ID);
		if (thd->recipient == NULL) {
			free(thd);
			goto error;
		}

		thd->id = sqlite3_column_int64(stm, SBK_THREADS_COLUMN__ID);
		thd->date = sqlite3_column_int64(stm, SBK_THREADS_COLUMN_DATE);
		thd->nmessages = sqlite3_column_int64(stm,
		    SBK_THREADS_COLUMN_MEANINGFUL_MESSAGES);
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

static int
sbk_compute_keys(struct sbk_ctx *ctx, const char *passphr,
    const unsigned char *salt, size_t saltlen)
{
	EVP_MD_CTX	*md_ctx;
	unsigned char	 key[SHA512_DIGEST_LENGTH];
	unsigned char	 deriv_key[SBK_DERIV_KEY_LEN];
	size_t		 passphrlen;
	int		 i, ret;

	if ((md_ctx = EVP_MD_CTX_new()) == NULL)
		goto error;

	passphrlen = strlen(passphr);

	/* The first round */
	if (!EVP_DigestInit_ex(md_ctx, EVP_sha512(), NULL))
		goto error;
	if (salt != NULL)
		if (!EVP_DigestUpdate(md_ctx, salt, saltlen))
			goto error;
	if (!EVP_DigestUpdate(md_ctx, passphr, passphrlen))
		goto error;
	if (!EVP_DigestUpdate(md_ctx, passphr, passphrlen))
		goto error;
	if (!EVP_DigestFinal_ex(md_ctx, key, NULL))
		goto error;

	/* The remaining rounds */
	for (i = 0; i < SBK_ROUNDS - 1; i++) {
		if (!EVP_DigestInit_ex(md_ctx, EVP_sha512(), NULL))
			goto error;
		if (!EVP_DigestUpdate(md_ctx, key, sizeof key))
			goto error;
		if (!EVP_DigestUpdate(md_ctx, passphr, passphrlen))
			goto error;
		if (!EVP_DigestFinal(md_ctx, key, NULL))
			goto error;
	}

	if (!HKDF(deriv_key, sizeof deriv_key, EVP_sha256(), key, SBK_KEY_LEN,
	    (const unsigned char *)"", 0, (const unsigned char *)SBK_HKDF_INFO,
	    strlen(SBK_HKDF_INFO)))
		goto error;

	memcpy(ctx->cipher_key, deriv_key, SBK_CIPHER_KEY_LEN);
	memcpy(ctx->mac_key, deriv_key + SBK_CIPHER_KEY_LEN, SBK_MAC_KEY_LEN);

	ret = 0;
	goto out;

error:
	warnx("Cannot compute keys");
	ret = -1;

out:
	explicit_bzero(key, sizeof key);
	explicit_bzero(deriv_key, sizeof deriv_key);
	if (md_ctx != NULL)
		EVP_MD_CTX_free(md_ctx);
	return ret;
}

struct sbk_ctx *
sbk_ctx_new(void)
{
	struct sbk_ctx *ctx;

	if ((ctx = calloc(1, sizeof *ctx)) == NULL) {
		warn(NULL);
		return NULL;
	}

	if ((ctx->cipher_ctx = EVP_CIPHER_CTX_new()) == NULL) {
		warnx("Cannot create cipher context");
		goto error;
	}

	if ((ctx->hmac_ctx = HMAC_CTX_new()) == NULL) {
		warnx("Cannot create MAC context");
		goto error;
	}

	if (sbk_enlarge_buffers(ctx, 1024) == -1)
		goto error;

	return ctx;

error:
	sbk_ctx_free(ctx);
	return NULL;
}

void
sbk_ctx_free(struct sbk_ctx *ctx)
{
	if (ctx != NULL) {
		EVP_CIPHER_CTX_free(ctx->cipher_ctx);
		HMAC_CTX_free(ctx->hmac_ctx);
		free(ctx->ibuf);
		free(ctx->obuf);
		free(ctx);
	}
}

int
sbk_open(struct sbk_ctx *ctx, const char *path, const char *passphr)
{
	Signal__BackupFrame	*frm;
	uint8_t			*salt;
	size_t			 saltlen;

	if ((ctx->fp = fopen(path, "rb")) == NULL) {
		warn("%s", path);
		return -1;
	}

	ctx->state = SBK_FIRST_FRAME;

	if ((frm = sbk_get_frame(ctx, NULL)) == NULL)
		goto error;

	if (frm->header == NULL) {
		warnx("Missing header frame");
		goto error;
	}

	if (!frm->header->has_iv) {
		warnx("Missing IV");
		goto error;
	}

	if (frm->header->iv.len != SBK_IV_LEN) {
		warnx("Invalid IV size");
		goto error;
	}

	memcpy(ctx->iv, frm->header->iv.data, SBK_IV_LEN);
	ctx->counter = ctx->counter_start =
	    ((uint32_t)ctx->iv[0] << 24) | ((uint32_t)ctx->iv[1] << 16) |
	    ((uint32_t)ctx->iv[2] <<  8) | ctx->iv[3];

	if (frm->header->has_salt) {
		salt = frm->header->salt.data;
		saltlen = frm->header->salt.len;
	} else {
		salt = NULL;
		saltlen = 0;
	}

	if (sbk_compute_keys(ctx, passphr, salt, saltlen) == -1)
		goto error;

	if (!EVP_DecryptInit_ex(ctx->cipher_ctx, EVP_aes_256_ctr(), NULL, NULL,
	    NULL)) {
		warnx("Cannot initialise cipher context");
		goto error;
	}

	if (!HMAC_Init_ex(ctx->hmac_ctx, ctx->mac_key, SBK_MAC_KEY_LEN,
	    EVP_sha256(), NULL)) {
		warnx("Cannot initialise MAC context");
		goto error;
	}

	if (sbk_rewind(ctx) == -1)
		goto error;

	sbk_free_frame(frm);
	ctx->db = NULL;
	ctx->db_version = 0;
	RB_INIT(&ctx->attachments);
	RB_INIT(&ctx->recipients);
	return 0;

error:
	explicit_bzero(ctx->cipher_key, SBK_CIPHER_KEY_LEN);
	explicit_bzero(ctx->mac_key, SBK_MAC_KEY_LEN);
	sbk_free_frame(frm);
	fclose(ctx->fp);
	return -1;
}

void
sbk_close(struct sbk_ctx *ctx)
{
	sbk_free_recipient_tree(ctx);
	sbk_free_attachment_tree(ctx);
	explicit_bzero(ctx->cipher_key, SBK_CIPHER_KEY_LEN);
	explicit_bzero(ctx->mac_key, SBK_MAC_KEY_LEN);
	sqlite3_close(ctx->db);
	fclose(ctx->fp);
}

int
sbk_rewind(struct sbk_ctx *ctx)
{
	if (fseek(ctx->fp, 0, SEEK_SET) == -1) {
		warn("Cannot seek");
		return -1;
	}

	clearerr(ctx->fp);
	ctx->counter = ctx->counter_start;
	ctx->state = SBK_FIRST_FRAME;
	return 0;
}

int
sbk_eof(struct sbk_ctx *ctx)
{
	return ctx->state == SBK_LAST_FRAME;
}
