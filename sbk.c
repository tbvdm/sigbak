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

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#include "sigbak.h"

#define SBK_IV_LEN		16
#define SBK_KEY_LEN		32
#define SBK_CIPHERKEY_LEN	32
#define SBK_MACKEY_LEN		32
#define SBK_DERIVKEY_LEN	(SBK_CIPHERKEY_LEN + SBK_MACKEY_LEN)
#define SBK_MAC_LEN		10
#define SBK_ROUNDS		250000
#define SBK_HKDF_INFO		"Backup Export"

#define SBK_GROUP_PREFIX	"__textsecure_group__!"

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

struct sbk_ctx {
	FILE		*fp;
	sqlite3		*db;
	struct sbk_attachment_tree attachments;
	int		(*get_contact)(struct sbk_ctx *, const char *, char **,
			    char **);
	int		(*get_group)(struct sbk_ctx *, const char *, char **);
	int		(*is_group)(struct sbk_ctx *, const char *);
	EVP_CIPHER_CTX	*cipher;
	HMAC_CTX	*hmac;
	unsigned char	 cipherkey[SBK_CIPHERKEY_LEN];
	unsigned char	 mackey[SBK_MACKEY_LEN];
	unsigned char	 iv[SBK_IV_LEN];
	uint32_t	 counter;
	unsigned char	*ibuf;
	size_t		 ibufsize;
	unsigned char	*obuf;
	size_t		 obufsize;
	int		 firstframe;
	int		 eof;
	char		*error;
};

static int	sbk_cmp_attachment_entries(struct sbk_attachment_entry *,
		    struct sbk_attachment_entry *);
static void	sbk_set_function_pointers(struct sbk_ctx *);

RB_GENERATE_STATIC(sbk_attachment_tree, sbk_attachment_entry, entries,
    sbk_cmp_attachment_entries)

static ProtobufCAllocator sbk_protobuf_alloc = {
	mem_protobuf_malloc,
	mem_protobuf_free,
	NULL
};

static void
sbk_error_clear(struct sbk_ctx *ctx)
{
	free(ctx->error);
	ctx->error = NULL;
}

static void
sbk_error_set(struct sbk_ctx *ctx, const char *fmt, ...)
{
	va_list	 ap;
	char	*errmsg, *msg;
	int	 saved_errno;

	va_start(ap, fmt);
	saved_errno = errno;
	sbk_error_clear(ctx);
	errmsg = strerror(saved_errno);

	if (fmt == NULL || vasprintf(&msg, fmt, ap) == -1)
		ctx->error = strdup(errmsg);
	else if (asprintf(&ctx->error, "%s: %s", msg, errmsg) == -1)
		ctx->error = msg;
	else
		free(msg);

	errno = saved_errno;
	va_end(ap);
}

static void
sbk_error_setx(struct sbk_ctx *ctx, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sbk_error_clear(ctx);

	if (fmt == NULL || vasprintf(&ctx->error, fmt, ap) == -1)
		ctx->error = NULL;

	va_end(ap);
}

static void
sbk_error_sqlite_vsetd(struct sbk_ctx *ctx, sqlite3 *db, const char *fmt,
    va_list ap)
{
	const char	*errmsg;
	char		*msg;

	sbk_error_clear(ctx);
	errmsg = sqlite3_errmsg(db);

	if (fmt == NULL || vasprintf(&msg, fmt, ap) == -1)
		ctx->error = strdup(errmsg);
	else if (asprintf(&ctx->error, "%s: %s", msg, errmsg) == -1)
		ctx->error = msg;
	else
		free(msg);
}

static void
sbk_error_sqlite_setd(struct sbk_ctx *ctx, sqlite3 *db, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sbk_error_sqlite_vsetd(ctx, db, fmt, ap);
	va_end(ap);
}

static void
sbk_error_sqlite_set(struct sbk_ctx *ctx, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sbk_error_sqlite_vsetd(ctx, ctx->db, fmt, ap);
	va_end(ap);
}

static int
sbk_init(void)
{
	static int		done;
	sqlite3_mem_methods	methods;

	if (done)
		return 0;

	methods.xMalloc = mem_sqlite_malloc;
	methods.xFree = mem_sqlite_free;
	methods.xRealloc = mem_sqlite_realloc;
	methods.xSize = mem_sqlite_size;
	methods.xRoundup = mem_sqlite_roundup;
	methods.xInit = mem_sqlite_init;
	methods.xShutdown = mem_sqlite_shutdown;
	methods.pAppData = NULL;

	if (sqlite3_config(SQLITE_CONFIG_MALLOC, &methods) != SQLITE_OK)
		return -1;

	if (sqlite3_initialize() != SQLITE_OK)
		return -1;

	done = 1;
	return 0;
}

static int
sbk_enlarge_buffers(struct sbk_ctx *ctx, size_t size)
{
	unsigned char *buf;

	if (ctx->ibufsize < size) {
		if ((buf = realloc(ctx->ibuf, size)) == NULL) {
			sbk_error_set(ctx, NULL);
			return -1;
		}
		ctx->ibuf = buf;
		ctx->ibufsize = size;
	}

	if (size > SIZE_MAX - EVP_MAX_BLOCK_LENGTH) {
		sbk_error_setx(ctx, "Buffer size too large");
		return -1;
	}

	size += EVP_MAX_BLOCK_LENGTH;

	if (ctx->obufsize < size) {
		if ((buf = recallocarray(ctx->obuf, ctx->obufsize, size, 1)) ==
		    NULL) {
			sbk_error_set(ctx, NULL);
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
	ctx->iv[0] = counter >> 24;
	ctx->iv[1] = counter >> 16;
	ctx->iv[2] = counter >> 8;
	ctx->iv[3] = counter;

	if (HMAC_Init_ex(ctx->hmac, NULL, 0, NULL, NULL) == 0) {
		sbk_error_setx(ctx, "Cannot initialise HMAC");
		return -1;
	}

	if (EVP_DecryptInit_ex(ctx->cipher, NULL, NULL, ctx->cipherkey,
	    ctx->iv) == 0) {
		sbk_error_setx(ctx, "Cannot initialise cipher");
		return -1;
	}

	return 0;
}

static int
sbk_decrypt_update(struct sbk_ctx *ctx, size_t ibuflen, size_t *obuflen)
{
	int len;

	if (HMAC_Update(ctx->hmac, ctx->ibuf, ibuflen) == 0) {
		sbk_error_setx(ctx, "Cannot compute HMAC");
		return -1;
	}

	if (EVP_DecryptUpdate(ctx->cipher, ctx->obuf, &len, ctx->ibuf,
	    ibuflen) == 0) {
		sbk_error_setx(ctx, "Cannot decrypt data");
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

	if (EVP_DecryptFinal_ex(ctx->cipher, ctx->obuf + *obuflen, &len) ==
	    0) {
		sbk_error_setx(ctx, "Cannot decrypt data");
		return -1;
	}

	*obuflen += len;

	if (HMAC_Final(ctx->hmac, ourmac, &ourmaclen) == 0) {
		sbk_error_setx(ctx, "Cannot compute HMAC");
		return -1;
	}

	if (memcmp(ourmac, theirmac, SBK_MAC_LEN) != 0) {
		sbk_error_setx(ctx, "HMAC mismatch");
		return -1;
	}

	return 0;
}

static int
sbk_read(struct sbk_ctx *ctx, void *ptr, size_t size)
{
	if (fread(ptr, size, 1, ctx->fp) != 1) {
		if (ferror(ctx->fp))
			sbk_error_set(ctx, NULL);
		else
			sbk_error_setx(ctx, "Unexpected end of file");
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
		sbk_error_setx(ctx, "Invalid frame size");
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
		sbk_error_setx(ctx, "Invalid frame");
		return -1;
	}

	if (fseek(ctx->fp, len + SBK_MAC_LEN, SEEK_CUR) == -1) {
		sbk_error_set(ctx, "Cannot seek");
		return -1;
	}

	ctx->counter++;
	return 0;
}

static Signal__BackupFrame *
sbk_unpack_frame(struct sbk_ctx *ctx, unsigned char *buf, size_t len)
{
	Signal__BackupFrame *frm;

	if ((frm = signal__backup_frame__unpack(&sbk_protobuf_alloc, len, buf))
	    == NULL)
		sbk_error_setx(ctx, "Cannot unpack frame");

	return frm;
}

static struct sbk_file *
sbk_get_file(struct sbk_ctx *ctx, Signal__BackupFrame *frm)
{
	struct sbk_file *file;

	if ((file = malloc(sizeof *file)) == NULL) {
		sbk_error_set(ctx, NULL);
		return NULL;
	}

	if ((file->pos = ftell(ctx->fp)) == -1) {
		sbk_error_set(ctx, NULL);
		goto error;
	}

	if (frm->attachment != NULL) {
		if (!frm->attachment->has_length) {
			sbk_error_setx(ctx, "Invalid attachment frame");
			goto error;
		}
		file->len = frm->attachment->length;
	} else if (frm->avatar != NULL) {
		if (!frm->avatar->has_length) {
			sbk_error_setx(ctx, "Invalid avatar frame");
			goto error;
		}
		file->len = frm->avatar->length;
	} else if (frm->sticker != NULL) {
		if (!frm->sticker->has_length) {
			sbk_error_setx(ctx, "Invalid sticker frame");
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

	if (ctx->eof)
		return NULL;

	if (sbk_read_frame(ctx, &ibuflen) == -1)
		return NULL;

	/* The first frame is not encrypted */
	if (ctx->firstframe) {
		ctx->firstframe = 0;
		return sbk_unpack_frame(ctx, ctx->ibuf, ibuflen);
	}

	if (ibuflen <= SBK_MAC_LEN) {
		sbk_error_setx(ctx, "Invalid frame size");
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

	if ((frm = sbk_unpack_frame(ctx, ctx->obuf, obuflen)) == NULL)
		return NULL;

	if (frm->has_end)
		ctx->eof = 1;

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
		signal__backup_frame__free_unpacked(frm, &sbk_protobuf_alloc);
}

void
sbk_free_file(struct sbk_file *file)
{
	freezero(file, sizeof *file);
}

int
sbk_write_file(struct sbk_ctx *ctx, struct sbk_file *file, FILE *fp)
{
	size_t		ibuflen, len, obuflen;
	unsigned char	mac[SBK_MAC_LEN];

	if (sbk_enlarge_buffers(ctx, BUFSIZ) == -1)
		return -1;

	if (fseek(ctx->fp, file->pos, SEEK_SET) == -1) {
		sbk_error_set(ctx, "Cannot seek");
		return -1;
	}

	if (sbk_decrypt_init(ctx, file->counter) == -1)
		return -1;

	if (HMAC_Update(ctx->hmac, ctx->iv, SBK_IV_LEN) == 0) {
		sbk_error_setx(ctx, "Cannot compute HMAC");
		return -1;
	}

	for (len = file->len; len > 0; len -= ibuflen) {
		ibuflen = (len < BUFSIZ) ? len : BUFSIZ;

		if (sbk_read(ctx, ctx->ibuf, ibuflen) == -1)
			return -1;

		if (sbk_decrypt_update(ctx, ibuflen, &obuflen) == -1)
			return -1;

		if (fp != NULL && fwrite(ctx->obuf, obuflen, 1, fp) != 1) {
			sbk_error_set(ctx, "Cannot write file");
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
		sbk_error_set(ctx, "Cannot write file");
		return -1;
	}

	return 0;
}

char *
sbk_get_file_as_string(struct sbk_ctx *ctx, struct sbk_file *file)
{
	size_t		 ibuflen, len, obuflen, obufsize;
	unsigned char	 mac[SBK_MAC_LEN];
	char		*obuf, *ptr;

	if (sbk_enlarge_buffers(ctx, BUFSIZ) == -1)
		return NULL;

	if (fseek(ctx->fp, file->pos, SEEK_SET) == -1) {
		sbk_error_set(ctx, "Cannot seek");
		return NULL;
	}

	if ((size_t)file->len > SIZE_MAX - EVP_MAX_BLOCK_LENGTH - 1) {
		sbk_error_setx(ctx, "File too large");
		return NULL;
	}

	obufsize = file->len + EVP_MAX_BLOCK_LENGTH + 1;

	if ((obuf = malloc(obufsize)) == NULL) {
		sbk_error_set(ctx, NULL);
		return NULL;
	}

	if (sbk_decrypt_init(ctx, file->counter) == -1)
		goto error;

	if (HMAC_Update(ctx->hmac, ctx->iv, SBK_IV_LEN) == 0) {
		sbk_error_setx(ctx, "Cannot compute HMAC");
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

	*ptr = '\0';
	return obuf;

error:
	freezero(obuf, obufsize);
	return NULL;
}

static int
sbk_sqlite_bind_blob(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx,
    const void *val, size_t len)
{
	if (sqlite3_bind_blob(stm, idx, val, len, SQLITE_STATIC) !=
	    SQLITE_OK) {
		sbk_error_sqlite_set(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_bind_double(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx,
    double val)
{
	if (sqlite3_bind_double(stm, idx, val) != SQLITE_OK) {
		sbk_error_sqlite_set(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_bind_int(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx, int val)
{
	if (sqlite3_bind_int(stm, idx, val) != SQLITE_OK) {
		sbk_error_sqlite_set(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_bind_int64(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx,
    sqlite3_int64 val)
{
	if (sqlite3_bind_int64(stm, idx, val) != SQLITE_OK) {
		sbk_error_sqlite_set(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_bind_null(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx)
{
	if (sqlite3_bind_null(stm, idx) != SQLITE_OK) {
		sbk_error_sqlite_set(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_bind_text(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx,
    const char *val)
{
	if (sqlite3_bind_text(stm, idx, val, -1, SQLITE_STATIC) != SQLITE_OK) {
		sbk_error_sqlite_set(ctx, "Cannot bind SQL parameter");
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
		sbk_error_sqlite_set(ctx, "Cannot get column text");
		return -1;
	}

	if ((len = sqlite3_column_bytes(stm, idx)) < 0) {
		sbk_error_sqlite_set(ctx, "Cannot get column size");
		return -1;
	}

	if ((*buf = malloc((size_t)len + 1)) == NULL) {
		sbk_error_set(ctx, NULL);
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
		sbk_error_sqlite_set(ctx, "Cannot get column text");
		return -1;
	}

	if ((*buf = strdup(txt)) == NULL) {
		sbk_error_set(ctx, NULL);
		return -1;
	}

	return 0;
#endif
}

static int
sbk_sqlite_open(struct sbk_ctx *ctx, sqlite3 **db, const char *path)
{
	if (sqlite3_open(path, db) != SQLITE_OK) {
		sbk_error_sqlite_setd(ctx, *db, "Cannot open database");
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_prepare(struct sbk_ctx *ctx, sqlite3_stmt **stm, const char *query)
{
	if (sqlite3_prepare_v2(ctx->db, query, -1, stm, NULL) != SQLITE_OK) {
		sbk_error_sqlite_set(ctx, "Cannot prepare SQL statement");
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
		sbk_error_sqlite_set(ctx, "Cannot execute SQL statement");

	return ret;
}

static int
sbk_sqlite_exec(struct sbk_ctx *ctx, const char *sql)
{
	char *errmsg;

	if (sqlite3_exec(ctx->db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
		sbk_error_setx(ctx, "Cannot execute SQL statement: %s",
		    errmsg);
		sqlite3_free(errmsg);
		return -1;
	}

	return 0;
}

static int
sbk_sqlite_table_exists(struct sbk_ctx *ctx, const char *table)
{
	sqlite3_stmt	*stm;
	int		 ret;

	if (sbk_sqlite_prepare(ctx, &stm, "SELECT name FROM sqlite_master "
	    "WHERE type = 'table' AND NAME = ?") == -1)
		return 0;

	if (sbk_sqlite_bind_text(ctx, stm, 1, table) == -1)
		ret = 0;
	else
		ret = sbk_sqlite_step(ctx, stm) == SQLITE_ROW;

	sqlite3_finalize(stm);
	return ret;
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
		sbk_error_setx(ctx, "Invalid attachment frame");
		sbk_free_file(file);
		return -1;
	}

	if ((entry = malloc(sizeof *entry)) == NULL) {
		sbk_error_set(ctx, NULL);
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
		freezero(entry, sizeof *entry);
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

	sbk_error_setx(ctx, "Unknown SQL parameter type");
	return -1;
}

static int
sbk_exec_statement(struct sbk_ctx *ctx, Signal__SqlStatement *sql)
{
	sqlite3_stmt	*stm;
	size_t		 i;

	if (sql->statement == NULL) {
		sbk_error_setx(ctx, "Invalid SQL frame");
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
		sbk_error_setx(ctx, "Invalid version frame");
		return -1;
	}

	if (asprintf(&sql, "PRAGMA user_version = %" PRIu32, ver->version) ==
	    -1) {
		sbk_error_setx(ctx, "asprintf() failed");
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

	if (sbk_sqlite_open(ctx, &ctx->db, ":memory:") == -1)
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

	if (!ctx->eof)
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

	if (sbk_sqlite_open(ctx, &db, path) == -1)
		goto error;

	if (sbk_create_database(ctx) == -1)
		goto error;

	if ((bak = sqlite3_backup_init(db, "main", ctx->db, "main")) == NULL) {
		sbk_error_sqlite_setd(ctx, db, "Cannot write database");
		goto error;
	}

	if (sqlite3_backup_step(bak, -1) != SQLITE_DONE) {
		sbk_error_sqlite_setd(ctx, db, "Cannot write database");
		sqlite3_backup_finish(bak);
		goto error;
	}

	sqlite3_backup_finish(bak);

	if (sqlite3_close(db) != SQLITE_OK) {
		sbk_error_sqlite_setd(ctx, db, "Cannot close database");
		return -1;
	}

	return 0;

error:
	sqlite3_close(db);
	return -1;
}

static void
sbk_get_sms_body(struct sbk_ctx *ctx, struct sbk_sms *sms)
{
	char		*contact, *name;
	const char	*fmt;

	fmt = NULL;

	if (sms->type & SBK_KEY_EXCHANGE_IDENTITY_VERIFIED_BIT) {
		if (SBK_IS_OUTGOING_MESSAGE(sms->type))
			fmt = "You marked your safety number with %s verified";
		else
			fmt = "You marked your safety number with %s verified "
			    "from another device";
	} else if (sms->type & SBK_KEY_EXCHANGE_IDENTITY_DEFAULT_BIT) {
		if (SBK_IS_OUTGOING_MESSAGE(sms->type))
			fmt = "You marked your safety number with %s "
			    "unverified";
		else
			fmt = "You marked your safety number with %s "
			    "unverified from another device";
	} else if (sms->type & SBK_KEY_EXCHANGE_IDENTITY_UPDATE_BIT)
		fmt = "Your safety number with %s has changed";
	else
		switch (sms->type & SBK_BASE_TYPE_MASK) {
		case SBK_INCOMING_CALL_TYPE:
			fmt = "%s called you";
			break;
		case SBK_OUTGOING_CALL_TYPE:
			fmt = "Called %s";
			break;
		case SBK_MISSED_CALL_TYPE:
			fmt = "Missed call from %s";
			break;
		case SBK_JOINED_TYPE:
			fmt = "%s is on Signal";
			break;
		}

	if (fmt == NULL)
		return;

	if (sbk_get_contact(ctx, sms->address, &name, NULL) == -1 ||
	    name == NULL)
		contact = sms->address;
	else
		contact = name;

	freezero_string(sms->body);

	if (asprintf(&sms->body, fmt, contact) == -1)
		sms->body = NULL;

	free(name);
}

static void
sbk_free_sms(struct sbk_sms *sms)
{
	freezero_string(sms->address);
	freezero_string(sms->body);
	freezero(sms, sizeof *sms);
}

void
sbk_free_sms_list(struct sbk_sms_list *lst)
{
	struct sbk_sms *sms;

	if (lst != NULL) {
		while ((sms = SIMPLEQ_FIRST(lst)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(lst, entries);
			sbk_free_sms(sms);
		}
		free(lst);
	}
}

struct sbk_sms_list *
sbk_get_smses(struct sbk_ctx *ctx, int thread)
{
	struct sbk_sms_list	*lst;
	struct sbk_sms		*sms;
	sqlite3_stmt		*stm;
	int			 ret;

	if (sbk_create_database(ctx) == -1)
		return NULL;

	if ((lst = malloc(sizeof *lst)) == NULL) {
		sbk_error_set(ctx, NULL);
		return NULL;
	}

	SIMPLEQ_INIT(lst);

	if (thread == -1) {
		if (sbk_sqlite_prepare(ctx, &stm, "SELECT address, body, _id, "
		    "date, date_sent, thread_id, type FROM sms ORDER BY date")
		    == -1)
			goto error;
	} else {
		if (sbk_sqlite_prepare(ctx, &stm, "SELECT address, body, _id, "
		    "date, date_sent, thread_id, type FROM sms WHERE "
		    "thread_id = ? ORDER BY date") == -1)
			goto error;

		if (sbk_sqlite_bind_int(ctx, stm, 1, thread) == -1)
			goto error;
	}

	while ((ret = sbk_sqlite_step(ctx, stm)) == SQLITE_ROW) {
		if ((sms = malloc(sizeof *sms)) == NULL) {
			sbk_error_set(ctx, NULL);
			goto error;
		}

		sms->address = NULL;
		sms->body = NULL;

		if (sbk_sqlite_column_text_copy(ctx, &sms->address, stm, 0) ==
		    -1) {
			sbk_free_sms(sms);
			goto error;
		}

		if (sbk_sqlite_column_text_copy(ctx, &sms->body, stm, 1) ==
		    -1) {
			sbk_free_sms(sms);
			goto error;
		}

		sms->id = sqlite3_column_int(stm, 2);
		sms->date_recv = sqlite3_column_int64(stm, 3);
		sms->date_sent = sqlite3_column_int64(stm, 4);
		sms->thread = sqlite3_column_int(stm, 5);
		sms->type = sqlite3_column_int(stm, 6);

		if (sms->body == NULL || sms->body[0] == '\0')
			sbk_get_sms_body(ctx, sms);

		SIMPLEQ_INSERT_TAIL(lst, sms, entries);
	}

	if (ret != SQLITE_DONE)
		goto error;

	sqlite3_finalize(stm);
	return lst;

error:
	sbk_free_sms_list(lst);
	sqlite3_finalize(stm);
	return NULL;
}

static void
sbk_free_attachment(struct sbk_attachment *att)
{
	freezero_string(att->filename);
	freezero_string(att->content_type);
	freezero(att, sizeof *att);
}

static void
sbk_free_attachment_list(struct sbk_attachment_list *lst)
{
	struct sbk_attachment *att;

	if (lst != NULL) {
		while ((att = SIMPLEQ_FIRST(lst)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(lst, entries);
			sbk_free_attachment(att);
		}
		free(lst);
	}
}

int
sbk_get_attachments(struct sbk_ctx *ctx, struct sbk_mms *mms)
{
	struct sbk_attachment	*att;
	sqlite3_stmt		*stm;
	int			 ret;

	if (mms->attachments != NULL)
		return 0;

	if (sbk_create_database(ctx) == -1)
		return -1;

	if ((mms->attachments = malloc(sizeof *mms->attachments)) == NULL) {
		sbk_error_set(ctx, NULL);
		return -1;
	}

	SIMPLEQ_INIT(mms->attachments);

	if (sbk_sqlite_prepare(ctx, &stm, "SELECT file_name, ct, _id, "
	    "unique_id, pending_push, data_size FROM part WHERE mid = ? "
	    "ORDER BY unique_id, _id") == -1)
		goto error;

	if (sbk_sqlite_bind_int(ctx, stm, 1, mms->id) == -1)
		goto error;

	while ((ret = sbk_sqlite_step(ctx, stm)) == SQLITE_ROW) {
		if ((att = malloc(sizeof *att)) == NULL) {
			sbk_error_set(ctx, NULL);
			goto error;
		}

		att->filename = NULL;
		att->content_type = NULL;

		if (sbk_sqlite_column_text_copy(ctx, &att->filename, stm, 0)
		    == -1) {
			sbk_free_attachment(att);
			goto error;
		}

		if (sbk_sqlite_column_text_copy(ctx, &att->content_type, stm,
		    1) == -1) {
			sbk_free_attachment(att);
			goto error;
		}

		att->rowid = sqlite3_column_int64(stm, 2);
		att->attachmentid = sqlite3_column_int64(stm, 3);
		att->status = sqlite3_column_int(stm, 4);
		att->size = sqlite3_column_int64(stm, 5);

		if (att->status == SBK_ATTACHMENT_TRANSFER_DONE) {
			if ((att->file = sbk_get_attachment_file(ctx,
			    att->rowid, att->attachmentid)) == NULL) {
				sbk_error_setx(ctx, "Cannot find attachment "
				    "file");
				goto error;
			}

			if (att->size != att->file->len) {
				sbk_error_setx(ctx, "Inconsistent attachment "
				    "size");
				goto error;
			}
		}

		SIMPLEQ_INSERT_TAIL(mms->attachments, att, entries);
	}

	if (ret != SQLITE_DONE)
		goto error;

	sqlite3_finalize(stm);
	return 0;

error:
	sqlite3_finalize(stm);
	sbk_free_attachment_list(mms->attachments);
	mms->attachments = NULL;
	return -1;
}

static void
sbk_free_mms(struct sbk_mms *mms)
{
	freezero_string(mms->address);
	freezero_string(mms->body);
	sbk_free_attachment_list(mms->attachments);
	freezero(mms, sizeof *mms);
}

void
sbk_free_mms_list(struct sbk_mms_list *lst)
{
	struct sbk_mms *mms;

	if (lst != NULL) {
		while ((mms = SIMPLEQ_FIRST(lst)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(lst, entries);
			sbk_free_mms(mms);
		}
		free(lst);
	}
}

struct sbk_mms_list *
sbk_get_mmses(struct sbk_ctx *ctx, int thread)
{
	struct sbk_mms_list	*lst;
	struct sbk_mms		*mms;
	sqlite3_stmt		*stm;
	int			 ret;

	if (sbk_create_database(ctx) == -1)
		return NULL;

	if ((lst = malloc(sizeof *lst)) == NULL) {
		sbk_error_set(ctx, NULL);
		return NULL;
	}

	SIMPLEQ_INIT(lst);

	if (thread == -1) {
		if (sbk_sqlite_prepare(ctx, &stm, "SELECT address, body, _id, "
		    "date_received, date, thread_id, msg_box, part_count FROM "
		    "mms ORDER BY date_received") == -1)
			goto error;
	} else {
		if (sbk_sqlite_prepare(ctx, &stm, "SELECT address, body, _id, "
		    "date_received, date, thread_id, msg_box, part_count FROM "
		    "mms WHERE thread_id = ? ORDER BY date_received") == -1)
			goto error;

		if (sbk_sqlite_bind_int(ctx, stm, 1, thread) == -1)
			goto error;
	}

	while ((ret = sbk_sqlite_step(ctx, stm)) == SQLITE_ROW) {
		if ((mms = malloc(sizeof *mms)) == NULL) {
			sbk_error_set(ctx, NULL);
			goto error;
		}

		mms->address = NULL;
		mms->body = NULL;
		mms->attachments = NULL;

		if (sbk_sqlite_column_text_copy(ctx, &mms->address, stm, 0) ==
		    -1) {
			sbk_free_mms(mms);
			goto error;
		}

		if (sbk_sqlite_column_text_copy(ctx, &mms->body, stm, 1) ==
		    -1) {
			sbk_free_mms(mms);
			goto error;
		}

		mms->id = sqlite3_column_int(stm, 2);
		mms->date_recv = sqlite3_column_int64(stm, 3);
		mms->date_sent = sqlite3_column_int64(stm, 4);
		mms->thread = sqlite3_column_int(stm, 5);
		mms->type = sqlite3_column_int(stm, 6);
		mms->nattachments = sqlite3_column_int(stm, 7);
		SIMPLEQ_INSERT_TAIL(lst, mms, entries);
	}

	if (ret != SQLITE_DONE)
		goto error;

	sqlite3_finalize(stm);
	return lst;

error:
	sbk_free_mms_list(lst);
	sqlite3_finalize(stm);
	return NULL;
}

int
sbk_get_long_message(struct sbk_ctx *ctx, struct sbk_mms *mms)
{
	struct sbk_attachment	*att;
	char			*longmsg;
	int			 found;

	if (sbk_get_attachments(ctx, mms) == -1)
		return -1;

	found = 0;
	SIMPLEQ_FOREACH(att, mms->attachments, entries)
		if (strcmp(att->content_type, SBK_LONG_TEXT_TYPE) == 0) {
			found = 1;
			break;
		}

	if (!found)
		return 0;

	if ((longmsg = sbk_get_file_as_string(ctx, att->file)) == NULL)
		return -1;

	freezero_string(mms->body);
	mms->body = longmsg;
	return 0;
}

void
sbk_free_thread_list(struct sbk_thread_list *lst)
{
	struct sbk_thread *thd;

	if (lst != NULL) {
		while ((thd = SIMPLEQ_FIRST(lst)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(lst, entries);
			freezero(thd, sizeof *thd);
		}
		free(lst);
	}
}

struct sbk_thread_list *
sbk_get_threads(struct sbk_ctx *ctx)
{
	struct sbk_thread_list	*lst;
	struct sbk_thread	*thd;
	sqlite3_stmt		*stm;
	int			 ret;

	if (sbk_create_database(ctx) == -1)
		return NULL;

	if ((lst = malloc(sizeof *lst)) == NULL) {
		sbk_error_set(ctx, NULL);
		return NULL;
	}

	SIMPLEQ_INIT(lst);

	if (sbk_sqlite_prepare(ctx, &stm, "SELECT recipient_ids, _id, date, "
	    "message_count FROM thread ORDER BY _id") == -1)
		goto error;

	while ((ret = sbk_sqlite_step(ctx, stm)) == SQLITE_ROW) {
		if ((thd = malloc(sizeof *thd)) == NULL) {
			sbk_error_set(ctx, NULL);
			goto error;
		}

		if (sbk_sqlite_column_text_copy(ctx, &thd->recipient, stm, 0)
		    == -1) {
			freezero(thd, sizeof *thd);
			goto error;
		}

		thd->id = sqlite3_column_int64(stm, 1);
		thd->date = sqlite3_column_int64(stm, 2);
		thd->nmessages = sqlite3_column_int64(stm, 3);
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
sbk_get_contact_1(struct sbk_ctx *ctx, const char *id, char **name,
    char **phone)
{
	sqlite3_stmt	*stm;
	int		 result, ret;

	if (sbk_sqlite_prepare(ctx, &stm, "SELECT system_display_name FROM "
	    "recipient_preferences WHERE recipient_ids = ?") == -1)
		return -1;

	ret = -1;

	if (sbk_sqlite_bind_text(ctx, stm, 1, id) == -1)
		goto out;

	if ((result = sbk_sqlite_step(ctx, stm)) != SQLITE_ROW) {
		if (result == SQLITE_DONE)
			sbk_error_setx(ctx, "No such contact");
		goto out;
	}

	if (name != NULL) {
		if (sbk_sqlite_column_text_copy(ctx, name, stm, 0) == -1)
			goto out;
	}

	if (phone != NULL) {
		if ((*phone = strdup(id)) == NULL) {
			sbk_error_set(ctx, NULL);
			if (name != NULL) {
				freezero_string(*name);
				*name = NULL;
			}
			goto out;
		}
	}

	ret = 0;

out:
	sqlite3_finalize(stm);
	return ret;
}

static int
sbk_get_contact_2(struct sbk_ctx *ctx, const char *id, char **name,
    char **phone)
{
	sqlite3_stmt	*stm;
	int		 result, ret;

	if (sbk_sqlite_prepare(ctx, &stm, "SELECT system_display_name, phone "
	    "FROM recipient WHERE _id = ?") == -1)
		return -1;

	ret = -1;

	if (sbk_sqlite_bind_text(ctx, stm, 1, id) == -1)
		goto out;

	if ((result = sbk_sqlite_step(ctx, stm)) != SQLITE_ROW) {
		if (result == SQLITE_DONE)
			sbk_error_setx(ctx, "No such contact");
		goto out;
	}

	if (name != NULL) {
		if (sbk_sqlite_column_text_copy(ctx, name, stm, 0) == -1)
			goto out;
	}

	if (phone != NULL) {
		if (sbk_sqlite_column_text_copy(ctx, phone, stm, 1) == -1) {
			if (name != NULL) {
				freezero_string(*name);
				*name = NULL;
			}
			goto out;
		}
	}

	ret = 0;

out:
	sqlite3_finalize(stm);
	return ret;
}

int
sbk_get_contact(struct sbk_ctx *ctx, const char *id, char **name, char **phone)
{
	if (name != NULL)
		*name = NULL;

	if (phone != NULL)
		*phone = NULL;

	if (ctx->get_contact == NULL)
		sbk_set_function_pointers(ctx);

	return ctx->get_contact(ctx, id, name, phone);
}

int
sbk_get_group_1(struct sbk_ctx *ctx, const char *id, char **name)
{
	sqlite3_stmt	*stm;
	int		 result, ret;

	if (sbk_sqlite_prepare(ctx, &stm, "SELECT title FROM groups WHERE "
	    "group_id = ?") == -1)
		return -1;

	ret = -1;

	if (sbk_sqlite_bind_text(ctx, stm, 1, id) == -1)
		goto out;

	if ((result = sbk_sqlite_step(ctx, stm)) != SQLITE_ROW) {
		if (result == SQLITE_DONE)
			sbk_error_setx(ctx, "No such group");
		goto out;
	}

	if (name != NULL) {
		if (sbk_sqlite_column_text_copy(ctx, name, stm, 0) == -1)
			goto out;
	}

	ret = 0;

out:
	sqlite3_finalize(stm);
	return ret;
}

int
sbk_get_group_2(struct sbk_ctx *ctx, const char *id, char **name)
{
	sqlite3_stmt	*stm;
	int		 result, ret;

	if (sbk_sqlite_prepare(ctx, &stm, "SELECT title FROM groups WHERE "
		"recipient_id = ?") == -1)
		return -1;

	ret = -1;

	if (sbk_sqlite_bind_text(ctx, stm, 1, id) == -1)
		goto out;

	if ((result = sbk_sqlite_step(ctx, stm)) != SQLITE_ROW) {
		if (result == SQLITE_DONE)
			sbk_error_setx(ctx, "No such group");
		goto out;
	}

	if (name != NULL) {
		if (sbk_sqlite_column_text_copy(ctx, name, stm, 0) == -1)
			goto out;
	}

	ret = 0;

out:
	sqlite3_finalize(stm);
	return ret;
}

int
sbk_get_group(struct sbk_ctx *ctx, const char *id, char **name)
{
	if (name != NULL)
		*name = NULL;

	if (ctx->get_group == NULL)
		sbk_set_function_pointers(ctx);

	return ctx->get_group(ctx, id, name);
}

int
sbk_is_group_1(__unused struct sbk_ctx *ctx, const char *id)
{
	return strncmp(id, SBK_GROUP_PREFIX, sizeof SBK_GROUP_PREFIX - 1) == 0;
}

int
sbk_is_group_2(struct sbk_ctx *ctx, const char *id)
{
	sqlite3_stmt	*stm;
	int		 ret;

	if (sbk_sqlite_prepare(ctx, &stm, "SELECT group_id FROM recipient "
	    "WHERE _id = ?") == -1)
		return -1;

	ret = -1;

	if (sbk_sqlite_bind_text(ctx, stm, 1, id) == -1)
		goto out;

	if (sbk_sqlite_step(ctx, stm) != SQLITE_ROW)
		goto out;

	ret = sqlite3_column_type(stm, 0) != SQLITE_NULL;

out:
	sqlite3_finalize(stm);
	return ret;
}

int
sbk_is_group(struct sbk_ctx *ctx, const char *id)
{
	if (ctx->is_group == NULL)
		sbk_set_function_pointers(ctx);

	return ctx->is_group(ctx, id);
}

static void
sbk_set_function_pointers(struct sbk_ctx *ctx)
{
	if (sbk_sqlite_table_exists(ctx, "recipient_preferences")) {
		ctx->get_contact = sbk_get_contact_1;
		ctx->get_group = sbk_get_group_1;
		ctx->is_group = sbk_is_group_1;
	} else {
		ctx->get_contact = sbk_get_contact_2;
		ctx->get_group = sbk_get_group_2;
		ctx->is_group = sbk_is_group_2;
	}
}

static int
sbk_compute_keys(struct sbk_ctx *ctx, const char *passphr,
    const unsigned char *salt, size_t saltlen)
{
	unsigned char	key[SHA512_DIGEST_LENGTH];
	unsigned char	derivkey[SBK_DERIVKEY_LEN];
	SHA512_CTX	sha;
	size_t		passphrlen;
	int		i, ret;

	passphrlen = strlen(passphr);
	SHA512_Init(&sha);

	if (salt != NULL)
		SHA512_Update(&sha, salt, saltlen);

	SHA512_Update(&sha, passphr, passphrlen);
	SHA512_Update(&sha, passphr, passphrlen);
	SHA512_Final(key, &sha);

	for (i = 0; i < SBK_ROUNDS - 1; i++) {
		SHA512_Init(&sha);
		SHA512_Update(&sha, key, sizeof key);
		SHA512_Update(&sha, passphr, passphrlen);
		SHA512_Final(key, &sha);
	}

	if (HKDF(derivkey, sizeof derivkey, EVP_sha256(), key, SBK_KEY_LEN, "",
	    0, SBK_HKDF_INFO, strlen(SBK_HKDF_INFO)) == 0) {
		sbk_error_setx(ctx, "Cannot compute keys");
		ret = -1;
	} else {
		memcpy(ctx->cipherkey, derivkey, SBK_CIPHERKEY_LEN);
		memcpy(ctx->mackey, derivkey + SBK_CIPHERKEY_LEN,
		    SBK_MACKEY_LEN);
		ret = 0;
	}

	explicit_bzero(key, sizeof key);
	explicit_bzero(derivkey, sizeof derivkey);
	explicit_bzero(&sha, sizeof sha);
	return ret;
}

struct sbk_ctx *
sbk_ctx_new(void)
{
	struct sbk_ctx *ctx;

	if (sbk_init() == -1)
		return NULL;

	if ((ctx = malloc(sizeof *ctx)) == NULL)
		return NULL;

	ctx->hmac = NULL;
	ctx->ibuf = NULL;
	ctx->obuf = NULL;
	ctx->ibufsize = 0;
	ctx->obufsize = 0;
	ctx->error = NULL;

	if ((ctx->cipher = EVP_CIPHER_CTX_new()) == NULL)
		goto error;

	if ((ctx->hmac = HMAC_CTX_new()) == NULL)
		goto error;

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
		sbk_error_clear(ctx);
		EVP_CIPHER_CTX_free(ctx->cipher);
		HMAC_CTX_free(ctx->hmac);
		free(ctx->ibuf);
		freezero(ctx->obuf, ctx->obufsize);
		freezero(ctx, sizeof *ctx);
	}
}

int
sbk_open(struct sbk_ctx *ctx, const char *path, const char *passphr)
{
	Signal__BackupFrame	*frm;
	uint8_t			*salt;
	size_t			 saltlen;

	if ((ctx->fp = fopen(path, "rb")) == NULL) {
		sbk_error_set(ctx, NULL);
		return -1;
	}

	ctx->firstframe = 1;
	ctx->eof = 0;

	if ((frm = sbk_get_frame(ctx, NULL)) == NULL)
		goto error;

	if (frm->header == NULL) {
		sbk_error_setx(ctx, "Missing header frame");
		goto error;
	}

	if (!frm->header->has_iv) {
		sbk_error_setx(ctx, "Missing IV");
		goto error;
	}

	if (frm->header->iv.len != SBK_IV_LEN) {
		sbk_error_setx(ctx, "Invalid IV size");
		goto error;
	}

	memcpy(ctx->iv, frm->header->iv.data, SBK_IV_LEN);
	ctx->counter = (ctx->iv[0] << 24) | (ctx->iv[1] << 16) |
	    (ctx->iv[2] << 8) | ctx->iv[3];

	if (frm->header->has_salt) {
		salt = frm->header->salt.data;
		saltlen = frm->header->salt.len;
	} else {
		salt = NULL;
		saltlen = 0;
	}

	if (sbk_compute_keys(ctx, passphr, salt, saltlen) == -1)
		goto error;

	if (EVP_DecryptInit_ex(ctx->cipher, EVP_aes_256_ctr(), NULL, NULL,
	    NULL) == 0)
		goto error;

	if (HMAC_Init_ex(ctx->hmac, ctx->mackey, SBK_MACKEY_LEN, EVP_sha256(),
	    NULL) == 0) {
		sbk_error_setx(ctx, "Cannot initialise HMAC");
		goto error;
	}

	if (sbk_rewind(ctx) == -1)
		goto error;

	sbk_free_frame(frm);
	ctx->db = NULL;
	ctx->get_contact = NULL;
	ctx->get_group = NULL;
	ctx->is_group = NULL;
	RB_INIT(&ctx->attachments);
	return 0;

error:
	explicit_bzero(ctx->cipherkey, SBK_CIPHERKEY_LEN);
	explicit_bzero(ctx->mackey, SBK_MACKEY_LEN);
	sbk_free_frame(frm);
	fclose(ctx->fp);
	return -1;
}

void
sbk_close(struct sbk_ctx *ctx)
{
	sbk_free_attachment_tree(ctx);
	explicit_bzero(ctx->cipherkey, SBK_CIPHERKEY_LEN);
	explicit_bzero(ctx->mackey, SBK_MACKEY_LEN);
	sqlite3_close(ctx->db);
	fclose(ctx->fp);
}

int
sbk_rewind(struct sbk_ctx *ctx)
{
	if (fseek(ctx->fp, 0, SEEK_SET) == -1) {
		sbk_error_set(ctx, "Cannot seek");
		return -1;
	}

	clearerr(ctx->fp);
	ctx->eof = 0;
	ctx->firstframe = 1;
	return 0;
}

int
sbk_eof(struct sbk_ctx *ctx)
{
	return ctx->eof;
}

const char *
sbk_error(struct sbk_ctx *ctx)
{
	return (ctx->error != NULL) ? ctx->error : "Unknown error";
}
