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

#include <sys/types.h>

#include <inttypes.h>
#include <sha2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <sqlite3.h>

#include "sbk.h"

#define SBK_IV_LEN		16
#define SBK_KEY_LEN		32
#define SBK_CIPHERKEY_LEN	32
#define SBK_MACKEY_LEN		32
#define SBK_DERIVKEY_LEN	(SBK_CIPHERKEY_LEN + SBK_MACKEY_LEN)
#define SBK_MAC_LEN		10
#define SBK_HKDF_INFO		"Backup Export"

struct sbk_ctx {
	FILE		*fp;
	EVP_CIPHER_CTX	*cipher;
	HMAC_CTX	*hmac;
	unsigned char	 cipherkey[SBK_CIPHERKEY_LEN];
	unsigned char	 mackey[SBK_MACKEY_LEN];
	unsigned char	 iv[SBK_IV_LEN];
	int32_t		 counter;
	unsigned char	*ibuf;
	size_t		 ibufsize;
	unsigned char	*obuf;
	size_t		 obufsize;
	int		 firstframe;
	int		 eof;
};

struct sbk_file {
	enum sbk_file_type type;
	char		*name;
	uint32_t	 len;
	long		 off;
	int32_t		 counter;
};

static int
sbk_enlarge_buffers(struct sbk_ctx *ctx, size_t size)
{
	char *buf;

	if (ctx->ibufsize < size) {
		if ((buf = realloc(ctx->ibuf, size)) == NULL)
			return -1;
		ctx->ibuf = buf;
		ctx->ibufsize = size;
	}

	if (size > SIZE_MAX - EVP_MAX_BLOCK_LENGTH)
		return -1;

	size += EVP_MAX_BLOCK_LENGTH;

	if (ctx->obufsize < size) {
		if ((buf = recallocarray(ctx->obuf, ctx->obufsize, size, 1)) ==
		    NULL)
			return -1;
		ctx->obuf = buf;
		ctx->obufsize = size;
	}

	return 0;
}

static int
sbk_decrypt_init(struct sbk_ctx *ctx, int32_t counter)
{
	ctx->iv[0] = counter >> 24;
	ctx->iv[1] = counter >> 16;
	ctx->iv[2] = counter >> 8;
	ctx->iv[3] = counter;

	if (HMAC_Init_ex(ctx->hmac, ctx->mackey, SBK_MACKEY_LEN, EVP_sha256(),
	    NULL) == 0)
		return -1;

	if (EVP_DecryptInit_ex(ctx->cipher, EVP_aes_256_ctr(), NULL,
	    ctx->cipherkey, ctx->iv) == 0)
		return -1;

	return 0;
}

static int
sbk_decrypt_update(struct sbk_ctx *ctx, size_t ibuflen, size_t *obuflen)
{
	int len;

	if (HMAC_Update(ctx->hmac, ctx->ibuf, ibuflen) == 0)
		return -1;

	if (EVP_DecryptUpdate(ctx->cipher, ctx->obuf, &len, ctx->ibuf,
	    ibuflen) == 0)
		return -1;

	*obuflen = len;
	return 0;
}


static int
sbk_decrypt_final(struct sbk_ctx *ctx, size_t *obuflen, const char *theirmac)
{
	char		ourmac[EVP_MAX_MD_SIZE];
	unsigned int	ourmaclen;
	int		len;

	if (EVP_DecryptFinal_ex(ctx->cipher, ctx->obuf + *obuflen, &len) == 0)
		return -1;
	
	*obuflen += len;

	if (HMAC_Final(ctx->hmac, ourmac, &ourmaclen) == 0)
		return -1;

	if (memcmp(ourmac, theirmac, SBK_MAC_LEN) != 0)
		return -1;

	return 0;
}

static int
sbk_decrypt_reset(struct sbk_ctx *ctx)
{
	if (EVP_CIPHER_CTX_reset(ctx->cipher) == 0)
		return -1;

	if (HMAC_CTX_reset(ctx->hmac) == 0)
		return -1;

	return 0;
}

static int
sbk_read_frame(struct sbk_ctx *ctx, size_t *frmlen)
{
	int32_t		len;
	unsigned char	lenbuf[4];

	if (fread(lenbuf, sizeof lenbuf, 1, ctx->fp) != 1)
		return -1;

	len = (lenbuf[0] << 24) | (lenbuf[1] << 16) | (lenbuf[2] << 8) |
	    lenbuf[3];

	if (len <= 0)
		return -1;

	if (sbk_enlarge_buffers(ctx, len) == -1)
		return -1;

	if (fread(ctx->ibuf, len, 1, ctx->fp) != 1)
		return -1;

	*frmlen = len;
	return 0;
}

int
sbk_skip_file(struct sbk_ctx *ctx, Signal__BackupFrame *frm)
{
	uint32_t len;

	if (frm->attachment != NULL && frm->attachment->has_length)
		len = frm->attachment->length;
	else if (frm->avatar != NULL && frm->avatar->has_length)
		len = frm->avatar->length;
	else
		return 0;

	if (fseek(ctx->fp, len + SBK_MAC_LEN, SEEK_CUR) == -1)
		return -1;

	ctx->counter++;
	return 0;
}

Signal__BackupFrame *
sbk_get_frame(struct sbk_ctx *ctx)
{
	Signal__BackupFrame	*frm;
	size_t			 ibuflen, obuflen;
	unsigned char		*mac;

	if (ctx->eof)
		return NULL;

	if (sbk_read_frame(ctx, &ibuflen) == -1)
		return NULL;

	/* The first frame is not encrypted */
	if (ctx->firstframe) {
		ctx->firstframe = 0;
		return signal__backup_frame__unpack(NULL, ibuflen, ctx->ibuf);
	}

	if (ibuflen <= SBK_MAC_LEN)
		return NULL;

	ibuflen -= SBK_MAC_LEN;
	mac = ctx->ibuf + ibuflen;

	if (sbk_decrypt_init(ctx, ctx->counter) == -1)
		goto error;

	if (sbk_decrypt_update(ctx, ibuflen, &obuflen) == -1)
		goto error;

	if (sbk_decrypt_final(ctx, &obuflen, mac) == -1)
		goto error;

	if (sbk_decrypt_reset(ctx) == -1)
		goto error;

	if ((frm = signal__backup_frame__unpack(NULL, obuflen, ctx->obuf)) !=
	    NULL) {
		if (frm->has_end)
			ctx->eof = 1;
	}

	ctx->counter++;
	return frm;

error:
	sbk_decrypt_reset(ctx);
	return NULL;
}

void
sbk_free_frame(Signal__BackupFrame *frm)
{
	signal__backup_frame__free_unpacked(frm, NULL);
}

struct sbk_file *
sbk_get_file(struct sbk_ctx *ctx)
{
	struct sbk_file		*file;
	Signal__BackupFrame	*frm;

	file = NULL;

	while ((frm = sbk_get_frame(ctx)) != NULL)
		if (frm->attachment != NULL || frm->avatar != NULL)
			break;

	if (frm == NULL) {
		if (!ctx->eof)
			goto error;
		return NULL;
	}

	if ((file = malloc(sizeof *file)) == NULL)
		goto error;

	if ((file->off = ftell(ctx->fp)) == -1)
		goto error;

	if (frm->attachment != NULL) {
		file->type = SBK_ATTACHMENT;

		if (!frm->attachment->has_attachmentid ||
		    !frm->attachment->has_length)
			goto error;

		if (asprintf(&file->name, "%" PRIu64,
		    frm->attachment->attachmentid) == -1)
			goto error;

		file->len = frm->attachment->length;
	} else {
		file->type = SBK_AVATAR;

		if (frm->avatar->name == NULL || !frm->avatar->has_length)
			goto error;

		if ((file->name = strdup(frm->avatar->name)) == NULL)
			goto error;

		file->len = frm->avatar->length;
	}

	file->counter = ctx->counter;

	if (sbk_skip_file(ctx, frm) == -1)
		goto error;

	signal__backup_frame__free_unpacked(frm, NULL);
	return file;

error:
	if (frm != NULL)
		signal__backup_frame__free_unpacked(frm, NULL);

	freezero(file, sizeof *file);
	return NULL;
}

void
sbk_free_file(struct sbk_file *file)
{
	freezero(file->name, strlen(file->name) + 1);
	freezero(file, sizeof *file);
}

enum sbk_file_type
sbk_get_file_type(struct sbk_file *file)
{
	return file->type;
}

const char *
sbk_get_file_name(struct sbk_file *file)
{
	return file->name;
}

size_t
sbk_get_file_size(struct sbk_file *file)
{
	return file->len;
}

int
sbk_write_file(struct sbk_ctx *ctx, struct sbk_file *file, FILE *fp)
{
	size_t	ibuflen, len, obuflen;
	char	mac[SBK_MAC_LEN];

	if (sbk_enlarge_buffers(ctx, BUFSIZ) == -1)
		return -1;

	if (fseek(ctx->fp, file->off, SEEK_SET) == -1)
		return -1;

	if (sbk_decrypt_init(ctx, file->counter) == -1)
		goto error;

	if (HMAC_Update(ctx->hmac, ctx->iv, SBK_IV_LEN) == 0)
		goto error;

	for (len = file->len; len > 0; len -= ibuflen) {
		ibuflen = (len < ctx->ibufsize) ? len : ctx->ibufsize;

		if (fread(ctx->ibuf, ibuflen, 1, ctx->fp) != 1)
			goto error;

		if (sbk_decrypt_update(ctx, ibuflen, &obuflen) == -1)
			goto error;

		if (fwrite(ctx->obuf, obuflen, 1, fp) != 1)
			goto error;
	}

	if (fread(mac, sizeof mac, 1, ctx->fp) != 1)
		goto error;

	obuflen = 0;

	if (sbk_decrypt_final(ctx, &obuflen, mac) == -1)
		goto error;

	if (obuflen > 0 && fwrite(ctx->obuf, obuflen, 1, fp) != 1)
		goto error;

	return sbk_decrypt_reset(ctx);

error:
	sbk_decrypt_reset(ctx);
	return -1;
}

static int
sbk_compute_keys(struct sbk_ctx *ctx, const unsigned char *passphr,
    const unsigned char *salt, size_t saltlen)
{
	unsigned char	key[SHA512_DIGEST_LENGTH];
	unsigned char	derivkey[SBK_DERIVKEY_LEN];
	SHA2_CTX	sha;
	size_t		passphrlen;
	int		i, ret;

	passphrlen = strlen(passphr);
	SHA512Init(&sha);

	if (salt != NULL)
		SHA512Update(&sha, salt, saltlen);

	SHA512Update(&sha, passphr, passphrlen);
	SHA512Update(&sha, passphr, passphrlen);
	SHA512Final(key, &sha);

	for (i = 0; i < 250000 - 1; i++) {
		SHA512Init(&sha);
		SHA512Update(&sha, key, sizeof key);
		SHA512Update(&sha, passphr, passphrlen);
		SHA512Final(key, &sha);
	}

	if (HKDF(derivkey, sizeof derivkey, EVP_sha256(), key, SBK_KEY_LEN, "",
	    0, SBK_HKDF_INFO, strlen(SBK_HKDF_INFO)) == 0)
		ret = -1;
	else {
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

	if ((ctx = malloc(sizeof *ctx)) == NULL)
		return NULL;

	ctx->hmac = NULL;
	ctx->ibuf = NULL;
	ctx->obuf = NULL;
	ctx->ibufsize = 0;
	ctx->obufsize = 0;

	if ((ctx->cipher = EVP_CIPHER_CTX_new()) == NULL)
		goto error;

	if ((ctx->hmac = HMAC_CTX_new()) == NULL)
		goto error;

	if (sbk_enlarge_buffers(ctx, 1024) == -1)
		goto error;

	ctx->eof = 0;
	return ctx;

error:
	sbk_ctx_free(ctx);
	return NULL;
}

void
sbk_ctx_free(struct sbk_ctx *ctx)
{
	if (ctx != NULL) {
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
	int			 ret;

	if ((ctx->fp = fopen(path, "rb")) == NULL)
		return -1;

	ctx->firstframe = 1;

	if ((frm = sbk_get_frame(ctx)) == NULL)
		goto error1;

	if (frm->header == NULL)
		goto error2;

	if (!frm->header->has_iv)
		goto error2;

	if (frm->header->iv.len != SBK_IV_LEN)
		goto error2;

	memcpy(ctx->iv, frm->header->iv.data, SBK_IV_LEN);
	ctx->counter = (ctx->iv[0] << 24) | (ctx->iv[1] << 16) |
	    (ctx->iv[2] << 8) | ctx->iv[3];

	if (!frm->header->has_salt)
		ret = sbk_compute_keys(ctx, passphr, NULL, 0);
	else
		ret = sbk_compute_keys(ctx, passphr, frm->header->salt.data,
		    frm->header->salt.len);

	if (ret != 0)
		goto error2;

	signal__backup_frame__free_unpacked(frm, NULL);
	ctx->eof = 0;

	return sbk_rewind(ctx);

error2:
	signal__backup_frame__free_unpacked(frm, NULL);
error1:
	fclose(ctx->fp);
	return -1;
}

void
sbk_close(struct sbk_ctx *ctx)
{
	explicit_bzero(ctx->cipherkey, SBK_CIPHERKEY_LEN);
	explicit_bzero(ctx->mackey, SBK_MACKEY_LEN);
	fclose(ctx->fp);
}

int
sbk_rewind(struct sbk_ctx *ctx)
{
	if (fseek(ctx->fp, 0, SEEK_SET) == -1)
		return -1;

	clearerr(ctx->fp);
	ctx->firstframe = 1;
	return 0;
}

static int
sbk_exec_statement(sqlite3 *db, Signal__SqlStatement *stm)
{
	sqlite3_stmt	*sqlstm;
	size_t		 i;
	int		 ret;

	if (stm->statement == NULL)
		return -1;

	if (sqlite3_prepare_v2(db, stm->statement, -1, &sqlstm, NULL) !=
	    SQLITE_OK)
		return -1;

	for (i = 0; i < stm->n_parameters; i++) {
		if (stm->parameters[i]->stringparamter != NULL)
			ret = sqlite3_bind_text(sqlstm, i + 1,
			    stm->parameters[i]->stringparamter, -1, NULL);
		if (stm->parameters[i]->has_integerparameter)
			ret = sqlite3_bind_int64(sqlstm, i + 1,
			    *(int64_t *)&stm->parameters[i]->integerparameter);
		if (stm->parameters[i]->has_doubleparameter)
			ret = sqlite3_bind_double(sqlstm, i + 1,
			    stm->parameters[i]->doubleparameter);
		if (stm->parameters[i]->has_blobparameter)
			ret = sqlite3_bind_blob(sqlstm, i + 1,
			    stm->parameters[i]->blobparameter.data,
			    stm->parameters[i]->blobparameter.len, NULL);
		if (stm->parameters[i]->has_nullparameter)
			ret = sqlite3_bind_null(sqlstm, i + 1);
		if (ret != SQLITE_OK)
			goto error;
	}

	if (sqlite3_step(sqlstm) != SQLITE_DONE)
		goto error;

	if (sqlite3_finalize(sqlstm) != SQLITE_OK)
		return -1;

	return 0;

error:
	sqlite3_finalize(sqlstm);
	return -1;
}

int
sbk_sqlite(const char *bakpath, const char *passphr, const char *dbpath)
{
	struct sbk_ctx		*ctx;
	Signal__BackupFrame	*frm;
	sqlite3			*db;
	int			 ret;

	if ((ctx = sbk_ctx_new()) == NULL)
		return -1;

	if (sbk_open(ctx, bakpath, passphr) == -1)
		goto error1;

	if (sqlite3_open(dbpath, &db) != SQLITE_OK)
		goto error3;

	ret = 0;

	while ((frm = sbk_get_frame(ctx)) != NULL) {
		if (frm->statement != NULL)
			ret = sbk_exec_statement(db, frm->statement);
		else if (frm->attachment != NULL || frm->avatar != NULL)
			ret = sbk_skip_file(ctx, frm);

		signal__backup_frame__free_unpacked(frm, NULL);

		if (ret == -1)
			goto error3;
	}

	if (!ctx->eof)
		goto error3;

	if (sqlite3_close(db) != SQLITE_OK)
		goto error2;

	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return 0;

error3:
	sqlite3_close(db);
error2:
	sbk_close(ctx);
error1:
	sbk_ctx_free(ctx);
	return -1;
}

int
sbk_eof(struct sbk_ctx *ctx)
{
	return ctx->eof;
}
