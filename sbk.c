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

#include <errno.h>
#include <inttypes.h>
#include <sha2.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <sqlite3.h>

#include "backup.pb-c.h"
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
	unsigned char	 cipherkey[SBK_CIPHERKEY_LEN];
	unsigned char	 mackey[SBK_MACKEY_LEN];
	unsigned char	 iv[SBK_IV_LEN];
	int32_t		 counter;
	unsigned char	*buf;
	size_t		 bufsize;
	int		 dump;
	int		 eof;
};

static void
sbk_print(unsigned int ind, const char *name, const char *type,
    const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	while (ind-- > 0)
		putchar('\t');
	printf("%s (%s):", name, type);
	if (fmt != NULL) {
		putchar(' ');
		vprintf(fmt, ap);
	}
	putchar('\n');
	va_end(ap);
}

static void
sbk_print_bool(unsigned int ind, const char *name, int val)
{
	sbk_print(ind, name, "bool", "%d", val);
}

static void
sbk_print_uint32(unsigned int ind, const char *name, uint32_t val)
{
	sbk_print(ind, name, "uint32", "%" PRIu32, val);
}

static void
sbk_print_uint64(unsigned int ind, const char *name, uint64_t val)
{
	sbk_print(ind, name, "uint64", "%" PRIu64, val);
}

static void
sbk_print_double(unsigned int ind, const char *name, double val)
{
	sbk_print(ind, name, "string", "%g", val);
}

static void
sbk_print_string(unsigned int ind, const char *name, const char *val)
{
	sbk_print(ind, name, "string", "%s", val);
}

static void
sbk_print_binary(unsigned int ind, const char *name, ProtobufCBinaryData *bin)
{
	char	*hex;
	size_t	 i;

	if ((hex = reallocarray(NULL, bin->len + 1, 2)) == NULL)
		return;

	for (i = 0; i < bin->len; i++)
		snprintf(hex + (i * 2), 3, "%02x", bin->data[i]);

	sbk_print(ind, name, "bytes", "%s", hex);
	free(hex);
}

static void
sbk_print_attachment(unsigned int ind, const char *name,
    Signal__Attachment *att)
{
	sbk_print(ind, name, "Attachment", NULL);
	if (att->has_rowid)
		sbk_print_uint64(ind + 1, "rowid", att->rowid);
	if (att->has_attachmentid)
		sbk_print_uint64(ind + 1, "attachmentid", att->attachmentid);
	if (att->has_length)
		sbk_print_uint32(ind + 1, "length", att->length);
}

static void
sbk_print_avatar(unsigned int ind, const char *name, Signal__Avatar *avt)
{
	sbk_print(ind, name, "Avatar", NULL, NULL);
	if (avt->name)
		sbk_print_string(ind + 1, "name", avt->name);
	if (avt->has_length)
		sbk_print_uint32(ind + 1, "length", avt->length);
}

static void
sbk_print_header(unsigned int ind, const char *name, Signal__Header *hdr)
{
	sbk_print(ind, name, "Header", NULL);
	if (hdr->has_iv)
		sbk_print_binary(ind + 1, "iv", &hdr->iv);
	if (hdr->has_salt)
		sbk_print_binary(ind + 1, "salt", &hdr->salt);
}

static void
sbk_print_preference(unsigned int ind, const char *name,
    Signal__SharedPreference *prf)
{
	sbk_print(ind, name, "SharedPreference", NULL, NULL);
	if (prf->file != NULL)
		sbk_print_string(ind + 1, "file", prf->file);
	if (prf->key != NULL)
		sbk_print_string(ind + 1, "key", prf->key);
	if (prf->value != NULL)
		sbk_print_string(ind + 1, "value", prf->value);
}

static void
sbk_print_parameter(unsigned int ind, const char *name,
    Signal__SqlStatement__SqlParameter *par)
{
	sbk_print(ind, name, "SqlParameter", NULL);
	if (par->stringparamter != NULL)
		sbk_print_string(ind + 1, "stringParamter",
		    par->stringparamter);
	if (par->has_integerparameter)
		sbk_print_uint64(ind + 1, "integerParameter",
		    par->integerparameter);
	if (par->has_doubleparameter)
		sbk_print_double(ind + 1, "doubleParameter",
		    par->doubleparameter);
	if (par->has_blobparameter)
		sbk_print_binary(ind + 1, "blobParameter",
		    &par->blobparameter);
	if (par->has_nullparameter)
		sbk_print_bool(ind + 1, "nullparameter", par->nullparameter);
}

static void
sbk_print_statement(unsigned int ind, const char *name,
    Signal__SqlStatement *stm)
{
	size_t i;

	sbk_print(ind, name, "SqlStatement", NULL);
	if (stm->statement != NULL)
		sbk_print_string(ind + 1, "string", stm->statement);
	for (i = 0; i < stm->n_parameters; i++)
		sbk_print_parameter(ind + 1, "parameters", stm->parameters[i]);
}

static void
sbk_print_version(unsigned int ind, const char *name,
    Signal__DatabaseVersion *ver)
{
	sbk_print(ind, name, "DatabaseVersion", NULL);
	if (ver->has_version)
		sbk_print_uint32(ind + 1, "version", ver->version);
}

static void
sbk_print_frame(Signal__BackupFrame *frm, unsigned int n)
{
	printf("frame %u:\n", n);
	if (frm->header != NULL)
		sbk_print_header(1, "header", frm->header);
	if (frm->statement != NULL)
		sbk_print_statement(1, "statement", frm->statement);
	if (frm->preference != NULL)
		sbk_print_preference(1, "preference", frm->preference);
	if (frm->attachment != NULL)
		sbk_print_attachment(1, "attachment", frm->attachment);
	if (frm->version != NULL)
		sbk_print_version(1, "version", frm->version);
	if (frm->has_end)
		sbk_print_bool(1, "end", frm->end);
	if (frm->avatar != NULL)
		sbk_print_avatar(1, "avatar", frm->avatar);
}

static int
sbk_read_buf(struct sbk_ctx *ctx, size_t len)
{
	char *buf;

	if (ctx->bufsize < len) {
		if ((buf = realloc(ctx->buf, len)) == NULL)
			return -1;
		ctx->buf = buf;
		ctx->bufsize = len;
	}

	if (fread(ctx->buf, 1, len, ctx->fp) != len)
		return -1;

	return 0;
}

static int
sbk_read_frame(struct sbk_ctx *ctx, size_t *frmlen)
{
	int32_t	len;

	if (sbk_read_buf(ctx, 4) == -1)
		return -1;

	len = (ctx->buf[0] << 24) | (ctx->buf[1] << 16) | (ctx->buf[2] << 8) |
	    ctx->buf[3];

	if (len < 0)
		return -1;

	*frmlen = len;
	return sbk_read_buf(ctx, *frmlen);
}

static int
sbk_skip_data(struct sbk_ctx *ctx, Signal__BackupFrame *frm)
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

static int
sbk_verify_mac(struct sbk_ctx *ctx, size_t len)
{
	unsigned char *ourmac, *theirmac;

	theirmac = ctx->buf + len;

	if ((ourmac = HMAC(EVP_sha256(), ctx->mackey, SBK_MACKEY_LEN, ctx->buf,
	    len, NULL, NULL)) == NULL)
		return -1;

	if (memcmp(ourmac, theirmac, SBK_MAC_LEN) != 0)
		return -1;

	return 0;
}

static unsigned char *
sbk_decrypt(struct sbk_ctx *ctx, size_t buflen)
{
	unsigned char	*plain;
	int		 len;

	ctx->iv[0] = (ctx->counter >> 24);
	ctx->iv[1] = (ctx->counter >> 16);
	ctx->iv[2] = (ctx->counter >> 8);
	ctx->iv[3] = ctx->counter;
	ctx->counter++;

	if (EVP_DecryptInit_ex(ctx->cipher, EVP_aes_256_ctr(), NULL,
	    ctx->cipherkey, ctx->iv) == 0)
		return NULL;

	if ((plain = malloc(buflen)) == NULL)
		return NULL;

	if (EVP_DecryptUpdate(ctx->cipher, plain, &len, ctx->buf, buflen) == 0)
		goto error;

	if (EVP_DecryptFinal_ex(ctx->cipher, plain + len, &len) == 0)
		goto error;

	if (EVP_CIPHER_CTX_reset(ctx->cipher) == 0)
		goto error;

	return plain;

error:
	free(plain);
	return NULL;
}

static Signal__BackupFrame *
sbk_get_start_frame(struct sbk_ctx *ctx)
{
	size_t len;

	if (sbk_read_frame(ctx, &len) == -1)
		return NULL;

	return signal__backup_frame__unpack(NULL, len, ctx->buf);
}

static Signal__BackupFrame *
sbk_get_frame(struct sbk_ctx *ctx)
{
	Signal__BackupFrame	*frm;
	unsigned char		*plain;
	size_t			 len;

	if (ctx->eof)
		return NULL;

	if (sbk_read_frame(ctx, &len) == -1)
		return NULL;

	if (len <= SBK_MAC_LEN)
		return NULL;

	len -= SBK_MAC_LEN;

	if (sbk_verify_mac(ctx, len) == -1)
		return NULL;

	if ((plain = sbk_decrypt(ctx, len)) == NULL)
		return NULL;

	if ((frm = signal__backup_frame__unpack(NULL, len, plain)) != NULL) {
		if (frm->has_end)
			ctx->eof = 1;
	}

	free(plain);
	return frm;
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

	if ((ctx->cipher = EVP_CIPHER_CTX_new()) == NULL) {
		free(ctx);
		return NULL;
	}

	ctx->bufsize = 256;
	if ((ctx->buf = malloc(ctx->bufsize)) == NULL) {
		EVP_CIPHER_CTX_free(ctx->cipher);
		free(ctx);
		return NULL;
	}

	return ctx;
}

void
sbk_ctx_free(struct sbk_ctx *ctx)
{
	EVP_CIPHER_CTX_free(ctx->cipher);
	free(ctx->buf);
	free(ctx);
}

int
sbk_open(struct sbk_ctx *ctx, const char *path, const char *passphr)
{
	Signal__BackupFrame	*frm;
	int			 ret;

	if ((ctx->fp = fopen(path, "rb")) == NULL)
		return -1;

	if ((frm = sbk_get_start_frame(ctx)) == NULL)
		goto error1;

	if (ctx->dump)
		sbk_print_frame(frm, 0);

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
	return 0;

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
sbk_dump(const char *path, const char *passphr)
{
	struct sbk_ctx		*ctx;
	Signal__BackupFrame	*frm;
	unsigned int		 nfrm;
	int			 ret;

	if ((ctx = sbk_ctx_new()) == NULL)
		return -1;

	ctx->dump = 1;

	if (sbk_open(ctx, path, passphr) == -1) {
		sbk_ctx_free(ctx);
		return -1;
	}

	ret = 0;

	for (nfrm = 1; (frm = sbk_get_frame(ctx)) != NULL; nfrm++) {
		sbk_print_frame(frm, nfrm);

		if (frm->attachment != NULL || frm->avatar != NULL)
			if ((ret = sbk_skip_data(ctx, frm)) == -1) {
				signal__backup_frame__free_unpacked(frm, NULL);
				break;
			}

		signal__backup_frame__free_unpacked(frm, NULL);
	}

	if (!ctx->eof)
		ret = -1;

	sbk_close(ctx);
	sbk_ctx_free(ctx);
	return ret;
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
			ret = sqlite3_bind_int(sqlstm, i + 1,
			    stm->parameters[i]->integerparameter);
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

	while ((frm = sbk_get_frame(ctx)) != NULL) {
		if (frm->statement != NULL)
			ret = sbk_exec_statement(db, frm->statement);
		else if (frm->attachment != NULL || frm->avatar != NULL)
			ret = sbk_skip_data(ctx, frm);

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
