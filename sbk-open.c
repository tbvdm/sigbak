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
#include <string.h>

#include <openssl/sha.h>

#include "sbk-internal.h"

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
#ifdef HAVE_EVP_MAC
	EVP_MAC *mac;
#endif

	if ((ctx = calloc(1, sizeof *ctx)) == NULL) {
		warn(NULL);
		return NULL;
	}

	if ((ctx->cipher_ctx = EVP_CIPHER_CTX_new()) == NULL) {
		warnx("Cannot create cipher context");
		goto error;
	}

#ifdef HAVE_EVP_MAC
	if ((mac = EVP_MAC_fetch(NULL, "HMAC", NULL)) == NULL) {
		warnx("Cannot fetch MAC implementation");
		goto error;
	}

	if ((ctx->mac_ctx = EVP_MAC_CTX_new(mac)) == NULL) {
		warnx("Cannot create MAC context");
		EVP_MAC_free(mac);
		goto error;
	}

	EVP_MAC_free(mac);
#else
	if ((ctx->hmac_ctx = HMAC_CTX_new()) == NULL) {
		warnx("Cannot create MAC context");
		goto error;
	}
#endif

	if (sbk_grow_buffers(ctx, 8192) == -1)
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
#ifdef HAVE_EVP_MAC
		EVP_MAC_CTX_free(ctx->mac_ctx);
#else
		HMAC_CTX_free(ctx->hmac_ctx);
#endif
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

	ctx->backup_version = 0;
	ctx->state = SBK_FIRST_FRAME;

	if ((frm = sbk_get_first_frame(ctx)) == NULL)
		goto error;

	if (frm->header == NULL) {
		warnx("Missing header frame");
		goto error;
	}

	if (frm->header->has_version) {
		ctx->backup_version = frm->header->version;
		if (ctx->backup_version > 1) {
			warnx("Backup version %u not yet supported",
			    ctx->backup_version);
			goto error;
		}
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

#ifdef HAVE_EVP_MAC
	ctx->mac_params[0] = OSSL_PARAM_construct_octet_string("key",
	    ctx->mac_key, SBK_MAC_KEY_LEN);
	ctx->mac_params[1] = OSSL_PARAM_construct_utf8_string("digest",
	    "SHA256", 0);
	ctx->mac_params[2] = OSSL_PARAM_construct_end();
#else
	if (!HMAC_Init_ex(ctx->hmac_ctx, ctx->mac_key, SBK_MAC_KEY_LEN,
	    EVP_sha256(), NULL)) {
		warnx("Cannot initialise MAC context");
		goto error;
	}
#endif

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
