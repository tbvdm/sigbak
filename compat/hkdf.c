/* $OpenBSD: hkdf.c,v 1.9 2023/06/01 02:34:23 tb Exp $ */
/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "../config.h"

#ifndef HAVE_HKDF

#include <string.h>

#include <openssl/err.h>
#ifdef HAVE_EVP_MAC
#include <openssl/evp.h>
#endif
#include <openssl/hmac.h>

#include "../compat.h"

/* https://tools.ietf.org/html/rfc5869#section-2 */
int
HKDF(uint8_t *out_key, size_t out_len, const EVP_MD *digest,
    const uint8_t *secret, size_t secret_len, const uint8_t *salt,
    size_t salt_len, const uint8_t *info, size_t info_len)
{
	uint8_t prk[EVP_MAX_MD_SIZE];
	size_t prk_len;

	if (!HKDF_extract(prk, &prk_len, digest, secret, secret_len, salt,
	    salt_len))
		return 0;
	if (!HKDF_expand(out_key, out_len, digest, prk, prk_len, info,
	    info_len))
		return 0;

	return 1;
}

/* https://tools.ietf.org/html/rfc5869#section-2.2 */
int
HKDF_extract(uint8_t *out_key, size_t *out_len,
    const EVP_MD *digest, const uint8_t *secret, size_t secret_len,
    const uint8_t *salt, size_t salt_len)
{
	unsigned int len;

	/*
	 * If salt is not given, HashLength zeros are used. However, HMAC does
	 * that internally already so we can ignore it.
	 */
	if (HMAC(digest, salt, salt_len, secret, secret_len, out_key, &len) ==
	    NULL) {
		return 0;
	}
	*out_len = len;
	return 1;
}

/* https://tools.ietf.org/html/rfc5869#section-2.3 */
int
HKDF_expand(uint8_t *out_key, size_t out_len,
    const EVP_MD *digest, const uint8_t *prk, size_t prk_len,
    const uint8_t *info, size_t info_len)
{
	const size_t digest_len = EVP_MD_size(digest);
	uint8_t previous[EVP_MAX_MD_SIZE];
	size_t n, done = 0;
	unsigned int i;
	int ret = 0;
#ifdef HAVE_EVP_MAC
	EVP_MAC *mac;
	EVP_MAC_CTX *mac_ctx = NULL;
	OSSL_PARAM params[3];
#else
	HMAC_CTX *hmac;
#endif

	/* Expand key material to desired length. */
	n = (out_len + digest_len - 1) / digest_len;
	if (out_len + digest_len < out_len || n > 255) {
		return 0;
	}

#ifdef HAVE_EVP_MAC
	if ((mac = EVP_MAC_fetch(NULL, "HMAC", NULL)) == NULL)
		goto out;

	if ((mac_ctx = EVP_MAC_CTX_new(mac)) == NULL)
		goto out;

	params[0] = OSSL_PARAM_construct_octet_string("key", (uint8_t *)prk,
	    prk_len);
	params[1] = OSSL_PARAM_construct_utf8_string("digest",
	    (char *)EVP_MD_get0_name(digest), 0);
	params[2] = OSSL_PARAM_construct_end();
#else
	if ((hmac = HMAC_CTX_new()) == NULL)
		goto out;

	if (!HMAC_Init_ex(hmac, prk, prk_len, digest, NULL))
		goto out;
#endif

	for (i = 0; i < n; i++) {
		uint8_t ctr = i + 1;
		size_t todo;

#ifdef HAVE_EVP_MAC
		if (!EVP_MAC_init(mac_ctx, NULL, 0, params))
			goto out;

		if (i != 0 && !EVP_MAC_update(mac_ctx, previous, digest_len))
			goto out;

		if (!EVP_MAC_update(mac_ctx, info, info_len) ||
		    !EVP_MAC_update(mac_ctx, &ctr, 1) ||
		    !EVP_MAC_final(mac_ctx, previous, NULL, sizeof(previous)))
			goto out;
#else
		if (i != 0 && (!HMAC_Init_ex(hmac, NULL, 0, NULL, NULL) ||
		    !HMAC_Update(hmac, previous, digest_len)))
			goto out;

		if (!HMAC_Update(hmac, info, info_len) ||
		    !HMAC_Update(hmac, &ctr, 1) ||
		    !HMAC_Final(hmac, previous, NULL))
			goto out;
#endif

		todo = digest_len;
		if (todo > out_len - done)
			todo = out_len - done;

		memcpy(out_key + done, previous, todo);
		done += todo;
	}

	ret = 1;

 out:
#ifdef HAVE_EVP_MAC
	EVP_MAC_CTX_free(mac_ctx);
	EVP_MAC_free(mac);
#else
	HMAC_CTX_free(hmac);
#endif
	explicit_bzero(previous, sizeof(previous));
	return ret;
}

#endif
