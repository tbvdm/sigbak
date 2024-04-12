/* $OpenBSD: hkdf.c,v 1.11 2024/03/25 13:09:13 jsing Exp $ */
/*
 * Copyright (c) 2014, Google Inc.
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

#include "bytestring.h"

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
	uint8_t out_hmac[EVP_MAX_MD_SIZE];
	size_t n, remaining;
	uint8_t ctr;
#ifdef HAVE_EVP_MAC
	EVP_MAC *mac = NULL;
	EVP_MAC_CTX *mac_ctx = NULL;
	OSSL_PARAM params[3];
#else
	HMAC_CTX *hmac = NULL;
#endif
	CBB cbb;
	int ret = 0;

	if (!CBB_init_fixed(&cbb, out_key, out_len))
		goto err;

#ifdef HAVE_EVP_MAC
	if ((mac = EVP_MAC_fetch(NULL, "HMAC", NULL)) == NULL)
		goto err;
	if ((mac_ctx = EVP_MAC_CTX_new(mac)) == NULL)
		goto err;

	params[0] = OSSL_PARAM_construct_octet_string("key", (uint8_t *)prk,
	    prk_len);
	params[1] = OSSL_PARAM_construct_utf8_string("digest",
	    (char *)EVP_MD_get0_name(digest), 0);
	params[2] = OSSL_PARAM_construct_end();

	if (!EVP_MAC_init(mac_ctx, NULL, 0, params))
		goto err;
#else
	if ((hmac = HMAC_CTX_new()) == NULL)
		goto err;
	if (!HMAC_Init_ex(hmac, prk, prk_len, digest, NULL))
		goto err;
#endif

	remaining = out_len;
	ctr = 0;

	/* Expand key material to desired length. */
	while (remaining > 0) {
		if (++ctr == 0) {
			goto err;
		}

#ifdef HAVE_EVP_MAC
		if (!EVP_MAC_update(mac_ctx, info, info_len))
			goto err;
		if (!EVP_MAC_update(mac_ctx, &ctr, 1))
			goto err;
		if (!EVP_MAC_final(mac_ctx, out_hmac, NULL, sizeof(out_hmac)))
			goto err;
#else
		if (!HMAC_Update(hmac, info, info_len))
			goto err;
		if (!HMAC_Update(hmac, &ctr, 1))
			goto err;
		if (!HMAC_Final(hmac, out_hmac, NULL))
			goto err;
#endif

		if ((n = remaining) > digest_len)
			n = digest_len;

		if (!CBB_add_bytes(&cbb, out_hmac, n))
			goto err;

		remaining -= n;

		if (remaining > 0) {
#ifdef HAVE_EVP_MAC
			if (!EVP_MAC_init(mac_ctx, NULL, 0, params))
				goto err;
			if (!EVP_MAC_update(mac_ctx, out_hmac, digest_len))
				goto err;
#else
			if (!HMAC_Init_ex(hmac, NULL, 0, NULL, NULL))
				goto err;
			if (!HMAC_Update(hmac, out_hmac, digest_len))
				goto err;
#endif
		}
	}

	ret = 1;

 err:
	CBB_cleanup(&cbb);
#ifdef HAVE_EVP_MAC
	EVP_MAC_CTX_free(mac_ctx);
	EVP_MAC_free(mac);
#else
	HMAC_CTX_free(hmac);
#endif
	explicit_bzero(out_hmac, sizeof(out_hmac));

	return ret;
}

#endif
