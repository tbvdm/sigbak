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

#include <openssl/opensslv.h>

#ifndef LIBRESSL_VERSION_NUMBER

#include <openssl/evp.h>
#include <openssl/kdf.h>

int
HKDF(unsigned char *key, size_t keylen, const EVP_MD *md,
    const unsigned char *secret, size_t secretlen, const unsigned char *salt,
    size_t saltlen, const unsigned char *info, size_t infolen)
{
	EVP_PKEY_CTX	*pkey;
	int		 ret;

	ret = 0;

	if ((pkey = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL)) == NULL)
		goto out;

	if (EVP_PKEY_derive_init(pkey) <= 0)
		goto out;

	if (EVP_PKEY_CTX_set_hkdf_md(pkey, md) <= 0)
		goto out;

	if (EVP_PKEY_CTX_set1_hkdf_key(pkey, secret, secretlen) <= 0)
		goto out;

	if (EVP_PKEY_CTX_set1_hkdf_salt(pkey, salt, saltlen) <= 0)
		goto out;

	if (EVP_PKEY_CTX_add1_hkdf_info(pkey, info, infolen) <= 0)
		goto out;

	if (EVP_PKEY_derive(pkey, key, &keylen) <= 0)
		goto out;

	ret = 1;

out:
	EVP_PKEY_CTX_free(pkey);
	return ret;
}

#endif
