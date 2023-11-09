/*
 * Written by Tim van der Molen.
 * Public domain.
 */

#include "../config.h"

#include <openssl/opensslv.h>

#if !defined(HAVE_EXPLICIT_BZERO)
#if !defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER >= 0x3080100fL

#include <openssl/crypto.h>

void
explicit_bzero(void *buf, size_t len)
{
	OPENSSL_cleanse(buf, len);
}

#endif
#endif
