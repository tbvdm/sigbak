/*
 * Written by Tim van der Molen.
 * Public domain.
 */

#include "../config.h"

#ifndef HAVE_EXPLICIT_BZERO

#include <openssl/crypto.h>

void
explicit_bzero(void *buf, size_t len)
{
	OPENSSL_cleanse(buf, len);
}

#endif
