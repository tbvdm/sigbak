/*
 * Written by Tim van der Molen.
 * Public domain.
 */

#include "../config.h"

#ifndef HAVE_EXPLICIT_BZERO

#ifdef HAVE_EXPLICIT_MEMSET

#include <string.h>

void
explicit_bzero(void *buf, size_t len)
{
	explicit_memset(buf, 0, len);
}

#elif defined(HAVE_MEMSET_S)

#define __STDC_WANT_LIB_EXT1__ 1

#include <string.h>

void
explicit_bzero(void *buf, size_t len)
{
	memset_s(buf, len, 0, len);
}

#else

#include <openssl/crypto.h>

void
explicit_bzero(void *buf, size_t len)
{
	OPENSSL_cleanse(buf, len);
}

#endif

#endif
