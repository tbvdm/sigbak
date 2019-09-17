/*	$OpenBSD: explicit_bzero.c,v 1.4 2015/08/31 02:53:57 guenther Exp $ */
/*
 * Public domain.
 * Written by Matthew Dempsky.
 */

#include "../config.h"

#ifndef HAVE_EXPLICIT_BZERO

#include <string.h>

#ifdef HAVE_EXPLICIT_MEMSET

void
explicit_bzero(void *buf, size_t len)
{
	explicit_memset(buf, 0, len);
}

#elif defined(HAVE_MEMSET_S)

#define __STDC_WANT_LIB_EXT1__ 1

void
explicit_bzero(void *buf, size_t len)
{
	memset_s(buf, len, 0, len);
}

#else

__attribute__((weak)) void
__explicit_bzero_hook(void *buf, size_t len)
{
}

void
explicit_bzero(void *buf, size_t len)
{
	memset(buf, 0, len);
	__explicit_bzero_hook(buf, len);
}

#endif

#endif
