/*
 * Copyright (c) 2019 Tim van der Molen <tim@kariliq.nl>
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

/*
 * This file must be suited to your system. Edit it if necessary.
 *
 * Several systems are already supported; see farther below. On those systems,
 * no editing should be necessary.
 */

/* Define if you have asprintf() and vasprintf(). */
/* #define HAVE_ASPRINTF */

/*
 * Define if you have be32toh(). If you do, also define either HAVE_ENDIAN_H or
 * HAVE_SYS_ENDIAN_H below.
 */
/* #define HAVE_BE32TOH */

/* Define if you have <endian.h>. */
/* #define HAVE_ENDIAN_H */

/* Define if you have the err() family of functions. */
/* #define HAVE_ERR */

/* Define if you have explicit_bzero(). */
/* #define HAVE_EXPLICIT_BZERO */

/* Define if your fopen() supports the "x" mode extension. */
/* #define HAVE_FOPEN_X_MODE */

/* Define if you have getprogname() and setprogname(). */
/* #define HAVE_GETPROGNAME */

/* Define if you have pledge(). */
/* #define HAVE_PLEDGE */

/* Define if you have readpassphrase(). */
/* #define HAVE_READPASSPHRASE */

/* Define if you have reallocarray(). */
/* #define HAVE_REALLOCARRAY */

/* Define if you have <sys/endian.h>. */
/* #define HAVE_SYS_ENDIAN_H */

/* Define if your struct tm has a tm_gmtoff member. */
/* #define HAVE_TM_GMTOFF */

/* Define if you have unveil(). */
/* #define HAVE_UNVEIL */

/*
 * macOS
 */

#ifdef __APPLE__

#define HAVE_ASPRINTF
#define HAVE_ERR
#define HAVE_FOPEN_X_MODE
#define HAVE_GETPROGNAME
#define HAVE_READPASSPHRASE
#define HAVE_TM_GMTOFF

#endif

/*
 * Cygwin
 */

#ifdef __CYGWIN__

#define _GNU_SOURCE

#define HAVE_ASPRINTF
#define HAVE_BE32TOH
#define HAVE_ENDIAN_H
#define HAVE_ERR
/* Cygwin's explicit_bzero() merely is a wrapper around bzero(). */
/* #define HAVE_EXPLICIT_BZERO */
#define HAVE_FOPEN_X_MODE
#define HAVE_GETPROGNAME
#define HAVE_REALLOCARRAY
#define HAVE_TM_GMTOFF

#endif

/*
 * DragonFly BSD
 */

#ifdef __DragonFly__

#define HAVE_ASPRINTF
#define HAVE_BE32TOH
#define HAVE_ERR
#define HAVE_EXPLICIT_BZERO
#define HAVE_FOPEN_X_MODE
#define HAVE_GETPROGNAME
#define HAVE_READPASSPHRASE
#define HAVE_REALLOCARRAY
#define HAVE_SYS_ENDIAN_H
#define HAVE_TM_GMTOFF

#endif

/*
 * FreeBSD
 */

#ifdef __FreeBSD__

#define HAVE_ASPRINTF
#define HAVE_BE32TOH
#define HAVE_ERR
#define HAVE_EXPLICIT_BZERO
#define HAVE_FOPEN_X_MODE
#define HAVE_GETPROGNAME
#define HAVE_READPASSPHRASE
#define HAVE_REALLOCARRAY
#define HAVE_SYS_ENDIAN_H
#define HAVE_TM_GMTOFF

#endif

/*
 * NetBSD
 */

#ifdef __NetBSD__

#define _OPENBSD_SOURCE

#define HAVE_ASPRINTF
#define HAVE_BE32TOH
#define HAVE_ERR
#define HAVE_FOPEN_X_MODE
#define HAVE_GETPROGNAME
#define HAVE_REALLOCARRAY
#define HAVE_SYS_ENDIAN_H
#define HAVE_TM_GMTOFF

#endif

/*
 * OpenBSD
 */

#ifdef __OpenBSD__

#define HAVE_ASPRINTF
#define HAVE_BE32TOH
#define HAVE_ENDIAN_H
#define HAVE_ERR
#define HAVE_EXPLICIT_BZERO
#define HAVE_FOPEN_X_MODE
#define HAVE_GETPROGNAME
#define HAVE_PLEDGE
#define HAVE_READPASSPHRASE
#define HAVE_REALLOCARRAY
#define HAVE_TM_GMTOFF
#define HAVE_UNVEIL

#endif

/*
 * Linux
 */

#ifdef __linux__

#define _GNU_SOURCE

/* All modern versions of glibc, musl and bionic have these. */
#define HAVE_ASPRINTF
#define HAVE_BE32TOH
#define HAVE_ENDIAN_H
#define HAVE_ERR
#define HAVE_FOPEN_X_MODE
#define HAVE_TM_GMTOFF

#include <features.h>

/* glibc */

#ifdef __GLIBC_PREREQ
#  if __GLIBC_PREREQ(2, 25)
#    define HAVE_EXPLICIT_BZERO
#  endif
#  if __GLIBC_PREREQ(2, 26)
#    define HAVE_REALLOCARRAY
#  endif
#endif

/* bionic */

#ifdef __ANDROID_API__
#  if __ANDROID_API__ >= 21
#    define HAVE_GETPROGNAME
#  endif
#  if __ANDROID_API__ >= 29
#    define HAVE_REALLOCARRAY
#  endif
#endif

/* musl */

/* Define if you have musl >= 1.1.20. */
/* #define HAVE_EXPLICIT_BZERO */

/* Define if you have musl >= 1.2.2. */
/* #define HAVE_REALLOCARRAY */

#endif

/*
 * Solaris
 */

#ifdef __sun

#define HAVE_ASPRINTF
#define HAVE_ERR
#define HAVE_FOPEN_X_MODE
#define HAVE_GETPROGNAME

#endif

/*
 * LibreSSL/OpenSSL
 */

#include <openssl/opensslv.h>

#ifdef LIBRESSL_VERSION_NUMBER
#  if LIBRESSL_VERSION_NUMBER >= 0x2060000fL
#    define HAVE_HKDF
#  endif
#  if LIBRESSL_VERSION_NUMBER >= 0x2070000fL
#    define HAVE_EVP_MD_CTX_NEW
#    define HAVE_HMAC_CTX_NEW
#  endif
#else
#  if OPENSSL_VERSION_NUMBER >= 0x10100000L
#    define HAVE_EVP_MD_CTX_NEW
#    define HAVE_HMAC_CTX_NEW
#  endif
#  if OPENSSL_VERSION_NUMBER >= 0x30000000L
#    define HAVE_EVP_MAC
#  endif
#endif
