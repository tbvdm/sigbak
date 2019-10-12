/*
 * This file must be suited to your system. Edit it if necessary.
 *
 * Several systems are already supported; see further below. On those systems,
 * no editing should be necessary.
 */

/* Define if you have asprintf() and vasprintf(). */
/* #define HAVE_ASPRINTF */

/* Define if you have the err() family of functions. */
/* #define HAVE_ERR */

/* Define if you have explicit_bzero(). */
/* #define HAVE_EXPLICIT_BZERO */

/* Define if you have explicit_memset(). */
/* #define HAVE_EXPLICIT_MEMSET */

/* Define if your fopen() supports the "x" mode extension. */
/* #define HAVE_FOPEN_X_MODE */

/* Define if you have freezero(). */
/* #define HAVE_FREEZERO */

/* Define if you have getpagesize(). */
/* #define HAVE_GETPAGESIZE */

/* Define if you have getprogname(). */
/* #define HAVE_GETPROGNAME */

/* Define if you have memset_s(). */
/* #define HAVE_MEMSET_S */

/* Define if you have pledge(). */
/* #define HAVE_PLEDGE */

/* Define if you have readpassphrase(). */
/* #define HAVE_READPASSPHRASE */

/* Define if you have reallocarray(). */
/* #define HAVE_REALLOCARRAY */

/* Define if you have recallocarray(). */
/* #define HAVE_RECALLOCARRAY */

/* Define if you have unveil(). */
/* #define HAVE_UNVEIL */

/* Define if your compiler supports __attribute__(). */
/* #define HAVE___ATTRIBUTE__ */

#ifdef __DragonFly__

/* Untested */

#define HAVE_ASPRINTF
#define HAVE_ERR
#define HAVE_EXPLICIT_BZERO
#define HAVE_FOPEN_X_MODE
#define HAVE_FREEZERO
#define HAVE_GETPAGESIZE
#define HAVE_GETPROGNAME
#define HAVE_READPASSPHRASE
#define HAVE_REALLOCARRAY
#define HAVE_RECALLOCARRAY
#define HAVE___ATTRIBUTE__

#elif defined(__FreeBSD__)

#define HAVE_ASPRINTF
#define HAVE_ERR
#define HAVE_EXPLICIT_BZERO
#define HAVE_FOPEN_X_MODE
#define HAVE_GETPAGESIZE
#define HAVE_GETPROGNAME
#define HAVE_READPASSPHRASE
#define HAVE_REALLOCARRAY
#define HAVE___ATTRIBUTE__

#elif defined(__NetBSD__)

#define _OPENBSD_SOURCE

#define HAVE_ASPRINTF
#define HAVE_ERR
#define HAVE_EXPLICIT_MEMSET
#define HAVE_FOPEN_X_MODE
#define HAVE_GETPAGESIZE
#define HAVE_GETPROGNAME
#define HAVE_REALLOCARRAY
#define HAVE___ATTRIBUTE__

#elif defined(__OpenBSD__)

#define HAVE_ASPRINTF
#define HAVE_ERR
#define HAVE_EXPLICIT_BZERO
#define HAVE_FOPEN_X_MODE
#define HAVE_FREEZERO
#define HAVE_GETPAGESIZE
#define HAVE_GETPROGNAME
#define HAVE_PLEDGE
#define HAVE_READPASSPHRASE
#define HAVE_REALLOCARRAY
#define HAVE_RECALLOCARRAY
#define HAVE_UNVEIL
#define HAVE___ATTRIBUTE__

#elif defined(__linux__)

/* Tested on Debian 9.11 and 10.1 */

#define _GNU_SOURCE

#define HAVE_ASPRINTF
#define HAVE_ERR
#define HAVE_FOPEN_X_MODE
#define HAVE_GETPAGESIZE
#define HAVE___ATTRIBUTE__

/* Indirectly include features.h for __GLIBC_PREREQ */
#include <stdio.h>

#ifdef __GLIBC_PREREQ
#if __GLIBC_PREREQ(2, 25)
#define HAVE_EXPLICIT_BZERO
#endif
#if __GLIBC_PREREQ(2, 26)
#define HAVE_REALLOCARRAY
#endif
#endif

#endif
