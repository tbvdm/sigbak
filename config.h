#ifdef __DragonFly__

/*
 * DragonFly BSD (untested)
 */

#define HAVE_ASPRINTF
#define HAVE_ERR
#define HAVE_FOPEN_X_MODE
#define HAVE_FREEZERO
#define HAVE_GETPAGESIZE
#define HAVE_GETPROGNAME
/* #define HAVE_PLEDGE */
#define HAVE_READPASSPHRASE
#define HAVE_REALLOCARRAY
#define HAVE_RECALLOCARRAY
/* #define HAVE_UNVEIL */
#define HAVE___ATTRIBUTE__

#define HAVE_EXPLICIT_BZERO
/* #define HAVE_EXPLICIT_MEMSET */
/* #define HAVE_MEMSET_S */

#elif defined(__FreeBSD__)

/*
 * FreeBSD
 */

#define HAVE_ASPRINTF
#define HAVE_ERR
#define HAVE_FOPEN_X_MODE
/* #define HAVE_FREEZERO */
#define HAVE_GETPAGESIZE
#define HAVE_GETPROGNAME
/* #define HAVE_PLEDGE */
#define HAVE_READPASSPHRASE
#define HAVE_REALLOCARRAY
/* #define HAVE_RECALLOCARRAY */
/* #define HAVE_UNVEIL */
#define HAVE___ATTRIBUTE__

#define HAVE_EXPLICIT_BZERO
/* #define HAVE_EXPLICIT_MEMSET */
/* #define HAVE_MEMSET_S */

#elif defined(__NetBSD__)

/*
 * NetBSD
 */

#define _OPENBSD_SOURCE

#define HAVE_ASPRINTF
#define HAVE_ERR
#define HAVE_FOPEN_X_MODE
/* #define HAVE_FREEZERO */
#define HAVE_GETPAGESIZE
#define HAVE_GETPROGNAME
/* #define HAVE_PLEDGE */
/* #define HAVE_READPASSPHRASE */
#define HAVE_REALLOCARRAY
/* #define HAVE_RECALLOCARRAY */
/* #define HAVE_UNVEIL */
#define HAVE___ATTRIBUTE__

/* #define HAVE_EXPLICIT_BZERO */
#define HAVE_EXPLICIT_MEMSET
/* #define HAVE_MEMSET_S */

#elif defined(__OpenBSD__)

/*
 * OpenBSD
 */

#define HAVE_ASPRINTF
#define HAVE_ERR
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

#define HAVE_EXPLICIT_BZERO
/* #define HAVE_EXPLICIT_MEMSET */
/* #define HAVE_MEMSET_S */

#elif defined(__linux__)

/*
 * Linux (tested on Debian 9.11 and 10.1)
 */

#define _GNU_SOURCE

#define HAVE_ASPRINTF
#define HAVE_ERR
#define HAVE_FOPEN_X_MODE
/* #define HAVE_FREEZERO */
#define HAVE_GETPAGESIZE
/* #define HAVE_GETPROGNAME */
/* #define HAVE_PLEDGE */
/* #define HAVE_READPASSPHRASE */
/* #define HAVE_REALLOCARRAY */
/* #define HAVE_RECALLOCARRAY */
/* #define HAVE_UNVEIL */
#define HAVE___ATTRIBUTE__

/* #define HAVE_EXPLICIT_BZERO */
/* #define HAVE_EXPLICIT_MEMSET */
/* #define HAVE_MEMSET_S */

#else

/*
 * Other
 */

/* Define if you have asprintf() and vasprintf(). */
/* #define HAVE_ASPRINTF */

/* Define if you have the err() family of functions. */
/* #define HAVE_ERR */

/* Define if your fopen() supports the "x" mode extension. */
/* #define HAVE_FOPEN_X_MODE */

/* Define if you have freezero(). */
/* #define HAVE_FREEZERO */

/* Define if you have getpagesize(). */
/* #define HAVE_GETPAGESIZE */

/* Define if you have getprogname(). */
/* #define HAVE_GETPROGNAME */

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

/* Define if you have explicit_bzero(). */
/* #define HAVE_EXPLICIT_BZERO */

/*
 * Define if you don't have explicit_bzero(), but you do have
 * explicit_memset().
 */
/* #define HAVE_EXPLICIT_MEMSET */

/* Define if you don't have explicit_bzero(), but you do have memset_s(). */
/* #define HAVE_MEMSET_S */

#endif
