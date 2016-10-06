#ifndef ENDIANSHIM_H
#define ENDIANSHIM_H 1

/* Fetch HAVE_ENDIAN_H, HAVE_SYS_ENDIAN_H, HAVE_DECL_LE16TOH */
#include "config.h"

#ifdef HAVE_ENDIAN_H
/* Linux and friends. */
# include <endian.h>
#endif
#ifdef HAVE_SYS_ENDIAN_H
/* BSDs */
# include <sys/endian.h>
#endif
#if defined(__DARWIN)
/* Darwin does something else. */
#include <libkern/OSByteOrder.h>
#endif
#if defined(__SUNOS)
/* Solaris and derivatives */
#include <sys/byteorder.h>
#endif

#if defined(__DARWIN)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#elif defined(__HPUX)
/* HPUX is big endian (apparently..) */
#define le16toh(x) ((uint16_t)( \
    (((uint16_t)(x)) << 8) | \
    (((uint16_t)(x)) >> 8)))

#elif defined(__SUNOS)
#ifdef _BIG_ENDIAN
#   define le16toh(x) BSWAP_16(x)
#else
#   define le16toh(x) (x)
#endif

#elif !defined(HAVE_DECL_LE16TOH) || HAVE_DECL_LE16TOH == 0
/* le16toh() is missing in glibc before 2.9 */
#if BYTE_ORDER == BIG_ENDIAN
#   define le16toh(x) ((uint16_t)( \
        (((uint16_t)(x)) << 8) | \
        (((uint16_t)(x)) >> 8)))
#elif BYTE_ORDER == LITTLE_ENDIAN
#   define le16toh(x) (x)
#else /* BYTE_ORDER == <undefined> */
#   error Unknown endianness
#endif

#endif /* !HAVE_DECL_LE16TOH */

#endif /* ENDIANSHIM_H */
