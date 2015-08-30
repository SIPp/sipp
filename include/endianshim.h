#ifndef ENDIANSHIM_H
#define ENDIANSHIM_H 1

#if defined(__CYGWIN) || defined(__LINUX)
#include <endian.h>
#elif defined(__FreeBSD__)
#include <sys/endian.h>
#elif defined(__DARWIN)
#include <libkern/OSByteOrder.h>
#endif

#ifdef __DARWIN
#define le16toh(x) OSSwapLittleToHostInt16(x)
#endif

/* HP-UX 11 is missing byteswap.h, so we provide our own bswap_16() */
#ifdef __HPUX
#define bswap_16(x) ((uint16_t)( \
    (((uint16_t)(x)) << 8) | \
    (((uint16_t)(x)) >> 8)))

#define le16toh(x) bswap_16(x)
#endif

#endif /* ENDIANSHIM_H */
