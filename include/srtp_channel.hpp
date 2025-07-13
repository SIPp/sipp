#pragma once

#include "jlsrtp.hpp"

#ifdef GLOBALS_FULL_DEFINITION
#define MAYBE_EXTERN
#define DEFVAL(value) = value
#else
#define MAYBE_EXTERN extern
#define DEFVAL(value)
#endif

MAYBE_EXTERN unsigned int global_ssrc_id DEFVAL(0);

class SrtpChannel : public JLSRTP
{
public:
    SrtpChannel() : JLSRTP(global_ssrc_id, "127.0.0.1", 0) {}
    SrtpChannel(const JLSRTP &base) : JLSRTP(base) {}
    SrtpChannel &operator=(const JLSRTP &base)
    {
        JLSRTP::operator=(base);
        return *this;
    }
};
