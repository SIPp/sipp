#pragma once

#include "jlsrtp.hpp"

#include <memory>

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
    explicit SrtpChannel(unsigned int ssrc) : JLSRTP(ssrc, "127.0.0.1", 0) {}
    SrtpChannel &operator=(const JLSRTP &base)
    {
        JLSRTP::operator=(base);
        return *this;
    }
};

/* A call's SRTP context, made on first use: a call has eight, and most
 * calls use none. It keeps the SSRC of when the call was made, as a
 * context made with the call did. */
class LazySrtpChannel
{
public:
    LazySrtpChannel() : ssrc(global_ssrc_id) {}

    SrtpChannel &get()
    {
        if (!context) {
            context.reset(new SrtpChannel(ssrc));
        }
        return *context;
    }
    operator SrtpChannel &()
    {
        return get();
    }

    /* Whether the call has made this context: one without SRTP makes none */
    bool made() const
    {
        return context != nullptr;
    }

    /* The context to hand a playback thread, which copies only one with
     * a crypto tag: without SRTP, a shared one without keys, rather than
     * one made for the call */
    const SrtpChannel &forPlayback() const
    {
        static const SrtpChannel none(0);
        return context ? *context : none;
    }

    /* The context's methods, made on first use */
    SrtpChannel *operator->()
    {
        return &get();
    }

private:
    unsigned int ssrc;
    std::unique_ptr<SrtpChannel> context;
};

/* A call's SRTP contexts of one media: as the client (UAC) and as the
 * server (UAS), each sends with one and receives with one. */
struct SrtpMedia {
    LazySrtpChannel txUAC, rxUAC, txUAS, rxUAS;

    LazySrtpChannel &tx(bool client)
    {
        return client ? txUAC : txUAS;
    }
    LazySrtpChannel &rx(bool client)
    {
        return client ? rxUAC : rxUAS;
    }
};
