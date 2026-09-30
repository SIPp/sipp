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

    /* The methods of SrtpChannel that a call uses */
    int selectHashAlgorithm(HashType hashType, ActiveCrypto crypto_attrib = ACTIVE_CRYPTO)
    {
        return get().selectHashAlgorithm(hashType, crypto_attrib);
    }

    int selectCipherAlgorithm(CipherType cipherType, ActiveCrypto crypto_attrib = ACTIVE_CRYPTO)
    {
        return get().selectCipherAlgorithm(cipherType, crypto_attrib);
    }

    int setCryptoTag(unsigned int tag, ActiveCrypto crypto_attrib = ACTIVE_CRYPTO)
    {
        return get().setCryptoTag(tag, crypto_attrib);
    }

    int swapCrypto()
    {
        return get().swapCrypto();
    }

    void setOfferedCryptoSuite(const std::string &suite, ActiveCrypto crypto_attrib)
    {
        get().setOfferedCryptoSuite(suite, crypto_attrib);
    }

    int encodeMasterKeySalt(std::string &mks, ActiveCrypto crypto_attrib = ACTIVE_CRYPTO)
    {
        return get().encodeMasterKeySalt(mks, crypto_attrib);
    }

    void setID(CryptoContextID id)
    {
        get().setID(std::move(id));
    }

    void setSrtpPayloadSize(unsigned int size)
    {
        get().setSrtpPayloadSize(size);
    }

    void setSrtpHeaderSize(unsigned int size)
    {
        get().setSrtpHeaderSize(size);
    }

    int resetCipherState()
    {
        return get().resetCipherState();
    }

    int generateMasterSalt(ActiveCrypto crypto_attrib = ACTIVE_CRYPTO)
    {
        return get().generateMasterSalt(crypto_attrib);
    }

    int generateMasterKey(ActiveCrypto crypto_attrib = ACTIVE_CRYPTO)
    {
        return get().generateMasterKey(crypto_attrib);
    }

    std::string dumpCryptoContext()
    {
        return get().dumpCryptoContext();
    }

    int deriveSessionSaltingKey()
    {
        return get().deriveSessionSaltingKey();
    }

    int deriveSessionEncryptionKey()
    {
        return get().deriveSessionEncryptionKey();
    }

    int deriveSessionAuthenticationKey()
    {
        return get().deriveSessionAuthenticationKey();
    }

    int selectEncryptionKey()
    {
        return get().selectEncryptionKey();
    }

    int selectDecryptionKey()
    {
        return get().selectDecryptionKey();
    }

    void freeCiphers()
    {
        get().freeCiphers();
    }

private:
    unsigned int ssrc;
    std::unique_ptr<SrtpChannel> context;
};
