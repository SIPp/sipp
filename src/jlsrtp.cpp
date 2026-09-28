/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA
 *
 *  Author: Jeannot Langlois (jeannot.langlois@gmail.com) -- 2016-2020
 */

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)

#include "jlsrtp.hpp"
#include <iostream>
#include <string.h>
#include <iomanip>
#include <stdio.h>
#include <limits.h>
#include <algorithm>
#include <assert.h>
#include <iterator>
#include <sstream> // std::ostringstream

/* The AES-ECB cipher for a key of keySize bytes, nullptr if there is none
 * or the TLS library lacks it. */
static const EVP_CIPHER* aesEcbCipher(size_t keySize)
{
    switch (keySize) {
    case JLSRTP_ENCRYPTION_KEY_LENGTH:
        return EVP_aes_128_ecb();
#if !defined(USE_WOLFSSL) || defined(WOLFSSL_AES_192)
    case JLSRTP_AES_192_KEY_LENGTH:
        return EVP_aes_192_ecb();
#endif
#if !defined(USE_WOLFSSL) || defined(WOLFSSL_AES_256)
    case JLSRTP_AES_256_KEY_LENGTH:
        return EVP_aes_256_ecb();
#endif
    default:
        return nullptr;
    }
}

/* Makes an AES-ECB context when it is first needed: most calls never
 * use SRTP, and each context costs a cipher fetch. False if it fails. */
static bool aesContext(EVP_CIPHER_CTX*& ctx)
{
    if (!ctx) {
        ctx = EVP_CIPHER_CTX_new();
        if (ctx && EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            ctx = nullptr;
        }
    }
    return ctx != nullptr;
}

/* Sets the key of an AES-ECB context, switching it to the AES variant of
 * the key's length. Returns 1 on success, as EVP_EncryptInit_ex() does. */
static int setAESKey(EVP_CIPHER_CTX*& ctx, const std::vector<unsigned char>& key)
{
    const EVP_CIPHER* cipher = nullptr; // keep the context's cipher

    if (!aesContext(ctx)) {
        return 0;
    }

    if (EVP_CIPHER_CTX_key_length(ctx) != static_cast<int>(key.size())) {
        cipher = aesEcbCipher(key.size());
        if (!cipher) {
            return 0;
        }
    }
    return EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), nullptr);
}

/* The master key length a cipher takes: RFC 6188 uses the AES key size, and
 * the NULL cipher keeps the 128-bit PRF of RFC 4568. */
static size_t masterKeyLength(CipherType cipher)
{
    switch (cipher) {
    case AES_CM_192:
        return JLSRTP_AES_192_KEY_LENGTH;
    case AES_CM_256:
        return JLSRTP_AES_256_KEY_LENGTH;
    default:
        return JLSRTP_ENCRYPTION_KEY_LENGTH;
    }
}

// --------------- PRIVATE METHODS ----------------

bool JLSRTP::isBase64(unsigned char c)
{
    return (isalnum(c) ||
           (c == '+') ||
           (c == '/'));
}

int JLSRTP::resetPseudoRandomState(std::vector<unsigned char> iv)
{
    unsigned int ivSize = 0;

    ivSize = iv.size();
    assert(ivSize == JLSRTP_SALTING_KEY_LENGTH);
    if (ivSize == JLSRTP_SALTING_KEY_LENGTH)
    {
        // aes_ctr128_encrypt() requires 'num' and 'ecount' to be set to zero on the first call
        _pseudorandomstate.num = 0;
        memset(_pseudorandomstate.ecount, 0, sizeof(_pseudorandomstate.ecount));

        // Clear BOTH high-order bytes [0..13] for 'IV' AND low-order bytes [14..15] for 'counter'
        memset(_pseudorandomstate.ivec, 0, AES_BLOCK_SIZE);
        // Copy 'IV' into high-order bytes [0..13] -- low-order bytes [14..15] remain zero
        memcpy(_pseudorandomstate.ivec, iv.data(), iv.size());

        return 0;
    }
    else
    {
        return -1;
    }
}

int JLSRTP::pseudorandomFunction(std::vector<unsigned char> iv, int n, std::vector<unsigned char> &output)
{
    int rc = 0;
    unsigned int num_loops = 0;
    std::vector<unsigned char> block;
    std::vector<unsigned char> input;
    unsigned int ivSize = 0;
    unsigned int keySize = 0;
    int retVal = 0;

    switch (_active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            ivSize = iv.size();
            keySize = _primary_crypto.master_key.size();

            assert(ivSize == JLSRTP_SALTING_KEY_LENGTH);
            assert(aesEcbCipher(keySize));
            if (ivSize == JLSRTP_SALTING_KEY_LENGTH)
            {
                if (aesEcbCipher(keySize))
                {
                    input.resize(AES_BLOCK_SIZE);
                    output.clear();

                    // Determine how many AES_BLOCK_SIZE-byte encryption loops will be necessary to achieve at least n/8 bytes of pseudorandom ciphertext
                    num_loops = (n % JLSRTP_PSEUDORANDOM_BITS) ? ((n / JLSRTP_PSEUDORANDOM_BITS) + 1) : (n / JLSRTP_PSEUDORANDOM_BITS);

                    // Set encryption key
                    rc = setAESPseudoRandomFunctionKey(_active_crypto);
                    if (rc == 0)
                    {
                        // Reset IV/counter state
                        resetPseudoRandomState(iv);

                        for (unsigned int i = 0; i < num_loops; i++)
                        {
                            // Encrypt given _pseudorandomstate.ivec input using aes_key to block
                            block.clear();
                            block.resize(AES_BLOCK_SIZE);
                            AES_ctr128_pseudorandom_EVPencrypt(input.data(), block.data(), AES_BLOCK_SIZE, _pseudorandomstate.ivec, _pseudorandomstate.ecount, &_pseudorandomstate.num);
                            output.insert(output.end(), block.begin(), block.end());
                        }

                        // Truncate output to n/8 bytes
                        output.resize(n / 8);

                        retVal = 0;
                    }
                    else
                    {
                        retVal = -3;
                    }
                }
                else
                {
                    retVal = -2;
                }
            }
            else
            {
                retVal = -1;
            }
        }
        break;

        case SECONDARY_CRYPTO:
        {
            ivSize = iv.size();
            keySize = _secondary_crypto.master_key.size();

            assert(ivSize == JLSRTP_SALTING_KEY_LENGTH);
            assert(aesEcbCipher(keySize));
            if (ivSize == JLSRTP_SALTING_KEY_LENGTH)
            {
                if (aesEcbCipher(keySize))
                {
                    input.resize(AES_BLOCK_SIZE);
                    output.clear();

                    // Determine how many AES_BLOCK_SIZE-byte encryption loops will be necessary to achieve at least n/8 bytes of pseudorandom ciphertext
                    num_loops = (n % JLSRTP_PSEUDORANDOM_BITS) ? ((n / JLSRTP_PSEUDORANDOM_BITS) + 1) : (n / JLSRTP_PSEUDORANDOM_BITS);

                    // Set encryption key
                    rc = setAESPseudoRandomFunctionKey(_active_crypto);
                    if (rc == 0)
                    {
                        // Reset IV/counter state
                        resetPseudoRandomState(iv);

                        for (unsigned int i = 0; i < num_loops; i++)
                        {
                            // Encrypt given _pseudorandomstate.ivec input using aes_key to block
                            block.clear();
                            block.resize(AES_BLOCK_SIZE);
                            AES_ctr128_pseudorandom_EVPencrypt(input.data(), block.data(), AES_BLOCK_SIZE, _pseudorandomstate.ivec, _pseudorandomstate.ecount, &_pseudorandomstate.num);
                            output.insert(output.end(), block.begin(), block.end());
                        }

                        // Truncate output to n/8 bytes
                        output.resize(n / 8);

                        retVal = 0;
                    }
                    else
                    {
                        retVal = -3;
                    }
                }
                else
                {
                    retVal = -2;
                }
            }
            else
            {
                retVal = -1;
            }
        }
        break;

        default:
        {
            retVal = -4;
        }
        break;
    }

    return retVal;
}

int JLSRTP::shiftVectorLeft(std::vector<unsigned char> &shifted_vec, std::vector<unsigned char> &original_vec, int shift_value)
{
    shifted_vec.clear();
    shifted_vec.resize(original_vec.size());

    for (unsigned int i = shift_value, j = 0; i < original_vec.size(); i++, j++) {
        shifted_vec[j] = original_vec[i];
    }

    return 0;
}

int JLSRTP::shiftVectorRight(std::vector<unsigned char> &shifted_vec, std::vector<unsigned char> &original_vec, int shift_value)
{
    shifted_vec.clear();
    shifted_vec.resize(original_vec.size());

    for (unsigned int i = shift_value, j = 0; i < shifted_vec.size(); i++, j++) {
        shifted_vec[i] = original_vec[j];
    }

    return 0;
}

int JLSRTP::xorVector(std::vector<unsigned char> &a, std::vector<unsigned char> &b, std::vector<unsigned char> &result)
{
    int retVal = -1;

    if (a.size() == b.size())
    {
        result.clear();
        result.resize(a.size());
        std::transform(a.begin(), a.end(), b.begin(), result.begin(), std::bit_xor<unsigned char>());
        retVal = 0;
    }
    else
    {
        retVal = -1;
    }

    return retVal;
}

int JLSRTP::isBigEndian()
{
    Conversion32 bint = {0x01020304};

    return (bint.c[0] == 0x01);
}

int JLSRTP::isLittleEndian()
{
    Conversion32 bint = {0x01020304};

    return (bint.c[0] == 0x04);
}

int JLSRTP::convertSsrc(unsigned long ssrc, std::vector<unsigned char> &result)
{
    Conversion32 exchange_ssrc = {ssrc};

    result.clear();
    result.resize(16);

    if (isLittleEndian())
    {
        result[12] = exchange_ssrc.c[3];
        result[13] = exchange_ssrc.c[2];
        result[14] = exchange_ssrc.c[1];
        result[15] = exchange_ssrc.c[0];
    }
    else
    {
        result[12] = exchange_ssrc.c[0];
        result[13] = exchange_ssrc.c[1];
        result[14] = exchange_ssrc.c[2];
        result[15] = exchange_ssrc.c[3];
    }

    return 0;
}

int JLSRTP::convertPacketIndex(unsigned long long i, std::vector<unsigned char> &result)
{
    Conversion64 exchange_i = {i};

    result.clear();
    result.resize(16);

    if (isLittleEndian())
    {
        result[8]  = exchange_i.c[7];
        result[9]  = exchange_i.c[6];
        result[10] = exchange_i.c[5];
        result[11] = exchange_i.c[4];
        result[12] = exchange_i.c[3];
        result[13] = exchange_i.c[2];
        result[14] = exchange_i.c[1];
        result[15] = exchange_i.c[0];
    }
    else
    {
        result[8]  = exchange_i.c[0];
        result[9]  = exchange_i.c[1];
        result[10] = exchange_i.c[2];
        result[11] = exchange_i.c[3];
        result[12] = exchange_i.c[4];
        result[13] = exchange_i.c[5];
        result[14] = exchange_i.c[6];
        result[15] = exchange_i.c[7];
    }

    return 0;
}

int JLSRTP::convertROC(unsigned long ROC, std::vector<unsigned char> &result)
{
    Conversion32 exchange_roc = {ROC};

    result.clear();
    result.resize(4);

    if (isLittleEndian())
    {
        result[0] = exchange_roc.c[3];
        result[1] = exchange_roc.c[2];
        result[2] = exchange_roc.c[1];
        result[3] = exchange_roc.c[0];
    }
    else
    {
        result[0] = exchange_roc.c[0];
        result[1] = exchange_roc.c[1];
        result[2] = exchange_roc.c[2];
        result[3] = exchange_roc.c[3];
    }

    return 0;
}

unsigned long JLSRTP::determineV(unsigned short SEQ)
{
    unsigned long v = 0;

    /* Nothing to compare the first packet with: its SEQ becomes s_l
     * (RFC 3711 section 3.3.1). Comparing it with the initial 0 instead
     * took any first SEQ above 32768, as RFC 3550 senders pick at random,
     * for one from before a rollover, and ROC-1 wrapped. */
    if (!_s_l_set)
    {
        return _ROC;
    }

    if (_s_l < 32768)
    {
        if ((SEQ - _s_l) > 32768)
        {
            v = (_ROC > 0) ? _ROC-1 : 0;
        }
        else
        {
            v = _ROC;
        }
    }
    else
    {
        if ((SEQ - _s_l) < -32768)
        {
            v = _ROC+1;
        }
        else
        {
            v = _ROC;
        }
    }

    return v;
}

bool JLSRTP::updateRollOverCounter(unsigned long v)
{
    _ROC = v;

    return true;
}

unsigned long JLSRTP::fetchRollOverCounter()
{
    return _ROC;
}

bool JLSRTP::updateSL(unsigned short s)
{
    _s_l = s;
    _s_l_set = true;

    return true;
}

unsigned short JLSRTP::fetchSL()
{
    return _s_l;
}

unsigned long long JLSRTP::determinePacketIndex(unsigned long ROC, unsigned short SEQ)
{
    return ((JLSRTP_MAX_SEQUENCE_NUMBERS * ROC) + SEQ);
}

int JLSRTP::setPacketIV()
{
    unsigned int ivSize = 0;

    ivSize = _packetIV.size();
    assert(ivSize == JLSRTP_SALTING_KEY_LENGTH);
    if (ivSize == JLSRTP_SALTING_KEY_LENGTH)
    {
        // Copy 'IV' into high-order bytes [0..13] -- low-order bytes [14..15] remain zero
        memcpy(_cipherstate.ivec, _packetIV.data(), _packetIV.size());

        return 0;
    }
    else
    {
        return -1;
    }
}

int JLSRTP::computePacketIV(unsigned long long i)
{
    std::vector<unsigned char> padded_salt;
    std::vector<unsigned char> ssrc_vec;
    std::vector<unsigned char> i_vec;
    std::vector<unsigned char> shifted_ssrc;
    std::vector<unsigned char> shifted_i;
    std::vector<unsigned char> intermediate;
    unsigned long ssrc = _id.ssrc; // SSRC
    unsigned int saltSize = 0;

    _packetIV.clear();

    saltSize = _session_salt_key.size();
    assert(saltSize == JLSRTP_SALTING_KEY_LENGTH);
    if (saltSize == JLSRTP_SALTING_KEY_LENGTH)
    {
        padded_salt = _session_salt_key;
        padded_salt.push_back(0x00); // 1-byte PAD
        padded_salt.push_back(0x00); // 1-byte PAD

        convertSsrc(ssrc, ssrc_vec);
        convertPacketIndex(i, i_vec);

        shiftVectorLeft(shifted_ssrc, ssrc_vec, 8);
        shiftVectorLeft(shifted_i, i_vec, 2);

        xorVector(padded_salt, shifted_ssrc, intermediate);
        xorVector(intermediate, shifted_i, _packetIV);

        // Truncate output IV to 14 bytes
        _packetIV.resize(14);

        return 0;
    }
    else
    {
        return -1;
    }
}

void JLSRTP::displayPacketIV()
{
    printf("packet_iv                  : [");
    for (unsigned int i = 0; i < _packetIV.size(); i++)
    {
        printf("%02x", _packetIV[i]);
    }
    printf("]\n");
}

int JLSRTP::encryptVector(std::vector<unsigned char> &invdata, std::vector<unsigned char> &ciphertext_output)
{
    int retVal = 0;

    assert(!invdata.empty());
    if (!invdata.empty())
    {
        switch (_active_crypto)
        {
            case PRIMARY_CRYPTO:
            {
                switch (_primary_crypto.cipher_algorithm)
                {
                    case AES_CM_128:
                    case AES_CM_192:
                    case AES_CM_256:
                    {
                        ciphertext_output.resize(invdata.size());
                        resetCipherBlockOffset();
                        resetCipherOutputBlock();
                        resetCipherBlockCounter();
                        AES_ctr128_session_EVPencrypt(invdata.data(), ciphertext_output.data(), invdata.size(), _cipherstate.ivec, _cipherstate.ecount, &_cipherstate.num);
                        retVal = 0;
                    }
                    break;

                    case NULL_CIPHER:
                    {
                        ciphertext_output = invdata;
                        retVal = 0;
                    }
                    break;

                    default:
                    {
                        retVal = -3;
                    }
                    break;
                }
            }
            break;

            case SECONDARY_CRYPTO:
            {
                switch (_secondary_crypto.cipher_algorithm)
                {
                    case AES_CM_128:
                    case AES_CM_192:
                    case AES_CM_256:
                    {
                        ciphertext_output.resize(invdata.size());
                        resetCipherBlockOffset();
                        resetCipherOutputBlock();
                        resetCipherBlockCounter();
                        AES_ctr128_session_EVPencrypt(invdata.data(), ciphertext_output.data(), invdata.size(), _cipherstate.ivec, _cipherstate.ecount, &_cipherstate.num);
                        retVal = 0;
                    }
                    break;

                    case NULL_CIPHER:
                    {
                        ciphertext_output = invdata;
                        retVal = 0;
                    }
                    break;

                    default:
                    {
                        retVal = -3;
                    }
                    break;
                }
            }
            break;

            default:
            {
                retVal = -4;
            }
            break;
        }
    }
    else
    {
        retVal = -1;
    }

    return retVal;
}

int JLSRTP::decryptVector(std::vector<unsigned char> &ciphertext_input, std::vector<unsigned char> &outvdata)
{
    int retVal = 0;

    assert(!ciphertext_input.empty());
    if (!ciphertext_input.empty())
    {
        switch (_active_crypto)
        {
            case PRIMARY_CRYPTO:
            {
                switch (_primary_crypto.cipher_algorithm)
                {
                    case AES_CM_128:
                    case AES_CM_192:
                    case AES_CM_256:
                    {
                        outvdata.resize(ciphertext_input.size());
                        resetCipherBlockOffset();
                        resetCipherOutputBlock();
                        resetCipherBlockCounter();
                        AES_ctr128_session_EVPencrypt(ciphertext_input.data(), outvdata.data(), ciphertext_input.size(), _cipherstate.ivec, _cipherstate.ecount, &_cipherstate.num);
                        retVal = 0;
                    }
                    break;

                    case NULL_CIPHER:
                    {
                        outvdata = ciphertext_input;
                        retVal = 0;
                    }
                    break;

                    default:
                    {
                        retVal = -3;
                    }
                    break;
                }
            }
            break;

            case SECONDARY_CRYPTO:
            {
                switch (_secondary_crypto.cipher_algorithm)
                {
                    case AES_CM_128:
                    case AES_CM_192:
                    case AES_CM_256:
                    {
                        outvdata.resize(ciphertext_input.size());
                        resetCipherBlockOffset();
                        resetCipherOutputBlock();
                        resetCipherBlockCounter();
                        AES_ctr128_session_EVPencrypt(ciphertext_input.data(), outvdata.data(), ciphertext_input.size(), _cipherstate.ivec, _cipherstate.ecount, &_cipherstate.num);
                        retVal = 0;
                    }
                    break;

                    case NULL_CIPHER:
                    {
                        outvdata = ciphertext_input;
                        retVal = 0;
                    }
                    break;

                    default:
                    {
                        retVal = -3;
                    }
                    break;
                }
            }
            break;

            default:
            {
                retVal = -4;
            }
            break;
        }
    }
    else
    {
        retVal = -1;
    }

    return retVal;
}

int JLSRTP::issueAuthenticationTag(std::vector<unsigned char> &data, std::vector<unsigned char> &hash)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    int retVal = -1;
    std::vector<unsigned char> auth_portion;
    std::vector<unsigned char> rocVec;
    int rc = -1;

    assert(!_session_auth_key.empty());
    if (!_session_auth_key.empty())
    {
        rc = convertROC(_ROC, rocVec);
        if (rc == 0)
        {
            auth_portion.clear();
            auth_portion.insert(auth_portion.end(), data.begin(), data.end());
            auth_portion.insert(auth_portion.end(), rocVec.begin(), rocVec.end());

            hash.clear();
            // wolfSSL's HMAC() has no static output buffer: pass our own
            if (HMAC(EVP_sha1(), _session_auth_key.data(), _session_auth_key.size(), /*data.data()*/ auth_portion.data(), /*data.size()*/ auth_portion.size(), digest, &digest_len) != nullptr &&
                digest_len == JLSRTP_SHA1_HASH_LENGTH)
            {
                hash.assign(digest, digest+JLSRTP_SHA1_HASH_LENGTH);

                switch (_active_crypto)
                {
                    case PRIMARY_CRYPTO:
                    {
                        switch (_primary_crypto.hmac_algorithm)
                        {
                            case HMAC_SHA1_80:
                                hash.resize(JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_80); // Truncate to 10 bytes (80 bits / 8 bits/byte = 10 bytes)
                                retVal = 0;
                            break;

                            case HMAC_SHA1_32:
                                hash.resize(JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_32);  // Truncate to  4 bytes (32 bits / 8 bits/byte = 4 bytes)
                                retVal = 0;
                            break;

                            default:
                                // Unrecognized input value -- NO-OP...
                                retVal = -3;
                            break;
                        }
                    }
                    break;

                    case SECONDARY_CRYPTO:
                    {
                        switch (_secondary_crypto.hmac_algorithm)
                        {
                            case HMAC_SHA1_80:
                                hash.resize(JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_80); // Truncate to 10 bytes (80 bits / 8 bits/byte = 10 bytes)
                                retVal = 0;
                            break;

                            case HMAC_SHA1_32:
                                hash.resize(JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_32);  // Truncate to  4 bytes (32 bits / 8 bits/byte = 4 bytes)
                                retVal = 0;
                            break;

                            default:
                                // Unrecognized input value -- NO-OP...
                                retVal = -3;
                            break;
                        }
                    }
                    break;

                    default:
                    {
                        retVal = -5;
                    }
                    break;
                }
            }
            else
            {
                retVal = -2;
            }
        }
        else
        {
            retVal = -4;
        }
    }
    else
    {
        retVal = -1;
    }

    return retVal;
}

int JLSRTP::extractAuthenticationTag(std::vector<unsigned char> srtp_packet, std::vector<unsigned char> &hash)
{
    int retVal = -1;
    std::vector<unsigned char>::iterator it = srtp_packet.begin();
    int authtag_pos = 0;

    assert(!_session_auth_key.empty());
    if (!_session_auth_key.empty())
    {
        switch (_active_crypto)
        {
            case PRIMARY_CRYPTO:
            {
                switch (_primary_crypto.hmac_algorithm)
                {
                    case HMAC_SHA1_80:
                        if (srtp_packet.size() >= JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_80)
                        {
                            authtag_pos = srtp_packet.size() - 10;
                            std::advance(it, authtag_pos);
                            hash.assign(it, srtp_packet.end()); // Fetch trailing 10 bytes (80 bits / 8 bits/byte = 10 bytes)
                            retVal = 0;
                        }
                        else
                        {
                            retVal = -2;
                        }
                    break;

                    case HMAC_SHA1_32:
                        if (srtp_packet.size() >= JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_32)
                        {
                            authtag_pos = srtp_packet.size() - 4;
                            std::advance(it, authtag_pos);
                            hash.assign(it, srtp_packet.end());  // Fetch trailing  4 bytes (32 bits / 8 bits/byte = 4 bytes)
                            retVal = 0;
                        }
                        else
                        {
                            retVal = -2;
                        }
                    break;

                    default:
                        // Unrecognized input value -- NO-OP...
                        retVal = -3;
                    break;
                }
            }
            break;

            case SECONDARY_CRYPTO:
            {
                switch (_secondary_crypto.hmac_algorithm)
                {
                    case HMAC_SHA1_80:
                        if (srtp_packet.size() >= JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_80)
                        {
                            authtag_pos = srtp_packet.size() - 10;
                            std::advance(it, authtag_pos);
                            hash.assign(it, srtp_packet.end()); // Fetch trailing 10 bytes (80 bits / 8 bits/byte = 10 bytes)
                            retVal = 0;
                        }
                        else
                        {
                            retVal = -2;
                        }
                    break;

                    case HMAC_SHA1_32:
                        if (srtp_packet.size() >= JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_32)
                        {
                            authtag_pos = srtp_packet.size() - 4;
                            std::advance(it, authtag_pos);
                            hash.assign(it, srtp_packet.end());  // Fetch trailing  4 bytes (32 bits / 8 bits/byte = 4 bytes)
                            retVal = 0;
                        }
                        else
                        {
                            retVal = -2;
                        }
                    break;

                    default:
                        // Unrecognized input value -- NO-OP...
                        retVal = -3;
                    break;
                }
            }
            break;

            default:
            {
                retVal = -4;
            }
            break;
        }
    }
    else
    {
        retVal = -1;
    }

    return retVal;
}

int JLSRTP::extractSRTPHeader(std::vector<unsigned char> srtp_packet, std::vector<unsigned char> &header)
{
    int retVal = -1;
    std::vector<unsigned char>::iterator it = srtp_packet.begin();

    if (_srtp_header_size > 0)
    {
        if (srtp_packet.size() >= _srtp_header_size)
        {
            header.clear();
            std::advance(it, _srtp_header_size);
            header.assign(srtp_packet.begin(), it); // Fetch leading 12 bytes
            retVal = 0;
        }
        else
        {
            retVal = -2;
        }
    }
    else
    {
        retVal = -1;
    }

    return retVal;
}

int JLSRTP::extractSRTPPayload(std::vector<unsigned char> srtp_packet, std::vector<unsigned char> &payload)
{
    int retVal = -1;
    std::vector<unsigned char>::iterator it_payload_begin = srtp_packet.begin();
    std::vector<unsigned char>::iterator it_payload_end = srtp_packet.begin();
    unsigned int header_payload_size = 0;

    header_payload_size = _srtp_header_size + _srtp_payload_size;

    if (_srtp_header_size > 0)
    {
        if (_srtp_payload_size > 0)
        {
            if (srtp_packet.size() >= header_payload_size)
            {
                payload.clear();
                std::advance(it_payload_begin, _srtp_header_size);
                std::advance(it_payload_end, header_payload_size);
                payload.assign(it_payload_begin, it_payload_end); // Fetch payload bytes
                retVal = 0;
            }
            else
            {
                retVal = -3;
            }
        }
        else
        {
            retVal = -2;
        }
    }
    else
    {
        retVal = -1;
    }

    return retVal;
}

std::string JLSRTP::base64Encode(std::vector<unsigned char> const& s)
{
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    unsigned char const* bytes_to_encode = &s.front();
    unsigned int in_len = s.size();
    std::string ret;
    // Reserve enough space in 'ret' to avoid multiple allocations.
    // In Base64, every 3 bytes of binary data become 4 bytes of ASCII text.
    // Round up for potential padding.
    ret.reserve(((in_len + 2) / 3) * 4);

    while (in_len--)
    {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
            {
                ret += base64Chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i)
    {
        for(j = i; j < 3; j++)
        {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
        {
            ret += base64Chars[char_array_4[j]];
        }

        while((i++ < 3))
        {
            ret += '=';
        }
    }

    return ret;
}

std::vector<unsigned char> JLSRTP::base64Decode(std::string const& encoded_string)
{
    int i = 0;
    int j = 0;
    unsigned char char_array_4[4];
    unsigned char char_array_3[3];
    int in_ = 0;
    unsigned int in_len = encoded_string.size();
    std::vector<unsigned char> ret;
    // Reserve enough space in 'ret' to avoid multiple allocations.
    // In Base64, every 4 bytes of ASCII text become 3 bytes of binary data.
    ret.reserve(in_len * 3 / 4);

    while (in_len-- && ( encoded_string[in_] != '=') && isBase64(encoded_string[in_]))
    {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i ==4)
        {
            for (i = 0; i <4; i++)
            {
                char_array_4[i] = base64Chars.find(char_array_4[i]);
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
            {
                ret.push_back(char_array_3[i]);
            }
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j <4; j++)
        {
            char_array_4[j] = 0;
        }

        for (j = 0; j <4; j++)
        {
            char_array_4[j] = base64Chars.find(char_array_4[j]);
        }

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++)
        {
            ret.push_back(char_array_3[j]);
        }
    }

    return ret;
}

int JLSRTP::resetCipherBlockOffset()
{
    _cipherstate.num = 0;

    return 0;
}

int JLSRTP::resetCipherOutputBlock()
{
    memset(_cipherstate.ecount, 0, sizeof(_cipherstate.ecount));

    return 0;
}

int JLSRTP::resetCipherBlockCounter()
{
    // Clear low-order bytes [14..15] for 'counter'
    memset(_cipherstate.ivec+14, 0, 2);

    return 0;
}

int JLSRTP::setAESPseudoRandomFunctionKey(ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    ActiveCrypto active_crypto = INVALID_CRYPTO;
    int rc = 0;
    int retVal = 0;

    if (aesContext(_pseudorandomstate.cipher))
    {
        if (crypto_attrib == ACTIVE_CRYPTO)
        {
            active_crypto = _active_crypto;
        }
        else
        {
            active_crypto = crypto_attrib;
        }

        switch (active_crypto)
        {
            case PRIMARY_CRYPTO:
            {
                rc = setAESKey(_pseudorandomstate.cipher, _primary_crypto.master_key);
                if (rc == 1)
                {
                    retVal = 0;
                }
                else
                {
                    retVal = -2;
                }
            }
            break;

            case SECONDARY_CRYPTO:
            {
                rc = setAESKey(_pseudorandomstate.cipher, _secondary_crypto.master_key);
                if (rc == 1)
                {
                    retVal = 0;
                }
                else
                {
                    retVal = -3;
                }
            }
            break;

            default:
            {
                retVal = -4;
            }
            break;
        }
    }
    else
    {
        retVal = -1;
    }

    return retVal;
}

int JLSRTP::setAESSessionEncryptionKey()
{
    int rc = 0;
    int retVal = 0;

    if (aesContext(_cipherstate.cipher))
    {
        rc = setAESKey(_cipherstate.cipher, _session_enc_key);
        if (rc == 1)
        {
            retVal = 0;
        }
        else
        {
            retVal = -2;
        }
    }
    else
    {
        retVal = -1;
    }

    return retVal;
}

void JLSRTP::AES_ctr128_increment(unsigned char* counter)
{
    unsigned char* cur_pos = nullptr;

    for (cur_pos = counter + 15; cur_pos >= counter; cur_pos--)
    {
        (*cur_pos)++;
        if (*cur_pos != 0)
        {
            break;
        }
    }
}

int JLSRTP::AES_ctr128_pseudorandom_EVPencrypt(const unsigned char* in,
                                               unsigned char* out,
                                               const unsigned long length,
                                               unsigned char counter[AES_BLOCK_SIZE],
                                               unsigned char ecount_buf[AES_BLOCK_SIZE],
                                               unsigned int* num)
{
    int nb;
    unsigned int n;
    unsigned long l=length;
    int rc = 0;
    int retVal = 0;

    switch (_active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            n = *num;

            while (l--)
            {
                if (n == 0)
                {
                    // IMPORTANT:  Key MUST be set every single time EVP_EncryptUpdate() is to be called...
                    rc = setAESKey(_pseudorandomstate.cipher, _primary_crypto.master_key);
                    if (rc == 1)
                    {
                        rc = EVP_EncryptUpdate(_pseudorandomstate.cipher, ecount_buf, &nb, counter, AES_BLOCK_SIZE);
                        if (rc == 1)
                        {
                            retVal = 0;
                            AES_ctr128_increment(counter);
                        }
                        else
                        {
                            retVal = -2;
                            break;
                        }
                    }
                    else
                    {
                        retVal = -1;
                        break;
                    }
                }
                *(out++) = *(in++) ^ ecount_buf[n];
                n = (n+1) % AES_BLOCK_SIZE;
            }

            *num=n;
        }
        break;

        case SECONDARY_CRYPTO:
        {
            n = *num;

            while (l--)
            {
                if (n == 0)
                {
                    // IMPORTANT:  Key MUST be set every single time EVP_EncryptUpdate() is to be called...
                    rc = setAESKey(_pseudorandomstate.cipher, _secondary_crypto.master_key);
                    if (rc == 1)
                    {
                        rc = EVP_EncryptUpdate(_pseudorandomstate.cipher, ecount_buf, &nb, counter, AES_BLOCK_SIZE);
                        if (rc == 1)
                        {
                            retVal = 0;
                            AES_ctr128_increment(counter);
                        }
                        else
                        {
                            retVal = -2;
                            break;
                        }
                    }
                    else
                    {
                        retVal = -1;
                        break;
                    }
                }
                *(out++) = *(in++) ^ ecount_buf[n];
                n = (n+1) % AES_BLOCK_SIZE;
            }

            *num=n;
        }
        break;

        default:
        {
            retVal = -3;
        }
        break;
    }

    return retVal;
}

int JLSRTP::AES_ctr128_session_EVPencrypt(const unsigned char* in,
                                          unsigned char* out,
                                          const unsigned long length,
                                          unsigned char counter[AES_BLOCK_SIZE],
                                          unsigned char ecount_buf[AES_BLOCK_SIZE],
                                          unsigned int* num)
{
    int nb;
    unsigned int n;
    unsigned long l=length;
    int rc = 0;
    int retVal = 0;

    n = *num;

    while (l--)
    {
        if (n == 0)
        {
            // IMPORTANT:  Key MUST be set every single time EVP_EncryptUpdate() is to be called...
            rc = setAESKey(_cipherstate.cipher, _session_enc_key);
            if (rc == 1)
            {
                rc = EVP_EncryptUpdate(_cipherstate.cipher, ecount_buf, &nb, counter, AES_BLOCK_SIZE);
                if (rc == 1)
                {
                    retVal = 0;
                    AES_ctr128_increment(counter);
                }
                else
                {
                    retVal = -2;
                    break;
                }
            }
            else
            {
                retVal = -1;
                break;
            }
        }
        *(out++) = *(in++) ^ ecount_buf[n];
        n = (n+1) % AES_BLOCK_SIZE;
    }

    *num=n;

    return retVal;
}


// --------------- PUBLIC METHODS ----------------

void JLSRTP::resetCryptoContext(unsigned int ssrc, std::string ipAddress, unsigned short port)
{
    _id.ssrc = ssrc;
    _id.address = ipAddress;
    _id.port = port;
    _ROC = 0;
    _s_l = 0;
    _s_l_set = false;
    _primary_crypto.cipher_algorithm = AES_CM_128;
    _primary_crypto.hmac_algorithm = HMAC_SHA1_80;
    _primary_crypto.MKI = 0;
    _primary_crypto.MKI_length = 0;
    _primary_crypto.active_MKI = 0;
    _primary_crypto.master_key.resize(JLSRTP_ENCRYPTION_KEY_LENGTH);
    _primary_crypto.master_key_counter = 0;
    _primary_crypto.n_e = _primary_crypto.master_key.size();
    _primary_crypto.n_a = JLSRTP_AUTHENTICATION_KEY_LENGTH;
    _primary_crypto.master_salt.resize(JLSRTP_SALTING_KEY_LENGTH);
    _primary_crypto.master_key_derivation_rate = 0;
    _primary_crypto.master_mki_value = 0;
    _primary_crypto.n_s = _primary_crypto.master_salt.size();
    _primary_crypto.tag = 0;
    _secondary_crypto.cipher_algorithm = AES_CM_128;
    _secondary_crypto.hmac_algorithm = HMAC_SHA1_80;
    _secondary_crypto.MKI = 0;
    _secondary_crypto.MKI_length = 0;
    _secondary_crypto.active_MKI = 0;
    _secondary_crypto.master_key.resize(JLSRTP_ENCRYPTION_KEY_LENGTH);
    _secondary_crypto.master_key_counter = 0;
    _secondary_crypto.n_e = _secondary_crypto.master_key.size();
    _secondary_crypto.n_a = JLSRTP_AUTHENTICATION_KEY_LENGTH;
    _secondary_crypto.master_salt.resize(JLSRTP_SALTING_KEY_LENGTH);
    _secondary_crypto.master_key_derivation_rate = 0;
    _secondary_crypto.master_mki_value = 0;
    _secondary_crypto.n_s = _secondary_crypto.master_salt.size();
    _secondary_crypto.tag = 0;
    _session_enc_key.resize(JLSRTP_ENCRYPTION_KEY_LENGTH);
    _session_salt_key.resize(JLSRTP_SALTING_KEY_LENGTH);
    _session_auth_key.resize(JLSRTP_AUTHENTICATION_KEY_LENGTH);
    _packetIV.resize(JLSRTP_SALTING_KEY_LENGTH);
    memset(_pseudorandomstate.ivec, 0, sizeof(_pseudorandomstate.ivec));
    _pseudorandomstate.num = 0;
    memset(_pseudorandomstate.ecount, 0, sizeof(_pseudorandomstate.ecount));
    memset(_cipherstate.ivec, 0, sizeof(_cipherstate.ivec));
    _cipherstate.num = 0;
    memset(_cipherstate.ecount, 0, sizeof(_cipherstate.ecount));
    _srtp_header_size = JLSRTP_SRTP_DEFAULT_HEADER_SIZE;
    _srtp_payload_size = 0;
    _active_crypto = PRIMARY_CRYPTO;
}

int JLSRTP::resetCipherState()
{
    unsigned int ivSize = 0;

    ivSize = _packetIV.size();
    assert(ivSize == JLSRTP_SALTING_KEY_LENGTH);
    if (ivSize == JLSRTP_SALTING_KEY_LENGTH)
    {
        // aes_ctr128_encrypt() requires 'num' and 'ecount' to be set to zero on the first call
        resetCipherBlockOffset();
        resetCipherOutputBlock();

        // Clear BOTH high-order bytes [0..13] for 'IV' AND low-order bytes [14..15] for 'counter'
        memset(_cipherstate.ivec, 0, AES_BLOCK_SIZE);
        // Copy 'IV' into high-order bytes [0..13] -- low-order bytes [14..15] remain zero
        memcpy(_cipherstate.ivec, _packetIV.data(), _packetIV.size());

        return 0;
    }
    else
    {
        return -1;
    }
}

int JLSRTP::deriveSessionEncryptionKey()
{
    std::vector<unsigned char> input_vector;        // Input vector (built from applicable keyid_XXXs)
    std::vector<unsigned char> keyid_encryption;
    unsigned int saltSize = 0;
    int retVal = -1;

    switch (_active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            saltSize = _primary_crypto.master_salt.size();
            assert(saltSize == JLSRTP_SALTING_KEY_LENGTH);
            if (saltSize == JLSRTP_SALTING_KEY_LENGTH)
            {
                input_vector.clear();

                keyid_encryption.clear();
                keyid_encryption.resize(7);
                keyid_encryption.push_back(JLSRTP_KEY_ENCRYPTION_LABEL);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);

                xorVector(keyid_encryption, _primary_crypto.master_salt, input_vector);

                // As long as the master key (RFC 6188 section 3)
                retVal = pseudorandomFunction(input_vector, 8 * _primary_crypto.master_key.size(), _session_enc_key);
            }
            else
            {
                retVal = -1;
            }
        }
        break;

        case SECONDARY_CRYPTO:
        {
            saltSize = _secondary_crypto.master_salt.size();
            assert(saltSize == JLSRTP_SALTING_KEY_LENGTH);
            if (saltSize == JLSRTP_SALTING_KEY_LENGTH)
            {
                input_vector.clear();

                keyid_encryption.clear();
                keyid_encryption.resize(7);
                keyid_encryption.push_back(JLSRTP_KEY_ENCRYPTION_LABEL);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);

                xorVector(keyid_encryption, _secondary_crypto.master_salt, input_vector);

                // As long as the master key (RFC 6188 section 3)
                retVal = pseudorandomFunction(input_vector, 8 * _secondary_crypto.master_key.size(), _session_enc_key);
            }
            else
            {
                retVal = -1;
            }
        }
        break;

        default:
        {
            retVal = -4;
        }
        break;
    }

    return retVal;
}

int JLSRTP::deriveSessionSaltingKey()
{
    std::vector<unsigned char> input_vector;        // Input vector (built from applicable keyid_XXXs)
    std::vector<unsigned char> keyid_salting;
    unsigned int saltSize = 0;
    int retVal = -1;

    switch (_active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            saltSize = _primary_crypto.master_salt.size();
            assert(saltSize == JLSRTP_SALTING_KEY_LENGTH);
            if (saltSize == JLSRTP_SALTING_KEY_LENGTH)
            {
                input_vector.clear();

                keyid_salting.clear();
                keyid_salting.resize(7);
                keyid_salting.push_back(JLSRTP_KEY_SALTING_LABEL);
                keyid_salting.push_back(0x00);
                keyid_salting.push_back(0x00);
                keyid_salting.push_back(0x00);
                keyid_salting.push_back(0x00);
                keyid_salting.push_back(0x00);
                keyid_salting.push_back(0x00);

               xorVector(keyid_salting, _primary_crypto.master_salt, input_vector);

                retVal = pseudorandomFunction(input_vector, 112, _session_salt_key);
            }
            else
            {
                retVal = -1;
            }
        }
        break;

        case SECONDARY_CRYPTO:
        {
            saltSize = _secondary_crypto.master_salt.size();
            assert(saltSize == JLSRTP_SALTING_KEY_LENGTH);
            if (saltSize == JLSRTP_SALTING_KEY_LENGTH)
            {
                input_vector.clear();

                keyid_salting.clear();
                keyid_salting.resize(7);
                keyid_salting.push_back(JLSRTP_KEY_SALTING_LABEL);
                keyid_salting.push_back(0x00);
                keyid_salting.push_back(0x00);
                keyid_salting.push_back(0x00);
                keyid_salting.push_back(0x00);
                keyid_salting.push_back(0x00);
                keyid_salting.push_back(0x00);

               xorVector(keyid_salting, _secondary_crypto.master_salt, input_vector);

                retVal = pseudorandomFunction(input_vector, 112, _session_salt_key);
            }
            else
            {
                retVal = -1;
            }
        }
        break;

        default:
        {
            retVal = -4;
        }
        break;
    }

    return retVal;
}

int JLSRTP::deriveSessionAuthenticationKey()
{
    std::vector<unsigned char> input_vector;        // Input vector (built from applicable keyid_XXXs)
    std::vector<unsigned char> keyid_authentication;
    unsigned int saltSize = 0;
    int retVal = -1;

    switch (_active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            saltSize = _primary_crypto.master_salt.size();
            assert(saltSize == JLSRTP_SALTING_KEY_LENGTH);
            if (saltSize == JLSRTP_SALTING_KEY_LENGTH)
            {
                input_vector.clear();

                keyid_authentication.clear();
                keyid_authentication.resize(7);
                keyid_authentication.push_back(JLSRTP_KEY_AUTHENTICATION_LABEL);
                keyid_authentication.push_back(0x00);
                keyid_authentication.push_back(0x00);
                keyid_authentication.push_back(0x00);
                keyid_authentication.push_back(0x00);
                keyid_authentication.push_back(0x00);
                keyid_authentication.push_back(0x00);

                xorVector(keyid_authentication, _primary_crypto.master_salt, input_vector);

                retVal = pseudorandomFunction(input_vector, 160, _session_auth_key);
            }
            else
            {
                retVal = -1;
            }
        }
        break;

        case SECONDARY_CRYPTO:
        {
            saltSize = _secondary_crypto.master_salt.size();
            assert(saltSize == JLSRTP_SALTING_KEY_LENGTH);
            if (saltSize == JLSRTP_SALTING_KEY_LENGTH)
            {
                input_vector.clear();

                keyid_authentication.clear();
                keyid_authentication.resize(7);
                keyid_authentication.push_back(JLSRTP_KEY_AUTHENTICATION_LABEL);
                keyid_authentication.push_back(0x00);
                keyid_authentication.push_back(0x00);
                keyid_authentication.push_back(0x00);
                keyid_authentication.push_back(0x00);
                keyid_authentication.push_back(0x00);
                keyid_authentication.push_back(0x00);

                xorVector(keyid_authentication, _secondary_crypto.master_salt, input_vector);

                retVal = pseudorandomFunction(input_vector, 160, _session_auth_key);
            }
            else
            {
                retVal = -1;
            }
        }
        break;

        default:
        {
            retVal = -4;
        }
        break;
    }

    return retVal;
}

void JLSRTP::displaySessionEncryptionKey()
{
    //printf("session_encryption_key[] size: %d\n", _session_enc_key.size());

    printf("_session_enc_key           : [");
    for (unsigned int i = 0; i < _session_enc_key.size(); i++)
    {
        printf("%02x", _session_enc_key[i]);
    }
    printf("]\n");
}

void JLSRTP::displaySessionSaltingKey()
{
    //printf("session_salting_key[] size: %d\n", _session_salt_key.size());

    printf("_session_salt_key          : [");
    for (unsigned int i = 0; i < _session_salt_key.size(); i++)
    {
        printf("%02x", _session_salt_key[i]);
    }
    printf("]\n");
}

void JLSRTP::displaySessionAuthenticationKey()
{
    //printf("session_authentication_key[] size: %d\n", _session_auth_key.size());

    printf("_session_auth_key          : [");
    for (unsigned int i = 0; i < _session_auth_key.size(); i++)
    {
        printf("%02x", _session_auth_key[i]);
    }
    printf("]\n");
}

int JLSRTP::selectEncryptionKey()
{
    int rc = 0;

    assert(!_session_enc_key.empty());
    if (!_session_enc_key.empty())
    {
        rc = setAESSessionEncryptionKey();
        if (rc == 0)
        {
            return 0;
        }

        return  -2;
    }
    else
    {
        return -1;
    }
}

int JLSRTP::selectDecryptionKey()
{
    int rc = 0;

    assert(!_session_enc_key.empty());
    if (!_session_enc_key.empty())
    {
        rc = setAESSessionEncryptionKey();
        if (rc == 0)
        {
            return 0;
        }

        return -2;
    }
    else
    {
        return -1;
    }
}

CipherType JLSRTP::getCipherAlgorithm(ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    CipherType retVal = INVALID_CIPHER;
    ActiveCrypto active_crypto = INVALID_CRYPTO;

    if (crypto_attrib == ACTIVE_CRYPTO)
    {
        active_crypto = _active_crypto;
    }
    else
    {
        active_crypto = crypto_attrib;
    }

    switch (active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            retVal = _primary_crypto.cipher_algorithm;
        }
        break;

        case SECONDARY_CRYPTO:
        {
            retVal = _secondary_crypto.cipher_algorithm;
        }
        break;

        default:
        {
            retVal = INVALID_CIPHER;
        }
        break;
    }

    return retVal;
}

int JLSRTP::selectCipherAlgorithm(CipherType cipherType, ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    int retVal = -1;
    ActiveCrypto active_crypto = INVALID_CRYPTO;

    if (crypto_attrib == ACTIVE_CRYPTO)
    {
        active_crypto = _active_crypto;
    }
    else
    {
        active_crypto = crypto_attrib;
    }

    switch (active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            switch (cipherType)
            {
                case AES_CM_128:
                {
                    _primary_crypto.cipher_algorithm = AES_CM_128;
                    retVal = 0;
                }
                break;

                case NULL_CIPHER:
                {
                    _primary_crypto.cipher_algorithm = NULL_CIPHER;
                    retVal = 0;
                }
                break;

                case AES_CM_192:
                case AES_CM_256:
                {
                    if (aesEcbCipher(masterKeyLength(cipherType)))
                    {
                        _primary_crypto.cipher_algorithm = cipherType;
                        retVal = 0;
                    }
                    else
                    {
                        retVal = -1;
                    }
                }
                break;

                default:
                {
                    retVal = -1;
                }
                break;
            }
        }
        break;

        case SECONDARY_CRYPTO:
        {
            switch (cipherType)
            {
                case AES_CM_128:
                {
                    _secondary_crypto.cipher_algorithm = AES_CM_128;
                    retVal = 0;
                }
                break;

                case NULL_CIPHER:
                {
                    _secondary_crypto.cipher_algorithm = NULL_CIPHER;
                    retVal = 0;
                }
                break;

                case AES_CM_192:
                case AES_CM_256:
                {
                    if (aesEcbCipher(masterKeyLength(cipherType)))
                    {
                        _secondary_crypto.cipher_algorithm = cipherType;
                        retVal = 0;
                    }
                    else
                    {
                        retVal = -1;
                    }
                }
                break;

                default:
                {
                    retVal = -1;
                }
                break;
            }
        }
        break;

        default:
        {
            retVal = -2;
        }
        break;
    }

    return retVal;
}

HashType JLSRTP::getHashAlgorithm(ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    HashType retVal = INVALID_HASH;
    ActiveCrypto active_crypto = INVALID_CRYPTO;

    if (crypto_attrib == ACTIVE_CRYPTO)
    {
        active_crypto = _active_crypto;
    }
    else
    {
        active_crypto = crypto_attrib;
    }

    switch (active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            retVal = _primary_crypto.hmac_algorithm;
        }
        break;

        case SECONDARY_CRYPTO:
        {
            retVal = _secondary_crypto.hmac_algorithm;
        }
        break;

        default:
        {
            retVal = INVALID_HASH;
        }
        break;
    }

    return retVal;
}

int JLSRTP::selectHashAlgorithm(HashType hashType, ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    int retVal = -1;
    ActiveCrypto active_crypto = INVALID_CRYPTO;

    if (crypto_attrib == ACTIVE_CRYPTO)
    {
        active_crypto = _active_crypto;
    }
    else
    {
        active_crypto = crypto_attrib;
    }

    switch (active_crypto)
    {

        case PRIMARY_CRYPTO:
        {
            switch (hashType)
            {
                case HMAC_SHA1_80:
                {
                    _primary_crypto.hmac_algorithm = HMAC_SHA1_80;
                    retVal = 0;
                }
                break;

                case HMAC_SHA1_32:
                {
                    _primary_crypto.hmac_algorithm = HMAC_SHA1_32;
                    retVal = 0;
                }
                break;

                default:
                {
                    retVal = -1;
                }
                break;
            }
        }
        break;

        case SECONDARY_CRYPTO:
        {
            switch (hashType)
            {
                case HMAC_SHA1_80:
                {
                    _secondary_crypto.hmac_algorithm = HMAC_SHA1_80;
                    retVal = 0;
                }
                break;

                case HMAC_SHA1_32:
                {
                    _secondary_crypto.hmac_algorithm = HMAC_SHA1_32;
                    retVal = 0;
                }
                break;

                default:
                {
                    retVal = -1;
                }
                break;
            }
        }
        break;

        default:
        {
            retVal = -2;
        }
        break;
    }

    return retVal;
}

int JLSRTP::getAuthenticationTagSize()
{
    int retVal = -1;

    assert(!_session_auth_key.empty());
    if (!_session_auth_key.empty())
    {
        switch (_active_crypto)
        {
            case PRIMARY_CRYPTO:
            {
                switch (_primary_crypto.hmac_algorithm)
                {
                    case HMAC_SHA1_80:
                        retVal = JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_80;
                    break;

                    case HMAC_SHA1_32:
                        retVal = JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_32;
                    break;

                    default:
                        // Unrecognized input value -- NO-OP...
                        retVal = -2;
                    break;
                }
            }
            break;

            case SECONDARY_CRYPTO:
            {
                switch (_secondary_crypto.hmac_algorithm)
                {
                    case HMAC_SHA1_80:
                        retVal = JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_80;
                    break;

                    case HMAC_SHA1_32:
                        retVal = JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_32;
                    break;

                    default:
                        // Unrecognized input value -- NO-OP...
                        retVal = -2;
                    break;
                }
            }
            break;

            default:
            {
                retVal = -3;
            }
            break;
        }
    }
    else
    {
        retVal = -1;
    }

    return retVal;
}

void JLSRTP::displayAuthenticationTag(std::vector<unsigned char> &authtag)
{
    printf("authentication tag         : [");
    for (unsigned int i = 0; i < authtag.size(); i++)
    {
        printf("%02x", authtag[i]);
    }
    printf("]\n");
}

unsigned int JLSRTP::getSSRC()
{
    return _id.ssrc;
}

std::string JLSRTP::getIPAddress()
{
    return _id.address;
}

unsigned short JLSRTP::getPort()
{
    return _id.port;
}

void JLSRTP::setSSRC(unsigned int ssrc)
{
    _id.ssrc = ssrc;
}

void JLSRTP::setIPAddress(std::string ipAddress)
{
    _id.address = ipAddress;
}

void JLSRTP::setPort(unsigned short port)
{
    _id.port = port;
}

void JLSRTP::setID(CryptoContextID id)
{
    _id.ssrc = id.ssrc;
    _id.address = id.address;
    _id.port = id.port;
}

unsigned int JLSRTP::getSrtpHeaderSize()
{
    return _srtp_header_size;
}

void JLSRTP::setSrtpHeaderSize(unsigned int size)
{
    _srtp_header_size = size;
}

unsigned int JLSRTP::getSrtpPayloadSize()
{
    return _srtp_payload_size;
}

void JLSRTP::setSrtpPayloadSize(unsigned int size)
{
    _srtp_payload_size = size;
}

int JLSRTP::processOutgoingPacket(unsigned short SEQ_s,
                                  std::vector<unsigned char> &rtp_header,
                                  std::vector<unsigned char> &rtp_payload,
                                  std::vector<unsigned char> &srtp_packet)
{
    int rc = 0;
    bool check = false;
    unsigned long v_s = 0;
    unsigned long long i_s = 0LL; /* TEST PACKET INDEX */
    std::vector<unsigned char> srtp_payload; /* ENCRYPTED PAYLOAD */
    std::vector<unsigned char> auth_tag;
    std::vector<unsigned char> auth_portion;
    int retVal = -1;

    // 1.  Determine crypto context to use
    // NO-OP (IMPLICIT)

    // 2.  Determine packet index (i) using RoC + _s_l + SEQ (section 3.3.1)
    //std::cout << "[processOutgoingPacket] SEQ_s: " << SEQ_s << " current ROC_s: " << _ROC << " current s_l_s: " << _s_l << " ";
    v_s = determineV(SEQ_s);
    //std::cout << "v_s: " << v_s << " ";
    i_s = determinePacketIndex(v_s, SEQ_s);
    //std::cout << "i_s: " << i_s << std::endl;

    // 3.  Determine master key / master salt using packet index (i) OR MKI (section 8.1)
    // NO-OP -- MASTER KEY / MASTER SALT ASSUMED TO BE UNIQUE WITHIN CONTEXT

    // 4.  Determine session key / session salt (section 4.3) using master key + master salt + key_derivation_rate + session key-lengths + packet index (i)
    // NO-OP -- SESSION KEY / SESSION SALT ALREADY DETERMINED AT THIS POINT

    // 5.  Encrypt PAYLOAD to produce encrypted portion (section 4.1) using encryption algorithm + session encryption key + session salting key + packet index (i)
    rc = computePacketIV(i_s);
    if (rc == 0)
    {
        rc = setPacketIV();
        if (rc == 0)
        {
            rc = encryptVector(rtp_payload, srtp_payload);
            if (rc == 0)
            {
                //printf("[processOutgoingPacket] CIPHERTEXT: [");
                //for (unsigned int i = 0; i < srtp_payload.size(); i++) {
                //    printf("%02x", srtp_payload[i]);
                //}
                //printf("]\n");

                auth_portion.insert(auth_portion.end(), rtp_header.begin(), rtp_header.end());
                auth_portion.insert(auth_portion.end(), srtp_payload.begin(), srtp_payload.end());

                // 6.  If MKI is 1 then append MKI to packet
                // NO-OP -- MKI NOT USED

                // 7A. Compute authentication tag from authenticated portion of the packet (section 4.2) using RoC + authentication algorithm + session authentication key
                rc = issueAuthenticationTag(auth_portion, auth_tag);
                if (rc == 0)
                {
                    // 7B. Append authentication tag to the packet to produce encrypted+authenticated portion
                    srtp_packet.clear();
                    srtp_packet.insert(srtp_packet.end(), auth_portion.begin(), auth_portion.end());
                    srtp_packet.insert(srtp_packet.end(), auth_tag.begin(), auth_tag.end());

                    // 8.  If necessary update RoC (section 3.3.1) using packet index (i)
                    check = updateRollOverCounter(v_s);
                    if (check)
                    {
                        check = updateSL(SEQ_s);
                        if (check)
                        {
                            retVal = 0;
                        }
                        else
                        {
                            retVal = -6;
                        }
                    }
                    else
                    {
                        retVal = -5;
                    }
                }
                else
                {
                    retVal = -2;
                }
            }
            else
            {
                retVal = -1; // ENCRYPTION FAILURE
            }
        }
        else
        {
            retVal = -4;
        }
    }
    else
    {
        retVal = -3;
    }

    return retVal;
}

int JLSRTP::processIncomingPacket(unsigned short SEQ_r,
                                  std::vector<unsigned char> &srtp_packet,
                                  std::vector<unsigned char> &rtp_header,
                                  std::vector<unsigned char> &rtp_payload)
{
    int rc = 0;
    bool check = false;
    unsigned long v_r = 0;
    unsigned long long i_r = 0LL; /* TEST PACKET INDEX */
    std::vector<unsigned char> auth_tag_generated;
    std::vector<unsigned char> auth_portion;
    std::vector<unsigned char> auth_tag_received;
    std::vector<unsigned char> srtp_payload; /* ENCRYPTED PAYLOAD */
    int retVal = -1;

    rtp_header.clear();
    rtp_payload.clear();

    // 1.  Determine crypto context to use
    // NO-OP (IMPLICIT)

    // 2.  Determine packet index (i) using RoC + _s_l (section 3.3.1)
    //std::cout << "[processIncomingPacket] SEQ_r: " << SEQ_r << " current ROC_r: " << _ROC << " current s_l_r: " << _s_l << " ";
    v_r = determineV(SEQ_r);
    //std::cout << "v_r: " << v_r << " ";
    i_r = determinePacketIndex(v_r, SEQ_r);
    //std::cout << "i_r: " << i_r << " " << std::endl;

    // 3.  Determine master key / master salt -- if MKI is 1 then use MKI in packet otherwise use packet index (i) (section 8.1)
    // NO-OP -- MASTER KEY / MASTER SALT ASSUMED TO BE UNIQUE WITHIN CONTEXT

    // 4.  Determine session key / session salt (section 4.3) using master key + master salt + key_derivation_rate + session key-lengths + packet index (i)
    // NO-OP -- SESSION KEY / SESSION SALT ALREADY DETERMINED AT THIS POINT

    // 5A. Check if packet has been replayed (section 3.3.2) using replay list + packet index (i) -- discard packet if replayed
    // NO-OP -- REPLAY LIST NOT USED

    // 5B. Verify authentication tag using RoC + authentication algorithm + session authentication key -- if authentication failure (section 4.2) discard packet

    rc = extractAuthenticationTag(srtp_packet, auth_tag_received);
    if (rc == 0)
    {
        rc = extractSRTPHeader(srtp_packet, rtp_header);
        if (rc == 0)
        {
            rc = extractSRTPPayload(srtp_packet, srtp_payload);
            if (rc == 0)
            {
                auth_portion.insert(auth_portion.end(), rtp_header.begin(), rtp_header.end());
                auth_portion.insert(auth_portion.end(), srtp_payload.begin(), srtp_payload.end());

                rc = issueAuthenticationTag(auth_portion, auth_tag_generated);
                if (rc == 0)
                {
                    if (auth_tag_received == auth_tag_generated)
                    {
                        // 6.  Decrypt PAYLOAD (section 4.1) using decryption algorithm + session encryption key + session salting key
                        //printf("[processIncomingPacket] CIPHERTEXT: [");
                        //for (unsigned int i = 0; i < srtp_payload.size(); i++) {
                        //    printf("%02x", srtp_payload[i]);
                        //}
                        //printf("]\n");

                        rc = computePacketIV(i_r);
                        if (rc == 0)
                        {
                            rc = setPacketIV();
                            if (rc == 0)
                            {
                                rc = decryptVector(srtp_payload, rtp_payload);
                                if (rc == 0)
                                {
                                    // 7A. Update RoC / _s_l (section 3.3.1) using estimated packet index (i)
                                    check = updateRollOverCounter(v_r);
                                    if (check)
                                    {
                                        check = updateSL(SEQ_r);
                                        if (check)
                                        {
                                            // 7B. Update replay list if applicable (section 3.3.2)
                                            // NO-OP -- REPLAY LIST NOT USED

                                            // 8.  Remove MKI + authentication tag fields from packet if present
                                            // NO-OP -- AUTOMATICALLY DONE BY PREVIOUS RTP HEADER+PAYLOAD EXTRACTION

                                            retVal = 0;
                                        }
                                        else
                                        {
                                            retVal = -10;
                                        }
                                    }
                                    else
                                    {
                                        retVal = -9;
                                    }
                                }
                                else
                                {
                                    retVal = -2;  // DECRYPTION FAILURE
                                }
                            }
                            else
                            {
                                retVal = -8;
                            }
                        }
                        else
                        {
                            retVal = -7;
                        }
                    }
                    else
                    {
                        retVal = -1; // AUTHENTICATION FAILURE
                    }
                }
                else
                {
                    retVal = -6;
                }
            }
            else
            {
                retVal = -5;
            }
        }
        else
        {
            retVal = -4;
        }
    }
    else
    {
        retVal = -3;
    }

    return retVal;
}

int JLSRTP::setCryptoTag(unsigned int tag, ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    int retVal = -1;
    ActiveCrypto active_crypto = INVALID_CRYPTO;

    if (crypto_attrib == ACTIVE_CRYPTO)
    {
        active_crypto = _active_crypto;
    }
    else
    {
        active_crypto = crypto_attrib;
    }

    switch (active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            _primary_crypto.tag = tag;
            retVal = 0;
        }
        break;

        case SECONDARY_CRYPTO:
        {
            _secondary_crypto.tag = tag;
            retVal = 0;
        }
        break;

        default:
        {
            retVal = -1;
        }
        break;
    }

    return retVal;
}

unsigned int JLSRTP::getCryptoTag(ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    int retVal = -1;
    ActiveCrypto active_crypto = INVALID_CRYPTO;

    if (crypto_attrib == ACTIVE_CRYPTO)
    {
        active_crypto = _active_crypto;
    }
    else
    {
        active_crypto = crypto_attrib;
    }

    switch (active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            return _primary_crypto.tag;
        }
        break;

        case SECONDARY_CRYPTO:
        {
            return _secondary_crypto.tag;
        }
        break;

        default:
        {
            retVal = -1;
        }
        break;
    }

    return retVal;
}

void JLSRTP::setOfferedCryptoSuite(const std::string& suite, ActiveCrypto crypto_attrib)
{
    if (crypto_attrib == PRIMARY_CRYPTO) {
        _primary_crypto.offered_suite = suite;
    } else if (crypto_attrib == SECONDARY_CRYPTO) {
        _secondary_crypto.offered_suite = suite;
    }
}

std::string JLSRTP::getCryptoSuite(ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    std::string cryptosuite;
    ActiveCrypto active_crypto = (crypto_attrib == ACTIVE_CRYPTO) ? _active_crypto : crypto_attrib;

    const std::string& offered = (active_crypto == SECONDARY_CRYPTO) ? _secondary_crypto.offered_suite : _primary_crypto.offered_suite;
    if (!offered.empty()) {
        return offered;
    }

    switch (active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            switch (_primary_crypto.cipher_algorithm)
            {
                case AES_CM_128:
                {
                    switch (_primary_crypto.hmac_algorithm)
                    {
                        case HMAC_SHA1_80:
                        {
                             cryptosuite = "AES_CM_128_HMAC_SHA1_80";
                        }
                        break;

                        case HMAC_SHA1_32:
                        {
                            cryptosuite = "AES_CM_128_HMAC_SHA1_32";
                        }
                        break;

                        default:
                        {
                            cryptosuite = "";
                        }
                        break;
                    }
                }
                break;

                case AES_CM_192:
                case AES_CM_256:
                {
                    const char* aes = (_primary_crypto.cipher_algorithm == AES_CM_192) ? "AES_192_CM" : "AES_256_CM";
                    switch (_primary_crypto.hmac_algorithm)
                    {
                        case HMAC_SHA1_80:
                        {
                            cryptosuite = std::string(aes) + "_HMAC_SHA1_80";
                        }
                        break;

                        case HMAC_SHA1_32:
                        {
                            cryptosuite = std::string(aes) + "_HMAC_SHA1_32";
                        }
                        break;

                        default:
                        {
                            cryptosuite = "";
                        }
                        break;
                    }
                }
                break;

                case NULL_CIPHER:
                {
                    switch (_primary_crypto.hmac_algorithm)
                    {
                        case HMAC_SHA1_80:
                        {
                            cryptosuite = "NULL_HMAC_SHA1_80";
                        }
                        break;

                        case HMAC_SHA1_32:
                        {
                            cryptosuite = "NULL_HMAC_SHA1_32";
                        }
                        break;

                        default:
                        {
                            cryptosuite = "";
                        }
                        break;
                    }
                }
                break;

                default:
                {
                    cryptosuite = "";
                }
                break;
            }
        }
        break;

        case SECONDARY_CRYPTO:
        {
            switch (_secondary_crypto.cipher_algorithm)
            {
                case AES_CM_128:
                {
                    switch (_secondary_crypto.hmac_algorithm)
                    {
                        case HMAC_SHA1_80:
                        {
                             cryptosuite = "AES_CM_128_HMAC_SHA1_80";
                        }
                        break;

                        case HMAC_SHA1_32:
                        {
                            cryptosuite = "AES_CM_128_HMAC_SHA1_32";
                        }
                        break;

                        default:
                        {
                            cryptosuite = "";
                        }
                        break;
                    }
                }
                break;

                case AES_CM_192:
                case AES_CM_256:
                {
                    const char* aes = (_secondary_crypto.cipher_algorithm == AES_CM_192) ? "AES_192_CM" : "AES_256_CM";
                    switch (_secondary_crypto.hmac_algorithm)
                    {
                        case HMAC_SHA1_80:
                        {
                            cryptosuite = std::string(aes) + "_HMAC_SHA1_80";
                        }
                        break;

                        case HMAC_SHA1_32:
                        {
                            cryptosuite = std::string(aes) + "_HMAC_SHA1_32";
                        }
                        break;

                        default:
                        {
                            cryptosuite = "";
                        }
                        break;
                    }
                }
                break;

                case NULL_CIPHER:
                {
                    switch (_secondary_crypto.hmac_algorithm)
                    {
                        case HMAC_SHA1_80:
                        {
                            cryptosuite = "NULL_HMAC_SHA1_80";
                        }
                        break;

                        case HMAC_SHA1_32:
                        {
                            cryptosuite = "NULL_HMAC_SHA1_32";
                        }
                        break;

                        default:
                        {
                            cryptosuite = "";
                        }
                        break;
                    }
                }
                break;

                default:
                {
                    cryptosuite = "";
                }
                break;
            }
        }
        break;

        default:
        {
            cryptosuite = "";
        }
        break;
    }

    return cryptosuite;
}

int JLSRTP::encodeMasterKeySalt(std::string &mks, ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    int retVal = -1;
    std::vector<unsigned char> concat;
    mks.clear();
    ActiveCrypto active_crypto = INVALID_CRYPTO;

    if (crypto_attrib == ACTIVE_CRYPTO)
    {
        active_crypto = _active_crypto;
    }
    else
    {
        active_crypto = crypto_attrib;
    }

    switch (active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            concat.insert(concat.end(), _primary_crypto.master_key.begin(), _primary_crypto.master_key.end());
            concat.insert(concat.end(), _primary_crypto.master_salt.begin(), _primary_crypto.master_salt.end());

            //std::cout << "encodeMasterKeySalt(): concat:[";
            //for (unsigned int i = 0; i < concat.size(); i++)
            //{
            //    printf("%02X", concat[i]);
            //}
            //std::cout << "]" << std::endl;

            mks = base64Encode(concat);

            //std::cout << "encodeMasterKeySalt():  [" << mks << "]" << std::endl;
            retVal = 0;
        }
        break;

        case SECONDARY_CRYPTO:
        {
            concat.insert(concat.end(), _secondary_crypto.master_key.begin(), _secondary_crypto.master_key.end());
            concat.insert(concat.end(), _secondary_crypto.master_salt.begin(), _secondary_crypto.master_salt.end());

            //std::cout << "encodeMasterKeySalt(): concat:[";
            //for (unsigned int i = 0; i < concat.size(); i++)
            //{
            //    printf("%02X", concat[i]);
            //}
            //std::cout << "]" << std::endl;

            mks = base64Encode(concat);

            //std::cout << "encodeMasterKeySalt():  [" << mks << "]" << std::endl;
            retVal = 0;
        }
        break;

        default:
        {
            retVal = -1;
        }
    }

    return retVal;
}

int JLSRTP::decodeMasterKeySalt(std::string &mks, ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/, size_t keyLength /*= 0*/)
{
    int retVal = -1;
    std::vector<unsigned char> concat;
    size_t split_pos = 0;
    ActiveCrypto active_crypto = INVALID_CRYPTO;

    if (crypto_attrib == ACTIVE_CRYPTO)
    {
        active_crypto = _active_crypto;
    }
    else
    {
        active_crypto = crypto_attrib;
    }

    // The salt is 14 bytes in all suites, the AES key what comes before
    concat = base64Decode(mks);
    if (concat.size() <= JLSRTP_SALTING_KEY_LENGTH)
    {
        return -1;
    }
    split_pos = concat.size() - JLSRTP_SALTING_KEY_LENGTH;
    if (keyLength ? split_pos != keyLength :
        split_pos != JLSRTP_ENCRYPTION_KEY_LENGTH && split_pos != JLSRTP_AES_192_KEY_LENGTH && split_pos != JLSRTP_AES_256_KEY_LENGTH)
    {
        return -1;
    }

    switch (active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            _primary_crypto.n_e = split_pos;
            _primary_crypto.master_key.assign(concat.begin(), concat.begin() + split_pos);
            _primary_crypto.master_salt.assign(concat.begin() + split_pos, concat.end());
            retVal = 0;
        }
        break;

        case SECONDARY_CRYPTO:
        {
            _secondary_crypto.n_e = split_pos;
            _secondary_crypto.master_key.assign(concat.begin(), concat.begin() + split_pos);
            _secondary_crypto.master_salt.assign(concat.begin() + split_pos, concat.end());
            retVal = 0;
        }
        break;

        default:
        {
            retVal = -1;
        }
        break;
    }

    return retVal;
}

void JLSRTP::displayCryptoContext()
{
    std::cout << "_id                                          : " << "(" << _id.ssrc << ", " << _id.address << ", " << _id.port << ")" << std::endl;
    std::cout << "_ROC                                         : " << _ROC << std::endl;
    std::cout << "_s_l                                         : " << _s_l << std::endl;
    std::cout << "_primary_crypto.cipher_algorithm             : " << _primary_crypto.cipher_algorithm << std::endl;
    std::cout << "_primary_crypto.hmac_algorithm               : " << _primary_crypto.hmac_algorithm << std::endl;
    std::cout << "_primary_crypto.MKI                          : " << _primary_crypto.MKI << std::endl;
    std::cout << "_primary_crypto.MKI_length                   : " << _primary_crypto.MKI_length << std::endl;
    std::cout << "_primary_crypto.active_MKI                   : " << _primary_crypto.active_MKI << std::endl;
    std::cout << "_primary_crypto.master_key                   : ";
    std::cout.setf(std::ios::hex, std::ios::basefield);
    std::cout << std::setfill('0') << std::setw(JLSRTP_ENCRYPTION_KEY_LENGTH);
    for (unsigned int i = 0; i < _primary_crypto.master_key.size(); i++)
    {
        printf("%02x", _primary_crypto.master_key[i]);
//        std::cout << std::hex << _primary_crypto.master_key[i];
    }
    std::cout.unsetf(std::ios::hex);
    std::cout << std::endl;
    std::cout << "_primary_crypto.master_key_counter           : " << _primary_crypto.master_key_counter << std::endl;
    std::cout << "_primary_crypto.n_e                          : " << _primary_crypto.n_e << std::endl;
    std::cout << "_primary_crypto.n_a                          : " << _primary_crypto.n_a << std::endl;
    std::cout << "_primary_crypto.master_salt                  : ";
    std::cout.setf(std::ios::hex, std::ios::basefield);
    std::cout << std::setfill('0') << std::setw(JLSRTP_SALTING_KEY_LENGTH);
    for (unsigned int i = 0; i < _primary_crypto.master_salt.size(); i++)
    {
        printf("%02x", _primary_crypto.master_salt[i]);
//        std::cout << std::hex << _primary_crypto.master_salt[i];
    }
    std::cout.unsetf(std::ios::hex);
    std::cout << std::endl;
    std::cout << "_primary_crypto.master_key_derivation_rate   : " << _primary_crypto.master_key_derivation_rate << std::endl;
    std::cout << "_primary_crypto.master_mki_value             : " << _primary_crypto.master_mki_value << std::endl;
    std::cout << "_primary_crypto.n_s                          : " << _primary_crypto.n_s << std::endl;
    std::cout << "_primary_crypto.tag                          : " << _primary_crypto.tag << std::endl;
    std::cout << "_secondary_crypto.cipher_algorithm           : " << _secondary_crypto.cipher_algorithm << std::endl;
    std::cout << "_secondary_crypto.hmac_algorithm             : " << _secondary_crypto.hmac_algorithm << std::endl;
    std::cout << "_secondary_crypto.MKI                        : " << _secondary_crypto.MKI << std::endl;
    std::cout << "_secondary_crypto.MKI_length                 : " << _secondary_crypto.MKI_length << std::endl;
    std::cout << "_secondary_crypto.active_MKI                 : " << _secondary_crypto.active_MKI << std::endl;
    std::cout << "_secondary_crypto.master_key                 : ";
    std::cout.setf(std::ios::hex, std::ios::basefield);
    std::cout << std::setfill('0') << std::setw(JLSRTP_ENCRYPTION_KEY_LENGTH);
    for (unsigned int i = 0; i < _secondary_crypto.master_key.size(); i++)
    {
        printf("%02x", _secondary_crypto.master_key[i]);
//        std::cout << std::hex << _secondary_crypto.master_key[i];
    }
    std::cout.unsetf(std::ios::hex);
    std::cout << std::endl;
    std::cout << "_secondary_crypto.master_key_counter         : " << _secondary_crypto.master_key_counter << std::endl;
    std::cout << "_secondary_crypto.n_e                        : " << _secondary_crypto.n_e << std::endl;
    std::cout << "_secondary_crypto.n_a                        : " << _secondary_crypto.n_a << std::endl;
    std::cout << "_secondary_crypto.master_salt                : ";
    std::cout.setf(std::ios::hex, std::ios::basefield);
    std::cout << std::setfill('0') << std::setw(JLSRTP_SALTING_KEY_LENGTH);
    for (unsigned int i = 0; i < _secondary_crypto.master_salt.size(); i++)
    {
        printf("%02x", _secondary_crypto.master_salt[i]);
//        std::cout << std::hex << _secondary_crypto.master_salt[i];
    }
    std::cout.unsetf(std::ios::hex);
    std::cout << std::endl;
    std::cout << "_secondary_crypto.master_key_derivation_rate : " << _secondary_crypto.master_key_derivation_rate << std::endl;
    std::cout << "_secondary_crypto.master_mki_value           : " << _secondary_crypto.master_mki_value << std::endl;
    std::cout << "_secondary_crypto.n_s                        : " << _secondary_crypto.n_s << std::endl;
    std::cout << "_secondary_crypto.tag                        : " << _secondary_crypto.tag << std::endl;
    printf("_session_enc_key                             : [");
    for (unsigned int i = 0; i < _session_enc_key.size(); i++)
    {
        printf("%02x", _session_enc_key[i]);
    }
    printf("]\n");
    printf("_session_salt_key                            : [");
    for (unsigned int i = 0; i < _session_salt_key.size(); i++)
    {
        printf("%02x", _session_salt_key[i]);
    }
    printf("]\n");
    printf("_session_auth_key                            : [");
    for (unsigned int i = 0; i < _session_auth_key.size(); i++)
    {
        printf("%02x", _session_auth_key[i]);
    }
    printf("]\n");
    printf("_packet_iv                                   : [");
    for (unsigned int i = 0; i < _packetIV.size(); i++)
    {
        printf("%02x", _packetIV[i]);
    }
    printf("]\n");

    std::cout << "_pseudorandomstate.ivec                      : [";
    for (unsigned int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        printf("%02x", _pseudorandomstate.ivec[i]);
    }
    std::cout << "]" << std::endl;
    std::cout << "_pseudorandomstate.num                       : " << _pseudorandomstate.num << std::endl;
    std::cout << "_pseudorandomstate.ecount                    : [";
    for (unsigned int i = 0; i < AES_BLOCK_SIZE; i++)
    {
       printf("%02x", _pseudorandomstate.ecount[i]);
    }
    std::cout << "]" << std::endl;

    std::cout << "_cipherstate.ivec                            : [";
    for (unsigned int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        printf("%02x", _cipherstate.ivec[i]);
    }
    std::cout << "]" << std::endl;
    std::cout << "_cipherstate.num                             : " << _cipherstate.num << std::endl;
    std::cout << "_cipherstate.ecount                          : [";
    for (unsigned int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        printf("%02x", _cipherstate.ecount[i]);
    }
    std::cout << "]" << std::endl;
    std::cout << "_srtp_header_size                            : " << _srtp_header_size << std::endl;
    std::cout << "_srtp_payload_size                           : " << _srtp_payload_size << std::endl;
    std::cout << "_active_crypto                               : " << _active_crypto << std::endl;
}

std::string JLSRTP::dumpCryptoContext()
{
    std::ostringstream oss;

    oss.str("");

    oss << "_id                                          : " << "(" << _id.ssrc << ", " << _id.address << ", " << _id.port << ")" << std::endl;
    oss << "_ROC                                         : " << _ROC << std::endl;
    oss << "_s_l                                         : " << _s_l << std::endl;
    oss << "_primary_crypto.cipher_algorithm             : " << _primary_crypto.cipher_algorithm << std::endl;
    oss << "_primary_crypto.hmac_algorithm               : " << _primary_crypto.hmac_algorithm << std::endl;
    oss << "_primary_crypto.MKI                          : " << _primary_crypto.MKI << std::endl;
    oss << "_primary_crypto.MKI_length                   : " << _primary_crypto.MKI_length << std::endl;
    oss << "_primary_crypto.active_MKI                   : " << _primary_crypto.active_MKI << std::endl;
    oss << "_primary_crypto.master_key                   : ";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (unsigned int i = 0; i < _primary_crypto.master_key.size(); i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_primary_crypto.master_key[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << std::endl;
    oss << "_primary_crypto.master_key_counter           : " << _primary_crypto.master_key_counter << std::endl;
    oss << "_primary_crypto.n_e                          : " << _primary_crypto.n_e << std::endl;
    oss << "_primary_crypto.n_a                          : " << _primary_crypto.n_a << std::endl;
    oss << "_primary_crypto.master_salt                  : ";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (unsigned int i = 0; i < _primary_crypto.master_salt.size(); i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_primary_crypto.master_salt[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << std::endl;
    oss << "_primary_crypto.master_key_derivation_rate   : " << _primary_crypto.master_key_derivation_rate << std::endl;
    oss << "_primary_crypto.master_mki_value             : " << _primary_crypto.master_mki_value << std::endl;
    oss << "_primary_crypto.n_s                          : " << _primary_crypto.n_s << std::endl;
    oss << "_primary_crypto.tag                          : " << _primary_crypto.tag << std::endl;
    oss << "_secondary_crypto.cipher_algorithm           : " << _secondary_crypto.cipher_algorithm << std::endl;
    oss << "_secondary_crypto.hmac_algorithm             : " << _secondary_crypto.hmac_algorithm << std::endl;
    oss << "_secondary_crypto.MKI                        : " << _secondary_crypto.MKI << std::endl;
    oss << "_secondary_crypto.MKI_length                 : " << _secondary_crypto.MKI_length << std::endl;
    oss << "_secondary_crypto.active_MKI                 : " << _secondary_crypto.active_MKI << std::endl;
    oss << "_secondary_crypto.master_key                 : ";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (unsigned int i = 0; i < _secondary_crypto.master_key.size(); i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_secondary_crypto.master_key[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << std::endl;
    oss << "_secondary_crypto.master_key_counter         : " << _secondary_crypto.master_key_counter << std::endl;
    oss << "_secondary_crypto.n_e                        : " << _secondary_crypto.n_e << std::endl;
    oss << "_secondary_crypto.n_a                        : " << _secondary_crypto.n_a << std::endl;
    oss << "_secondary_crypto.master_salt                : ";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (unsigned int i = 0; i < _secondary_crypto.master_salt.size(); i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_secondary_crypto.master_salt[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << std::endl;
    oss << "_secondary_crypto.master_key_derivation_rate : " << _secondary_crypto.master_key_derivation_rate << std::endl;
    oss << "_secondary_crypto.master_mki_value           : " << _secondary_crypto.master_mki_value << std::endl;
    oss << "_secondary_crypto.n_s                        : " << _secondary_crypto.n_s << std::endl;
    oss << "_secondary_crypto.tag                        : " << _secondary_crypto.tag << std::endl;
    oss << "_session_enc_key                       : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (unsigned int i = 0; i < _session_enc_key.size(); i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_session_enc_key[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;
    oss << "_session_salt_key                      : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (unsigned int i = 0; i < _session_salt_key.size(); i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_session_salt_key[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;
    oss << "_session_auth_key                      : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (unsigned int i = 0; i < _session_auth_key.size(); i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_session_auth_key[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;
    oss << "_packet_iv                             : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (unsigned int i = 0; i < _packetIV.size(); i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_packetIV[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;

    oss << "_pseudorandomstate.ivec                      : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (unsigned int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_pseudorandomstate.ivec[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;
    oss << "_pseudorandomstate.num                       : " << _pseudorandomstate.num << std::endl;
    oss << "_pseudorandomstate.ecount                    : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (unsigned int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_pseudorandomstate.ecount[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;

    oss << "_cipherstate.ivec                            : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (unsigned int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_cipherstate.ivec[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;
    oss << "_cipherstate.num                             : " << _cipherstate.num << std::endl;
    oss << "_cipherstate.ecount                          : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (unsigned int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_cipherstate.ecount[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;
    oss << "_srtp_header_size                            : " << _srtp_header_size << std::endl;
    oss << "_srtp_payload_size                           : " << _srtp_payload_size << std::endl;
    oss << "_active_crypto                               : " << _active_crypto << std::endl;

    return oss.str();
}

int JLSRTP::generateMasterKey(ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    int retVal = -1;
    ActiveCrypto active_crypto = INVALID_CRYPTO;

    if (crypto_attrib == ACTIVE_CRYPTO)
    {
        active_crypto = _active_crypto;
    }
    else
    {
        active_crypto = crypto_attrib;
    }

    switch (active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            _primary_crypto.master_key.resize(masterKeyLength(_primary_crypto.cipher_algorithm));
            _primary_crypto.n_e = _primary_crypto.master_key.size();
            if (RAND_bytes(_primary_crypto.master_key.data(), _primary_crypto.master_key.size()) == 1)
            {
                retVal = 0;
            }
            else
            {
                retVal = -1;
            }
/*
            _primary_crypto.master_key.clear();
            _primary_crypto.master_key.push_back(0xE1);
            _primary_crypto.master_key.push_back(0xF9);
            _primary_crypto.master_key.push_back(0x7A);
            _primary_crypto.master_key.push_back(0x0D);
            _primary_crypto.master_key.push_back(0x3E);
            _primary_crypto.master_key.push_back(0x01);
            _primary_crypto.master_key.push_back(0x8B);
            _primary_crypto.master_key.push_back(0xE0);
            _primary_crypto.master_key.push_back(0xD6);
            _primary_crypto.master_key.push_back(0x4F);
            _primary_crypto.master_key.push_back(0xA3);
            _primary_crypto.master_key.push_back(0x2C);
            _primary_crypto.master_key.push_back(0x06);
            _primary_crypto.master_key.push_back(0xDE);
            _primary_crypto.master_key.push_back(0x41);
            _primary_crypto.master_key.push_back(0x39);
            retVal = 0;
*/
        }
        break;

        case SECONDARY_CRYPTO:
        {
            _secondary_crypto.master_key.resize(masterKeyLength(_secondary_crypto.cipher_algorithm));
            _secondary_crypto.n_e = _secondary_crypto.master_key.size();
            if (RAND_bytes(_secondary_crypto.master_key.data(), _secondary_crypto.master_key.size()) == 1)
            {
                retVal = 0;
            }
            else
            {
                retVal = -1;
            }
/*
            _secondary_crypto.master_key.clear();
            _secondary_crypto.master_key.push_back(0xE1);
            _secondary_crypto.master_key.push_back(0xF9);
            _secondary_crypto.master_key.push_back(0x7A);
            _secondary_crypto.master_key.push_back(0x0D);
            _secondary_crypto.master_key.push_back(0x3E);
            _secondary_crypto.master_key.push_back(0x01);
            _secondary_crypto.master_key.push_back(0x8B);
            _secondary_crypto.master_key.push_back(0xE0);
            _secondary_crypto.master_key.push_back(0xD6);
            _secondary_crypto.master_key.push_back(0x4F);
            _secondary_crypto.master_key.push_back(0xA3);
            _secondary_crypto.master_key.push_back(0x2C);
            _secondary_crypto.master_key.push_back(0x06);
            _secondary_crypto.master_key.push_back(0xDE);
            _secondary_crypto.master_key.push_back(0x41);
            _secondary_crypto.master_key.push_back(0x39);
            retVal = 0;
*/
        }
        break;

        default:
        {
            retVal = -1;
        }
        break;
    }

    return retVal;
}

int JLSRTP::generateMasterSalt(ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    int retVal = -1;
    ActiveCrypto active_crypto = INVALID_CRYPTO;

    if (crypto_attrib == ACTIVE_CRYPTO)
    {
        active_crypto = _active_crypto;
    }
    else
    {
        active_crypto = crypto_attrib;
    }

    switch (active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            if (RAND_bytes(_primary_crypto.master_salt.data(), _primary_crypto.master_salt.size()) == 1)
            {
                retVal = 0;
            }
            else
            {
                retVal = -1;
            }
/*
            _primary_crypto.master_salt.clear();
            _primary_crypto.master_salt.push_back(0x0E);
            _primary_crypto.master_salt.push_back(0xC6);
            _primary_crypto.master_salt.push_back(0x75);
            _primary_crypto.master_salt.push_back(0xAD);
            _primary_crypto.master_salt.push_back(0x49);
            _primary_crypto.master_salt.push_back(0x8A);
            _primary_crypto.master_salt.push_back(0xFE);
            _primary_crypto.master_salt.push_back(0xEB);
            _primary_crypto.master_salt.push_back(0xB6);
            _primary_crypto.master_salt.push_back(0x96);
            _primary_crypto.master_salt.push_back(0x0B);
            _primary_crypto.master_salt.push_back(0x3A);
            _primary_crypto.master_salt.push_back(0xAB);
            _primary_crypto.master_salt.push_back(0xE6);
            retVal = 0;
*/
        }
        break;

        case SECONDARY_CRYPTO:
        {
            if (RAND_bytes(_secondary_crypto.master_salt.data(), _secondary_crypto.master_salt.size()) == 1)
            {
                retVal = 0;
            }
            else
            {
                retVal = -1;
            }
/*
            _secondary_crypto.master_salt.clear();
            _secondary_crypto.master_salt.push_back(0x0E);
            _secondary_crypto.master_salt.push_back(0xC6);
            _secondary_crypto.master_salt.push_back(0x75);
            _secondary_crypto.master_salt.push_back(0xAD);
            _secondary_crypto.master_salt.push_back(0x49);
            _secondary_crypto.master_salt.push_back(0x8A);
            _secondary_crypto.master_salt.push_back(0xFE);
            _secondary_crypto.master_salt.push_back(0xEB);
            _secondary_crypto.master_salt.push_back(0xB6);
            _secondary_crypto.master_salt.push_back(0x96);
            _secondary_crypto.master_salt.push_back(0x0B);
            _secondary_crypto.master_salt.push_back(0x3A);
            _secondary_crypto.master_salt.push_back(0xAB);
            _secondary_crypto.master_salt.push_back(0xE6);
            retVal = 0;
*/
        }
        break;

        default:
        {
            retVal = -1;
        }
        break;
    }

    return retVal;
}

std::vector<unsigned char> JLSRTP::getMasterKey(ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    std::vector<unsigned char> retVal;
    ActiveCrypto active_crypto = INVALID_CRYPTO;

    if (crypto_attrib == ACTIVE_CRYPTO)
    {
        active_crypto = _active_crypto;
    }
    else
    {
        active_crypto = crypto_attrib;
    }

    switch (active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            retVal = _primary_crypto.master_key;
        }
        break;

        case SECONDARY_CRYPTO:
        {
            retVal = _secondary_crypto.master_key;
        }
        break;

        default:
        {
            retVal.clear();
        }
        break;
    }

    return retVal;
}

std::vector<unsigned char> JLSRTP::getMasterSalt(ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    std::vector<unsigned char> retVal;
    ActiveCrypto active_crypto = INVALID_CRYPTO;

    if (crypto_attrib == ACTIVE_CRYPTO)
    {
        active_crypto = _active_crypto;
    }
    else
    {
        active_crypto = crypto_attrib;
    }

    switch (active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            retVal = _primary_crypto.master_salt;
        }
        break;

        case SECONDARY_CRYPTO:
        {
            retVal = _secondary_crypto.master_salt;
        }
        break;

        default:
        {
            retVal.clear();
        }
        break;
    }

    return retVal;
}

int JLSRTP::setMasterKey(std::vector<unsigned char> &key, ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    int retVal = -1;
    ActiveCrypto active_crypto = INVALID_CRYPTO;

    if (crypto_attrib == ACTIVE_CRYPTO)
    {
        active_crypto = _active_crypto;
    }
    else
    {
        active_crypto = crypto_attrib;
    }

    switch (active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            _primary_crypto.master_key = key;
            retVal = 0;
        }
        break;

        case SECONDARY_CRYPTO:
        {
            _secondary_crypto.master_key = key;
            retVal = 0;
        }
        break;

        default:
        {
            retVal = -1;
        }
        break;
    }

    return retVal;
}

int JLSRTP::setMasterSalt(std::vector<unsigned char> &salt, ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    int retVal = -1;
    ActiveCrypto active_crypto = INVALID_CRYPTO;

    if (crypto_attrib == ACTIVE_CRYPTO)
    {
        active_crypto = _active_crypto;
    }
    else
    {
        active_crypto = crypto_attrib;
    }

    switch (active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            _primary_crypto.master_salt = salt;
            retVal = 0;
        }
        break;

        case SECONDARY_CRYPTO:
        {
            _secondary_crypto.master_salt = salt;
            retVal = 0;
        }
        break;

        default:
        {
            retVal = -1;
        }
        break;
    }

    return retVal;
}

int JLSRTP::swapCrypto()
{
    int retVal = 0;

    CipherType              cipher_algorithm = INVALID_CIPHER;
    HashType                hmac_algorithm = INVALID_HASH;
    bool                    MKI = false;
    unsigned int            MKI_length = 0;
    unsigned long           active_MKI = 0;
    std::vector<unsigned char>      master_key;
    unsigned long           master_key_counter = 0;
    unsigned short          n_e = 0;
    unsigned short          n_a = 0;
    std::vector<unsigned char>      master_salt;
    unsigned long           master_key_derivation_rate = 0;
    unsigned long           master_mki_value = 0;
    unsigned short          n_s = 0;
    unsigned int                        tag = 0;

    _primary_crypto.offered_suite.swap(_secondary_crypto.offered_suite);

    cipher_algorithm                             = _primary_crypto.cipher_algorithm;
    hmac_algorithm                               = _primary_crypto.hmac_algorithm;
    MKI                                          = _primary_crypto.MKI;
    MKI_length                                   = _primary_crypto.MKI_length;
    active_MKI                                   = _primary_crypto.active_MKI;
    master_key                                   = _primary_crypto.master_key;
    master_key_counter                           = _primary_crypto.master_key_counter;
    n_e                                          = _primary_crypto.n_e;
    n_a                                          = _primary_crypto.n_a;
    master_salt                                  = _primary_crypto.master_salt;
    master_key_derivation_rate                   = _primary_crypto.master_key_derivation_rate;
    master_mki_value                             = _primary_crypto.master_mki_value;
    n_s                                          = _primary_crypto.n_s;
    tag                                          = _primary_crypto.tag;

    _primary_crypto.cipher_algorithm             = _secondary_crypto.cipher_algorithm;
    _primary_crypto.hmac_algorithm               = _secondary_crypto.hmac_algorithm;
    _primary_crypto.MKI                          = _secondary_crypto.MKI;
    _primary_crypto.MKI_length                   = _secondary_crypto.MKI_length;
    _primary_crypto.active_MKI                   = _secondary_crypto.active_MKI;
    _primary_crypto.master_key                   = _secondary_crypto.master_key;
    _primary_crypto.master_key_counter           = _secondary_crypto.master_key_counter;
    _primary_crypto.n_e                          = _secondary_crypto.n_e;
    _primary_crypto.n_a                          = _secondary_crypto.n_a;
    _primary_crypto.master_salt                  = _secondary_crypto.master_salt;
    _primary_crypto.master_key_derivation_rate   = _secondary_crypto.master_key_derivation_rate;
    _primary_crypto.master_mki_value             = _secondary_crypto.master_mki_value;
    _primary_crypto.n_s                          = _secondary_crypto.n_s;
    _primary_crypto.tag                          = _secondary_crypto.tag;

    _secondary_crypto.cipher_algorithm           = cipher_algorithm;
    _secondary_crypto.hmac_algorithm             = hmac_algorithm;
    _secondary_crypto.MKI                        = MKI;
    _secondary_crypto.MKI_length                 = MKI_length;
    _secondary_crypto.active_MKI                 = active_MKI;
    _secondary_crypto.master_key                 = master_key;
    _secondary_crypto.master_key_counter         = master_key_counter;
    _secondary_crypto.n_e                        = n_e;
    _secondary_crypto.n_a                        = n_a;
    _secondary_crypto.master_salt                = master_salt;
    _secondary_crypto.master_key_derivation_rate = master_key_derivation_rate;
    _secondary_crypto.master_mki_value           = master_mki_value;
    _secondary_crypto.n_s                        = n_s;
    _secondary_crypto.tag                        = tag;

    return retVal;
}

int JLSRTP::selectActiveCrypto(ActiveCrypto activeCrypto)
{
    int retVal = -1;

    switch (activeCrypto)
    {
        case PRIMARY_CRYPTO:
        {
            _active_crypto = activeCrypto;
            retVal = 0;
        }
        break;

        case SECONDARY_CRYPTO:
        {
            _active_crypto = activeCrypto;
            retVal = 0;
        }
        break;

        default:
        {
            _active_crypto = INVALID_CRYPTO;
            retVal = -1;
        }
        break;
    }

    return retVal;
}

ActiveCrypto JLSRTP::getActiveCrypto()
{
    return _active_crypto;
}

JLSRTP& JLSRTP::operator=(const JLSRTP& that)
{
    _id.ssrc = that._id.ssrc;
    _id.address = that._id.address;
    _id.port = that._id.port;
    _ROC = that._ROC;
    _s_l = that._s_l;
    _s_l_set = that._s_l_set;
    _primary_crypto.cipher_algorithm = that._primary_crypto.cipher_algorithm;
    _primary_crypto.hmac_algorithm = that._primary_crypto.hmac_algorithm;
    _primary_crypto.MKI = that._primary_crypto.MKI;
    _primary_crypto.MKI_length = that._primary_crypto.MKI_length;
    _primary_crypto.active_MKI = that._primary_crypto.active_MKI;
    _primary_crypto.master_key = that._primary_crypto.master_key;
    _primary_crypto.master_key_counter = that._primary_crypto.master_key_counter;
    _primary_crypto.n_e = that._primary_crypto.n_e;
    _primary_crypto.n_a = that._primary_crypto.n_a;
    _primary_crypto.master_salt = that._primary_crypto.master_salt;
    _primary_crypto.master_key_derivation_rate = that._primary_crypto.master_key_derivation_rate;
    _primary_crypto.master_mki_value = that._primary_crypto.master_mki_value;
    _primary_crypto.n_s = that._primary_crypto.n_s;
    _primary_crypto.tag = that._primary_crypto.tag;
    _secondary_crypto.cipher_algorithm = that._secondary_crypto.cipher_algorithm;
    _secondary_crypto.hmac_algorithm = that._secondary_crypto.hmac_algorithm;
    _secondary_crypto.MKI = that._secondary_crypto.MKI;
    _secondary_crypto.MKI_length = that._secondary_crypto.MKI_length;
    _secondary_crypto.active_MKI = that._secondary_crypto.active_MKI;
    _secondary_crypto.master_key = that._secondary_crypto.master_key;
    _secondary_crypto.master_key_counter = that._secondary_crypto.master_key_counter;
    _secondary_crypto.n_e = that._secondary_crypto.n_e;
    _secondary_crypto.n_a = that._secondary_crypto.n_a;
    _secondary_crypto.master_salt = that._secondary_crypto.master_salt;
    _secondary_crypto.master_key_derivation_rate = that._secondary_crypto.master_key_derivation_rate;
    _secondary_crypto.master_mki_value = that._secondary_crypto.master_mki_value;
    _secondary_crypto.n_s = that._secondary_crypto.n_s;
    _secondary_crypto.tag = that._secondary_crypto.tag;
    _session_enc_key = that._session_enc_key;
    _session_salt_key = that._session_salt_key;
    _session_auth_key = that._session_auth_key;
    _packetIV = that._packetIV;
    memcpy(_pseudorandomstate.ivec, that._pseudorandomstate.ivec, sizeof(_pseudorandomstate.ivec));
    _pseudorandomstate.num = that._pseudorandomstate.num;
    memcpy(_pseudorandomstate.ecount, that._pseudorandomstate.ecount, sizeof(_pseudorandomstate.ecount));
    memcpy(_cipherstate.ivec, that._cipherstate.ivec, sizeof(_cipherstate.ivec));
    _cipherstate.num = that._cipherstate.num;
    memcpy(_cipherstate.ecount, that._cipherstate.ecount, sizeof(_cipherstate.ecount));
    _srtp_header_size = that._srtp_header_size;
    _srtp_payload_size = that._srtp_payload_size;
    _active_crypto = that._active_crypto;

    return *this;
}

bool JLSRTP::operator==(const JLSRTP& that)
{
    if (
        (_id.ssrc == that._id.ssrc) &&
        (_id.address == that._id.address) &&
        (_id.port == that._id.port) &&
        (_ROC == that._ROC) &&
        (_s_l == that._s_l) &&
        (_primary_crypto.cipher_algorithm == that._primary_crypto.cipher_algorithm) &&
        (_primary_crypto.hmac_algorithm == that._primary_crypto.hmac_algorithm) &&
        (_primary_crypto.MKI == that._primary_crypto.MKI) &&
        (_primary_crypto.MKI_length == that._primary_crypto.MKI_length) &&
        (_primary_crypto.active_MKI == that._primary_crypto.active_MKI) &&
        (_primary_crypto.master_key == that._primary_crypto.master_key) &&
        (_primary_crypto.master_key_counter == that._primary_crypto.master_key_counter) &&
        (_primary_crypto.n_e == that._primary_crypto.n_e) &&
        (_primary_crypto.n_a == that._primary_crypto.n_a) &&
        (_primary_crypto.master_salt == that._primary_crypto.master_salt) &&
        (_primary_crypto.master_key_derivation_rate == that._primary_crypto.master_key_derivation_rate) &&
        (_primary_crypto.master_mki_value == that._primary_crypto.master_mki_value) &&
        (_primary_crypto.n_s == that._primary_crypto.n_s) &&
        (_primary_crypto.tag == that._primary_crypto.tag) &&
        (_secondary_crypto.cipher_algorithm == that._secondary_crypto.cipher_algorithm) &&
        (_secondary_crypto.hmac_algorithm == that._secondary_crypto.hmac_algorithm) &&
        (_secondary_crypto.MKI == that._secondary_crypto.MKI) &&
        (_secondary_crypto.MKI_length == that._secondary_crypto.MKI_length) &&
        (_secondary_crypto.active_MKI == that._secondary_crypto.active_MKI) &&
        (_secondary_crypto.master_key == that._secondary_crypto.master_key) &&
        (_secondary_crypto.master_key_counter == that._secondary_crypto.master_key_counter) &&
        (_secondary_crypto.n_e == that._secondary_crypto.n_e) &&
        (_secondary_crypto.n_a == that._secondary_crypto.n_a) &&
        (_secondary_crypto.master_salt == that._secondary_crypto.master_salt) &&
        (_secondary_crypto.master_key_derivation_rate == that._secondary_crypto.master_key_derivation_rate) &&
        (_secondary_crypto.master_mki_value == that._secondary_crypto.master_mki_value) &&
        (_secondary_crypto.n_s == that._secondary_crypto.n_s) &&
        (_secondary_crypto.tag == that._secondary_crypto.tag) &&
        (_session_enc_key == that._session_enc_key) &&
        (_session_salt_key == that._session_salt_key) &&
        (_session_auth_key == that._session_auth_key) &&
        (_packetIV == that._packetIV) &&
        (memcmp(_pseudorandomstate.ivec, that._pseudorandomstate.ivec, sizeof(_pseudorandomstate.ivec)) == 0) &&
        (_pseudorandomstate.num == that._pseudorandomstate.num) &&
        (memcmp(_pseudorandomstate.ecount, that._pseudorandomstate.ecount, sizeof(_pseudorandomstate.ecount)) == 0) &&
        (memcmp(_cipherstate.ivec, that._cipherstate.ivec, sizeof(_cipherstate.ivec)) == 0) &&
        (_cipherstate.num == that._cipherstate.num) &&
        (memcmp(_cipherstate.ecount, that._cipherstate.ecount, sizeof(_cipherstate.ecount)) == 0) &&
        (_srtp_header_size == that._srtp_header_size) &&
        (_srtp_payload_size == that._srtp_payload_size) &&
        (_active_crypto == that._active_crypto)
       )
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool JLSRTP::operator!=(const JLSRTP& that)
{
    if (*this == that)
    {
        return false;
    }
    else
    {
        return true;
    }
}

JLSRTP::JLSRTP()
{
    /* Made with their first key: see aesContext() */
    _pseudorandomstate.cipher = nullptr;
    _cipherstate.cipher = nullptr;

    resetCryptoContext(0xCA110000, "127.0.0.1", 0);
}

JLSRTP::JLSRTP(unsigned int ssrc, const std::string& ipAddress, unsigned short port)
{
    /* Made with their first key: see aesContext() */
    _pseudorandomstate.cipher = nullptr;
    _cipherstate.cipher = nullptr;

    resetCryptoContext(ssrc, ipAddress, port);
}

JLSRTP::~JLSRTP()
{
    EVP_CIPHER_CTX_free(_cipherstate.cipher);
    EVP_CIPHER_CTX_free(_pseudorandomstate.cipher);
    RAND_cleanup();
}

#ifdef GTEST
#include "gtest/gtest.h"

static std::vector<unsigned char> fromHex(const std::string& hex)
{
    std::vector<unsigned char> v;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        v.push_back(static_cast<unsigned char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return v;
}

class JLSRTPTest : public ::testing::Test
{
protected:
    // Session keys derived from a master key and salt with index 0, kdr 0
    static void derive(JLSRTP& s, CipherType cipher, const char* key, const char* salt)
    {
        std::vector<unsigned char> k = fromHex(key);
        std::vector<unsigned char> m = fromHex(salt);
        ASSERT_EQ(0, s.selectCipherAlgorithm(cipher, PRIMARY_CRYPTO));
        s.setMasterKey(k, PRIMARY_CRYPTO);
        s.setMasterSalt(m, PRIMARY_CRYPTO);
        ASSERT_EQ(0, s.deriveSessionEncryptionKey());
        ASSERT_EQ(0, s.deriveSessionSaltingKey());
        ASSERT_EQ(0, s.deriveSessionAuthenticationKey());
    }
    static std::vector<unsigned char> encKey(JLSRTP& s) { return s._session_enc_key; }
    static std::vector<unsigned char> saltKey(JLSRTP& s) { return s._session_salt_key; }
    static std::vector<unsigned char> authKey(JLSRTP& s) { return s._session_auth_key; }

    // The keystream for packet index 0 from the given session key and salt
    static std::vector<unsigned char> keystream(JLSRTP& s, CipherType cipher, const char* key, const char* salt, size_t len)
    {
        std::vector<unsigned char> zeros(len);
        std::vector<unsigned char> out;
        s.selectCipherAlgorithm(cipher, PRIMARY_CRYPTO);
        s._session_enc_key = fromHex(key);
        s._session_salt_key = fromHex(salt);
        s.selectEncryptionKey();
        s.computePacketIV(0);
        s.setPacketIV();
        s.encryptVector(zeros, out);
        return out;
    }
};

// RFC 3711 appendix B.3: the 128-bit key derivation stays as it was
TEST_F(JLSRTPTest, Aes128Kdf)
{
    JLSRTP s(0, "127.0.0.1", 0);
    derive(s, AES_CM_128, "e1f97a0d3e018be0d64fa32c06de4139", "0ec675ad498afeebb6960b3aabe6");
    EXPECT_EQ(fromHex("c61e7a93744f39ee10734afe3ff7a087"), encKey(s));
    EXPECT_EQ(fromHex("30cbbc08863d8c85d49db34a9ae1"), saltKey(s));
    EXPECT_EQ(fromHex("cebe321f6ff7716b6fd4ab49af256a156d38baa4"), authKey(s));
}

// RFC 6188 section 7.2
TEST_F(JLSRTPTest, Aes256Kdf)
{
    JLSRTP s(0, "127.0.0.1", 0);
    derive(s, AES_CM_256, "f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6", "3b04803de51ee7c96423ab5b78d2");
    EXPECT_EQ(fromHex("5ba1064e30ec51613cad926c5a28ef731ec7fb397f70a960653caf06554cd8c4"), encKey(s));
    EXPECT_EQ(fromHex("fa31791685ca444a9e07c6c64e93"), saltKey(s));
    EXPECT_EQ(fromHex("fd9c32d39ed5fbb5a9dc96b30818454d1313dc05"), authKey(s));
}

// RFC 6188 section 7.4
TEST_F(JLSRTPTest, Aes192Kdf)
{
    JLSRTP s(0, "127.0.0.1", 0);
    derive(s, AES_CM_192, "73edc66c4fa15776fb57f9505c17136550ffda71f3e8e5f1", "c8522f3acd4ce86d5add78edbb11");
    EXPECT_EQ(fromHex("31874736a8f1143870c26e4857d8a5b2c4a354407faadabb"), encKey(s));
    EXPECT_EQ(fromHex("2372b82d639b6d8503a47adc0a6c"), saltKey(s));
    EXPECT_EQ(fromHex("355b10973cd95b9eacf4061c7e1a7151e7cfbfcb"), authKey(s));
}

// RFC 6188 sections 7.1 and 7.3: the first and last three keystream blocks
TEST_F(JLSRTPTest, Aes256Keystream)
{
    JLSRTP s(0, "127.0.0.1", 0);
    std::vector<unsigned char> ks = keystream(s, AES_CM_256, "57f82fe3613fd170a85ec93c40b1f0922ec4cb0dc025b58272147cc438944a98",
                                              "f0f1f2f3f4f5f6f7f8f9fafbfcfd", 65282 * 16);
    ASSERT_EQ(65282u * 16, ks.size());
    EXPECT_EQ(fromHex("92bdd28a93c3f52511c677d08b5515a49da71b2378a854f67050756ded165bac63c4868b7096d88421b563b8c94c9a31"),
              std::vector<unsigned char>(ks.begin(), ks.begin() + 48));
    EXPECT_EQ(fromHex("cea518c90fd91ced9cbb18c078a547113dbc4814f4da5f00a08772b63c6a046d6eb246913062a16891433e97dd01a57f"),
              std::vector<unsigned char>(ks.end() - 48, ks.end()));
}

TEST_F(JLSRTPTest, Aes192Keystream)
{
    JLSRTP s(0, "127.0.0.1", 0);
    std::vector<unsigned char> ks = keystream(s, AES_CM_192, "eab234764e517b2d3d160d587d8c86219740f65f99b6bcf7",
                                              "f0f1f2f3f4f5f6f7f8f9fafbfcfd", 65282 * 16);
    ASSERT_EQ(65282u * 16, ks.size());
    EXPECT_EQ(fromHex("35096cba4610028dc1b57503804ce37c5de986291dcce161d5165ec4568f5c9a474a40c77894bc17180202272a4c264d"),
              std::vector<unsigned char>(ks.begin(), ks.begin() + 48));
    EXPECT_EQ(fromHex("d108d1a31a00bad6367ec23eb044b415c8f57129fdeb970b59f917b257662d4ca5dab625811034e8cebdfeb6dc158dd3"),
              std::vector<unsigned char>(ks.end() - 48, ks.end()));
}

struct SrtpSuite {
    CipherType cipher;
    HashType hash;
    const char* name;
    size_t inline_len; // base64 key||salt
    size_t tag_len;
};

class JLSRTPRoundTrip : public ::testing::TestWithParam<SrtpSuite> {};

// A sender's key||salt as the peer's a=crypto line carries it, and a
// packet it protects that the peer then authenticates and decrypts
TEST_P(JLSRTPRoundTrip, EncryptDecrypt)
{
    const SrtpSuite& suite = GetParam();
    JLSRTP tx(0x12345678, "127.0.0.1", 0);
    JLSRTP rx(0x12345678, "127.0.0.1", 0);
    std::string mks;

    ASSERT_EQ(0, tx.selectCipherAlgorithm(suite.cipher, PRIMARY_CRYPTO));
    ASSERT_EQ(0, tx.selectHashAlgorithm(suite.hash, PRIMARY_CRYPTO));
    ASSERT_EQ(0, tx.generateMasterKey(PRIMARY_CRYPTO));
    ASSERT_EQ(0, tx.generateMasterSalt(PRIMARY_CRYPTO));
    ASSERT_EQ(0, tx.encodeMasterKeySalt(mks, PRIMARY_CRYPTO));
    EXPECT_EQ(suite.inline_len, mks.size());
    EXPECT_EQ(suite.name, tx.getCryptoSuite());

    ASSERT_EQ(0, rx.decodeMasterKeySalt(mks, PRIMARY_CRYPTO));
    ASSERT_EQ(0, rx.selectCipherAlgorithm(suite.cipher, PRIMARY_CRYPTO));
    ASSERT_EQ(0, rx.selectHashAlgorithm(suite.hash, PRIMARY_CRYPTO));
    EXPECT_EQ(tx.getMasterKey(PRIMARY_CRYPTO), rx.getMasterKey(PRIMARY_CRYPTO));
    EXPECT_EQ(tx.getMasterSalt(PRIMARY_CRYPTO), rx.getMasterSalt(PRIMARY_CRYPTO));

    for (JLSRTP* s : {&tx, &rx}) {
        s->setSrtpHeaderSize(12);
        s->setSrtpPayloadSize(160);
        ASSERT_EQ(0, s->deriveSessionEncryptionKey());
        ASSERT_EQ(0, s->deriveSessionSaltingKey());
        ASSERT_EQ(0, s->deriveSessionAuthenticationKey());
        ASSERT_EQ(0, s->selectEncryptionKey());
        ASSERT_EQ(0, s->resetCipherState());
    }

    for (unsigned short seq = 1000; seq < 1003; seq++) {
        std::vector<unsigned char> header = {0x80, 0x00, static_cast<unsigned char>(seq >> 8), static_cast<unsigned char>(seq),
                                             0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78};
        std::vector<unsigned char> payload(160);
        for (size_t i = 0; i < payload.size(); i++) {
            payload[i] = static_cast<unsigned char>(i + seq);
        }
        std::vector<unsigned char> packet;
        ASSERT_EQ(0, tx.processOutgoingPacket(seq, header, payload, packet));
        ASSERT_EQ(12 + 160 + suite.tag_len, packet.size());
        EXPECT_NE(payload, std::vector<unsigned char>(packet.begin() + 12, packet.begin() + 172));

        std::vector<unsigned char> rx_header;
        std::vector<unsigned char> rx_payload;
        std::vector<unsigned char> tampered = packet;
        tampered[20] ^= 1;
        EXPECT_EQ(-1, rx.processIncomingPacket(seq, tampered, rx_header, rx_payload));
        ASSERT_EQ(0, rx.processIncomingPacket(seq, packet, rx_header, rx_payload));
        EXPECT_EQ(header, rx_header);
        EXPECT_EQ(payload, rx_payload);
    }
}

INSTANTIATE_TEST_SUITE_P(Suites, JLSRTPRoundTrip, ::testing::Values(
    SrtpSuite{AES_CM_128, HMAC_SHA1_80, "AES_CM_128_HMAC_SHA1_80", 40, 10},
    SrtpSuite{AES_CM_128, HMAC_SHA1_32, "AES_CM_128_HMAC_SHA1_32", 40, 4},
    SrtpSuite{AES_CM_192, HMAC_SHA1_80, "AES_192_CM_HMAC_SHA1_80", 52, 10},
    SrtpSuite{AES_CM_192, HMAC_SHA1_32, "AES_192_CM_HMAC_SHA1_32", 52, 4},
    SrtpSuite{AES_CM_256, HMAC_SHA1_80, "AES_256_CM_HMAC_SHA1_80", 64, 10},
    SrtpSuite{AES_CM_256, HMAC_SHA1_32, "AES_256_CM_HMAC_SHA1_32", 64, 4}));

// The key||salt of an a=crypto line: an AES key of 16, 24 or 32 bytes
// (or of the length asked for) and a 14-byte salt, or nothing is decoded
TEST(JLSRTPKey, DecodeMasterKeySaltChecksTheLength)
{
    JLSRTP rx(0x12345678, "127.0.0.1", 0);
    std::string aes128 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0e";
    std::string aes192 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSY=";
    std::string aes256 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLg==";
    std::vector<std::string> bad = {
        "",
        "AQIDBAUGBwgJCgsMDQ4=",                                             // a salt alone
        "AQIDBAUGBwgJCgsMDQ4PEBESExQ=",                                     // a 6-byte key
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0=",                         // 15 bytes
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHw==",                     // 17 bytes
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywt",     // 31 bytes
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8=", // 33 bytes
    };

    EXPECT_EQ(0, rx.decodeMasterKeySalt(aes192, PRIMARY_CRYPTO));
    EXPECT_EQ(24U, rx.getMasterKey(PRIMARY_CRYPTO).size());
    EXPECT_EQ(0, rx.decodeMasterKeySalt(aes256, PRIMARY_CRYPTO, JLSRTP_AES_256_KEY_LENGTH));
    EXPECT_EQ(32U, rx.getMasterKey(PRIMARY_CRYPTO).size());
    ASSERT_EQ(0, rx.decodeMasterKeySalt(aes128, PRIMARY_CRYPTO));
    std::vector<unsigned char> key = rx.getMasterKey(PRIMARY_CRYPTO);
    std::vector<unsigned char> salt = rx.getMasterSalt(PRIMARY_CRYPTO);
    EXPECT_EQ(16U, key.size());
    EXPECT_EQ(14U, salt.size());

    for (std::string mks : bad) {
        EXPECT_EQ(-1, rx.decodeMasterKeySalt(mks, PRIMARY_CRYPTO)) << mks;
    }
    // A key of another suite's length
    EXPECT_EQ(-1, rx.decodeMasterKeySalt(aes128, PRIMARY_CRYPTO, JLSRTP_AES_256_KEY_LENGTH));
    EXPECT_EQ(-1, rx.decodeMasterKeySalt(aes256, PRIMARY_CRYPTO, JLSRTP_ENCRYPTION_KEY_LENGTH));
    EXPECT_EQ(key, rx.getMasterKey(PRIMARY_CRYPTO));
    EXPECT_EQ(salt, rx.getMasterSalt(PRIMARY_CRYPTO));

    // The key it kept still derives the session keys
    ASSERT_EQ(0, rx.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO));
    EXPECT_EQ(0, rx.deriveSessionEncryptionKey());
    EXPECT_EQ(0, rx.deriveSessionSaltingKey());
    EXPECT_EQ(0, rx.deriveSessionAuthenticationKey());
}

#endif // GTEST

#else // !USE_OPENSSL && !USE_WOLFSSL

#include "jlsrtp.hpp"

JLSRTP::JLSRTP()
{
}

JLSRTP::JLSRTP(unsigned int ssrc, const std::string& ipAddress, unsigned short port)
{
}

JLSRTP::~JLSRTP()
{
}

#endif // USE_OPENSSL || USE_WOLFSSL

