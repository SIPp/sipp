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
 *  Author: Jeannot Langlois (jeannot.langlois@gmail.com) -- 2016-2018
 */

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

// --------------- PRIVATE METHODS ----------------

bool JLSRTP::isBase64(unsigned char c)
{
    return (isalnum(c) ||
           (c == '+') ||
           (c == '/'));
}

int JLSRTP::resetPseudoRandomState(std::vector<unsigned char> iv)
{
    int ivSize = 0;

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
    int num_loops = 0;
    AES_KEY aes_key;
    std::vector<unsigned char> block;
    std::vector<unsigned char> input;
    int ivSize = 0;
    int keySize = 0;
    int retVal = 0;

    switch (_active_crypto)
    {
        case PRIMARY_CRYPTO:
        {
            ivSize = iv.size();
            keySize = _primary_crypto.master_key.size();

            assert(ivSize == JLSRTP_SALTING_KEY_LENGTH);
            assert(keySize == JLSRTP_ENCRYPTION_KEY_LENGTH);
            if (ivSize == JLSRTP_SALTING_KEY_LENGTH)
            {
                if (keySize == JLSRTP_ENCRYPTION_KEY_LENGTH)
                {
                    input.resize(AES_BLOCK_SIZE, 0);
                    output.clear();

                    // Determine how many AES_BLOCK_SIZE-byte encryption loops will be necessary to achieve at least n/8 bytes of pseudorandom ciphertext
                    num_loops = (n % JLSRTP_PSEUDORANDOM_BITS) ? ((n / JLSRTP_PSEUDORANDOM_BITS) + 1) : (n / JLSRTP_PSEUDORANDOM_BITS);

                    // Set encryption key
                    rc = AES_set_encrypt_key(_primary_crypto.master_key.data(), 128, &aes_key);
                    if (rc >= 0)
                    {
                        // Reset IV/counter state
                        resetPseudoRandomState(iv);

                        for (int i = 0; i < num_loops; i++)
                        {
                            // Encrypt given _pseudorandomstate.ivec input using aes_key to block
                            block.clear();
                            block.resize(AES_BLOCK_SIZE, 0);
                            AES_ctr128_encrypt(input.data(), block.data(), AES_BLOCK_SIZE, &aes_key, _pseudorandomstate.ivec, _pseudorandomstate.ecount, &_pseudorandomstate.num);
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
            assert(keySize == JLSRTP_ENCRYPTION_KEY_LENGTH);
            if (ivSize == JLSRTP_SALTING_KEY_LENGTH)
            {
                if (keySize == JLSRTP_ENCRYPTION_KEY_LENGTH)
                {
                    input.resize(AES_BLOCK_SIZE, 0);
                    output.clear();

                    // Determine how many AES_BLOCK_SIZE-byte encryption loops will be necessary to achieve at least n/8 bytes of pseudorandom ciphertext
                    num_loops = (n % JLSRTP_PSEUDORANDOM_BITS) ? ((n / JLSRTP_PSEUDORANDOM_BITS) + 1) : (n / JLSRTP_PSEUDORANDOM_BITS);

                    // Set encryption key
                    rc = AES_set_encrypt_key(_secondary_crypto.master_key.data(), 128, &aes_key);
                    if (rc >= 0)
                    {
                        // Reset IV/counter state
                        resetPseudoRandomState(iv);

                        for (int i = 0; i < num_loops; i++)
                        {
                            // Encrypt given _pseudorandomstate.ivec input using aes_key to block
                            block.clear();
                            block.resize(AES_BLOCK_SIZE, 0);
                            AES_ctr128_encrypt(input.data(), block.data(), AES_BLOCK_SIZE, &aes_key, _pseudorandomstate.ivec, _pseudorandomstate.ecount, &_pseudorandomstate.num);
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
    int i = 0;
    int j = 0;

    shifted_vec.clear();
    shifted_vec.resize(original_vec.size(), 0);

    for (i = shift_value, j = 0; i < original_vec.size(); i++, j++) {
        shifted_vec[j] = original_vec[i];
    }

    return 0;
}

int JLSRTP::shiftVectorRight(std::vector<unsigned char> &shifted_vec, std::vector<unsigned char> &original_vec, int shift_value)
{
    int i = 0;
    int j = 0;

    shifted_vec.clear();
    shifted_vec.resize(original_vec.size(), 0);

    for (i = shift_value, j = 0; i < shifted_vec.size(); i++, j++) {
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
        result.resize(a.size(), 0);
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
    result.resize(16, 0);

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
    result.resize(16, 0);

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
    result.resize(4, 0);

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

    return 0;
}

unsigned long JLSRTP::determineV(unsigned short SEQ)
{
    unsigned long v = 0;

    if (_s_l < 32768)
    {
        if ((SEQ - _s_l) > 32768)
        {
            v = _ROC-1;
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
    int ivSize = 0;

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
    int saltSize = 0;

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
    for (int i = 0; i < _packetIV.size(); i++)
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
                    {
                        assert(_aes_key.rounds != 0);
                        if (_aes_key.rounds != 0)
                        {
                            ciphertext_output.resize(invdata.size(), 0);
                            resetCipherBlockOffset();
                            resetCipherOutputBlock();
                            resetCipherBlockCounter();
                            AES_ctr128_encrypt(invdata.data(), ciphertext_output.data(), invdata.size(), &_aes_key, _cipherstate.ivec, _cipherstate.ecount, &_cipherstate.num);
                            retVal = 0;
                        }
                        else
                        {
                            retVal = -2;
                        }
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
                    {
                        assert(_aes_key.rounds != 0);
                        if (_aes_key.rounds != 0)
                        {
                            ciphertext_output.resize(invdata.size(), 0);
                            resetCipherBlockOffset();
                            resetCipherOutputBlock();
                            resetCipherBlockCounter();
                            AES_ctr128_encrypt(invdata.data(), ciphertext_output.data(), invdata.size(), &_aes_key, _cipherstate.ivec, _cipherstate.ecount, &_cipherstate.num);
                            retVal = 0;
                        }
                        else
                        {
                            retVal = -2;
                        }
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
                    {
                        assert(_aes_key.rounds != 0);
                        if (_aes_key.rounds != 0)
                        {
                            outvdata.resize(ciphertext_input.size(), 0);
                            resetCipherBlockOffset();
                            resetCipherOutputBlock();
                            resetCipherBlockCounter();
                            AES_ctr128_encrypt(ciphertext_input.data(), outvdata.data(), ciphertext_input.size(), &_aes_key, _cipherstate.ivec, _cipherstate.ecount, &_cipherstate.num);
                            retVal = 0;
                        }
                        else
                        {
                            retVal = -2;
                        }
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
                    {
                        assert(_aes_key.rounds != 0);
                        if (_aes_key.rounds != 0)
                        {
                            outvdata.resize(ciphertext_input.size(), 0);
                            resetCipherBlockOffset();
                            resetCipherOutputBlock();
                            resetCipherBlockCounter();
                            AES_ctr128_encrypt(ciphertext_input.data(), outvdata.data(), ciphertext_input.size(), &_aes_key, _cipherstate.ivec, _cipherstate.ecount, &_cipherstate.num);
                            retVal = 0;
                        }
                        else
                        {
                            retVal = -2;
                        }
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
    unsigned char* digest = NULL;
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
            digest = HMAC(EVP_sha1(), _session_auth_key.data(), _session_auth_key.size(), /*data.data()*/ auth_portion.data(), /*data.size()*/ auth_portion.size(), NULL, NULL);

            if (digest != NULL)
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
    int header_payload_size = 0;

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
    int in_len = encoded_string.size();
    std::vector<unsigned char> ret;

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

// --------------- PUBLIC METHODS ----------------

void JLSRTP::resetCryptoContext(unsigned int ssrc, std::string ipAddress, unsigned short port)
{
    _id.ssrc = ssrc;
    _id.address = ipAddress;
    _id.port = port;
    _ROC = 0;
    _s_l = 0;
    _primary_crypto.cipher_algorithm = AES_CM_128;
    _primary_crypto.hmac_algorithm = HMAC_SHA1_80;
    _primary_crypto.MKI = 0;
    _primary_crypto.MKI_length = 0;
    _primary_crypto.active_MKI = 0;
    _primary_crypto.master_key.resize(JLSRTP_ENCRYPTION_KEY_LENGTH, 0);
    _primary_crypto.master_key_counter = 0;
    _primary_crypto.n_e = _primary_crypto.master_key.size();
    _primary_crypto.n_a = JLSRTP_AUTHENTICATION_KEY_LENGTH;
    _primary_crypto.master_salt.resize(JLSRTP_SALTING_KEY_LENGTH, 0);
    _primary_crypto.master_key_derivation_rate = 0;
    _primary_crypto.master_mki_value = 0;
    _primary_crypto.n_s = _primary_crypto.master_salt.size();
    _primary_crypto.tag = 0;
    _secondary_crypto.cipher_algorithm = AES_CM_128;
    _secondary_crypto.hmac_algorithm = HMAC_SHA1_80;
    _secondary_crypto.MKI = 0;
    _secondary_crypto.MKI_length = 0;
    _secondary_crypto.active_MKI = 0;
    _secondary_crypto.master_key.resize(JLSRTP_ENCRYPTION_KEY_LENGTH, 0);
    _secondary_crypto.master_key_counter = 0;
    _secondary_crypto.n_e = _secondary_crypto.master_key.size();
    _secondary_crypto.n_a = JLSRTP_AUTHENTICATION_KEY_LENGTH;
    _secondary_crypto.master_salt.resize(JLSRTP_SALTING_KEY_LENGTH, 0);
    _secondary_crypto.master_key_derivation_rate = 0;
    _secondary_crypto.master_mki_value = 0;
    _secondary_crypto.n_s = _secondary_crypto.master_salt.size();
    _secondary_crypto.tag = 0;
    _session_enc_key.resize(JLSRTP_ENCRYPTION_KEY_LENGTH, 0);
    _session_salt_key.resize(JLSRTP_SALTING_KEY_LENGTH, 0);
    _session_auth_key.resize(JLSRTP_AUTHENTICATION_KEY_LENGTH, 0);
    _packetIV.resize(JLSRTP_SALTING_KEY_LENGTH, 0);
    memset(_pseudorandomstate.ivec, 0, sizeof(_pseudorandomstate.ivec));
    _pseudorandomstate.num = 0;
    memset(_pseudorandomstate.ecount, 0, sizeof(_pseudorandomstate.ecount));
    memset(_cipherstate.ivec, 0, sizeof(_cipherstate.ivec));
    _cipherstate.num = 0;
    memset(_cipherstate.ecount, 0, sizeof(_cipherstate.ecount));
    memset(_aes_key.rd_key, 0, sizeof(_aes_key.rd_key));
    _aes_key.rounds = 0;
    _srtp_header_size = JLSRTP_SRTP_DEFAULT_HEADER_SIZE;
    _srtp_payload_size = 0;
    _active_crypto = PRIMARY_CRYPTO;
}

int JLSRTP::resetCipherState()
{
    int ivSize = 0;

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
    std::vector<unsigned char> input_vector;		// Input vector (built from applicable keyid_XXXs)
    std::vector<unsigned char> keyid_encryption;
    int saltSize = 0;
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
                keyid_encryption.resize(7, 0);
                keyid_encryption.push_back(JLSRTP_KEY_ENCRYPTION_LABEL);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);

                xorVector(keyid_encryption, _primary_crypto.master_salt, input_vector);

                retVal = pseudorandomFunction(input_vector, 128, _session_enc_key);
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
                keyid_encryption.resize(7, 0);
                keyid_encryption.push_back(JLSRTP_KEY_ENCRYPTION_LABEL);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);
                keyid_encryption.push_back(0x00);

                xorVector(keyid_encryption, _secondary_crypto.master_salt, input_vector);

                retVal = pseudorandomFunction(input_vector, 128, _session_enc_key);
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
    std::vector<unsigned char> input_vector;		// Input vector (built from applicable keyid_XXXs)
    std::vector<unsigned char> keyid_salting;
    int saltSize = 0;
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
                keyid_salting.resize(7, 0);
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
                keyid_salting.resize(7, 0);
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
    std::vector<unsigned char> input_vector;		// Input vector (built from applicable keyid_XXXs)
    std::vector<unsigned char> keyid_authentication;
    int saltSize = 0;
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
                keyid_authentication.resize(7, 0);
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
                keyid_authentication.resize(7, 0);
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
    for (int i = 0; i < _session_enc_key.size(); i++)
    {
        printf("%02x", _session_enc_key[i]);
    }
    printf("]\n");
}

void JLSRTP::displaySessionSaltingKey()
{
    //printf("session_salting_key[] size: %d\n", _session_salt_key.size());

    printf("_session_salt_key          : [");
    for (int i = 0; i < _session_salt_key.size(); i++)
    {
        printf("%02x", _session_salt_key[i]);
    }
    printf("]\n");
}

void JLSRTP::displaySessionAuthenticationKey()
{
    //printf("session_authentication_key[] size: %d\n", _session_auth_key.size());

    printf("_session_auth_key          : [");
    for (int i = 0; i < _session_auth_key.size(); i++)
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
        rc = AES_set_encrypt_key(_session_enc_key.data(), 128, &_aes_key);
        if (rc < 0)
        {
            return -2;
        }

        return  0;
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
        rc = AES_set_encrypt_key(_session_enc_key.data(), 128, &_aes_key);
        if (rc < 0)
        {
            return -2;
        }

        return 0;
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
    for (int i = 0; i < authtag.size(); i++)
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
                //for (int i = 0; i < srtp_payload.size(); i++) {
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
                        //for (int i = 0; i < srtp_payload.size(); i++) {
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

std::string JLSRTP::getCryptoSuite()
{
    std::string cryptosuite;

    switch (_active_crypto)
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
            //for (int i = 0; i < concat.size(); i++)
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
            //for (int i = 0; i < concat.size(); i++)
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

int JLSRTP::decodeMasterKeySalt(std::string &mks, ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    int retVal = -1;
    std::vector<unsigned char> concat;
    int split_pos = 0;
    std::vector<unsigned char>::iterator it_begin;
    std::vector<unsigned char>::iterator it_middle;
    std::vector<unsigned char>::iterator it_end;
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
            concat = base64Decode(mks);

            //std::cout << "decodeMasterKeySalt(): concat:[";
            //for (int i = 0; i < concat.size(); i++)
            //{
            //    printf("%02X", concat[i]);
            //}
            //std::cout << "]" << std::endl;

            split_pos = _primary_crypto.n_e;
            it_begin = concat.begin();
            it_middle = concat.begin();
            it_end = concat.end();

            std::advance(it_middle, split_pos);
            _primary_crypto.master_key.assign(it_begin, it_middle);
            _primary_crypto.master_salt.assign(it_middle, it_end);

            //std::cout << "decodeMasterKeySalt():  _masterKey:[";
            //for (int i = 0; i < _primary_crypto.master_key.size(); i++)
            //{
            //    printf("%02X", _primary_crypto.master_key[i]);
            //}
            //std::cout << "] _masterSalt:[";
            //for (int i = 0; i < _primary_crypto.master_salt.size(); i++)
            //{
            //    printf("%02X", _primary_crypto.master_salt[i]);
            //}
            //std::cout << "]" << std::endl;
            retVal = 0;
        }
        break;

        case SECONDARY_CRYPTO:
        {
            concat = base64Decode(mks);

            //std::cout << "decodeMasterKeySalt(): concat:[";
            //for (int i = 0; i < concat.size(); i++)
            //{
            //    printf("%02X", concat[i]);
            //}
            //std::cout << "]" << std::endl;

            split_pos = _secondary_crypto.n_e;
            it_begin = concat.begin();
            it_middle = concat.begin();
            it_end = concat.end();

            std::advance(it_middle, split_pos);
            _secondary_crypto.master_key.assign(it_begin, it_middle);
            _secondary_crypto.master_salt.assign(it_middle, it_end);

            //std::cout << "decodeMasterKeySalt():  _masterKey:[";
            //for (int i = 0; i < _secondary_crypto.master_key.size(); i++)
            //{
            //    printf("%02X", _secondary_crypto.master_key[i]);
            //}
            //std::cout << "] _masterSalt:[";
            //for (int i = 0; i < _secondary_crypto.master_salt.size(); i++)
            //{
            //    printf("%02X", _secondary_crypto.master_salt[i]);
            //}
            //std::cout << "]" << std::endl;
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
    for (int i = 0; i < _primary_crypto.master_key.size(); i++)
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
    for (int i = 0; i < _primary_crypto.master_salt.size(); i++)
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
    for (int i = 0; i < _secondary_crypto.master_key.size(); i++)
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
    for (int i = 0; i < _secondary_crypto.master_salt.size(); i++)
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
    for (int i = 0; i < _session_enc_key.size(); i++)
    {
        printf("%02x", _session_enc_key[i]);
    }
    printf("]\n");
    printf("_session_salt_key                            : [");
    for (int i = 0; i < _session_salt_key.size(); i++)
    {
        printf("%02x", _session_salt_key[i]);
    }
    printf("]\n");
    printf("_session_auth_key                            : [");
    for (int i = 0; i < _session_auth_key.size(); i++)
    {
        printf("%02x", _session_auth_key[i]);
    }
    printf("]\n");
    printf("_packet_iv                                   : [");
    for (int i = 0; i < _packetIV.size(); i++)
    {
        printf("%02x", _packetIV[i]);
    }
    printf("]\n");

    std::cout << "_pseudorandomstate.ivec                      : [";
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        printf("%02x", _pseudorandomstate.ivec[i]);
    }
    std::cout << "]" << std::endl;
    std::cout << "_pseudorandomstate.num                       : " << _pseudorandomstate.num << std::endl;
    std::cout << "_pseudorandomstate.ecount                    : [";
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
       printf("%02x", _pseudorandomstate.ecount[i]);
    }
    std::cout << "]" << std::endl;

    std::cout << "_cipherstate.ivec                            : [";
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        printf("%02x", _cipherstate.ivec[i]);
    }
    std::cout << "]" << std::endl;
    std::cout << "_cipherstate.num                             : " << _cipherstate.num << std::endl;
    std::cout << "_cipherstate.ecount                          : [";
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
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
    for (int i = 0; i < _primary_crypto.master_key.size(); i++)
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
    for (int i = 0; i < _primary_crypto.master_salt.size(); i++)
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
    for (int i = 0; i < _secondary_crypto.master_key.size(); i++)
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
    for (int i = 0; i < _secondary_crypto.master_salt.size(); i++)
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
    for (int i = 0; i < _session_enc_key.size(); i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_session_enc_key[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;
    oss << "_session_salt_key                      : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (int i = 0; i < _session_salt_key.size(); i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_session_salt_key[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;
    oss << "_session_auth_key                      : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (int i = 0; i < _session_auth_key.size(); i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_session_auth_key[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;
    oss << "_packet_iv                             : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (int i = 0; i < _packetIV.size(); i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_packetIV[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;

    oss << "_pseudorandomstate.ivec                      : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_pseudorandomstate.ivec[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;
    oss << "_pseudorandomstate.num                       : " << _pseudorandomstate.num << std::endl;
    oss << "_pseudorandomstate.ecount                    : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_pseudorandomstate.ecount[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;

    oss << "_cipherstate.ivec                            : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        oss << std::setw(2) << std::setfill('0');
        oss << static_cast<int>(_cipherstate.ivec[i]);
    }
    oss.unsetf(std::ios::hex);
    oss << "]" << std::endl;
    oss << "_cipherstate.num                             : " << _cipherstate.num << std::endl;
    oss << "_cipherstate.ecount                          : [";
    oss.setf(std::ios::hex, std::ios::basefield);
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
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

    CipherType    			cipher_algorithm = INVALID_CIPHER;
    HashType    			hmac_algorithm = INVALID_HASH;
    bool           			MKI = false;
    unsigned int   			MKI_length = 0;
    unsigned long  			active_MKI = 0;
    std::vector<unsigned char> 		master_key;
    unsigned long  			master_key_counter = 0;
    unsigned short 			n_e = 0;
    unsigned short 			n_a = 0;
    std::vector<unsigned char> 		master_salt;
    unsigned long  			master_key_derivation_rate = 0;
    unsigned long  			master_mki_value = 0;
    unsigned short 			n_s = 0;
    unsigned int                    	tag = 0;

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
    memcpy(_aes_key.rd_key, that._aes_key.rd_key, sizeof(_aes_key.rd_key));
    _aes_key.rounds = that._aes_key.rounds;
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
        (memcmp(_aes_key.rd_key, that._aes_key.rd_key, sizeof(_aes_key.rd_key)) == 0) &&
        (_aes_key.rounds == that._aes_key.rounds) &&
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
    resetCryptoContext(0xCA110000, "127.0.0.1", 0);
}

JLSRTP::JLSRTP(unsigned int ssrc, std::string ipAddress, unsigned short port)
{
    resetCryptoContext(ssrc, ipAddress, port);
}

JLSRTP::~JLSRTP()
{
    RAND_cleanup();
}


