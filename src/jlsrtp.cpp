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
#include <utility>

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

/* Made when it is first needed: most calls never use SRTP, and each
 * context costs a cipher fetch. */
bool AESCipher::make()
{
    if (!ctx) {
        ctx.reset(EVP_CIPHER_CTX_new());
        if (ctx && EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr, nullptr, nullptr) != 1) {
            ctx.reset();
        }
    }
    return ctx != nullptr;
}

int AESCipher::setKey(const std::vector<unsigned char>& key)
{
    return setKey(key.data(), key.size());
}

int AESCipher::setKey(const unsigned char *key, size_t length)
{
    const EVP_CIPHER* cipher = nullptr; // keep the context's cipher

    if (!make()) {
        return 0;
    }

    if (EVP_CIPHER_CTX_key_length(ctx.get()) != static_cast<int>(length)) {
        cipher = aesEcbCipher(length);
        if (!cipher) {
            return 0;
        }
    }
    return EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, key, nullptr);
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

int JLSRTP::resetPseudoRandomState(const std::vector<unsigned char> &iv)
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

int JLSRTP::pseudorandomFunction(const std::vector<unsigned char> &iv, int n, std::vector<unsigned char> &output)
{
    int rc = 0;
    unsigned int num_loops = 0;
    std::vector<unsigned char> block;
    std::vector<unsigned char> input;
    unsigned int ivSize = 0;
    unsigned int keySize = 0;
    int retVal = 0;

    switch (_active_crypto) {
    case PRIMARY_CRYPTO: {
        ivSize = iv.size();
        keySize = _primary_crypto.master_key.size();

        assert(ivSize == JLSRTP_SALTING_KEY_LENGTH);
        assert(aesEcbCipher(keySize));
        if (ivSize == JLSRTP_SALTING_KEY_LENGTH) {
            if (aesEcbCipher(keySize)) {
                input.resize(AES_BLOCK_SIZE);
                output.clear();

                // Determine how many AES_BLOCK_SIZE-byte encryption loops will be necessary to achieve at least n/8 bytes of pseudorandom ciphertext
                num_loops = (n % JLSRTP_PSEUDORANDOM_BITS) ? ((n / JLSRTP_PSEUDORANDOM_BITS) + 1)
                                                           : (n / JLSRTP_PSEUDORANDOM_BITS);

                // Set encryption key
                rc = setAESPseudoRandomFunctionKey(_active_crypto);
                if (rc == 0) {
                    // Reset IV/counter state
                    resetPseudoRandomState(iv);

                    for (unsigned int i = 0; i < num_loops; i++) {
                        // Encrypt given _pseudorandomstate.ivec input using aes_key to block
                        block.clear();
                        block.resize(AES_BLOCK_SIZE);
                        AES_ctr128_pseudorandom_EVPencrypt(input.data(), block.data(), AES_BLOCK_SIZE,
                                                           _pseudorandomstate.ivec, _pseudorandomstate.ecount,
                                                           &_pseudorandomstate.num);
                        output.insert(output.end(), block.begin(), block.end());
                    }

                    // Truncate output to n/8 bytes
                    output.resize(n / 8);

                    retVal = 0;
                } else {
                    retVal = -3;
                }
            } else {
                retVal = -2;
            }
        } else {
            retVal = -1;
        }
    } break;

    case SECONDARY_CRYPTO: {
        ivSize = iv.size();
        keySize = _secondary_crypto.master_key.size();

        assert(ivSize == JLSRTP_SALTING_KEY_LENGTH);
        assert(aesEcbCipher(keySize));
        if (ivSize == JLSRTP_SALTING_KEY_LENGTH) {
            if (aesEcbCipher(keySize)) {
                input.resize(AES_BLOCK_SIZE);
                output.clear();

                // Determine how many AES_BLOCK_SIZE-byte encryption loops will be necessary to achieve at least n/8 bytes of pseudorandom ciphertext
                num_loops = (n % JLSRTP_PSEUDORANDOM_BITS) ? ((n / JLSRTP_PSEUDORANDOM_BITS) + 1)
                                                           : (n / JLSRTP_PSEUDORANDOM_BITS);

                // Set encryption key
                rc = setAESPseudoRandomFunctionKey(_active_crypto);
                if (rc == 0) {
                    // Reset IV/counter state
                    resetPseudoRandomState(iv);

                    for (unsigned int i = 0; i < num_loops; i++) {
                        // Encrypt given _pseudorandomstate.ivec input using aes_key to block
                        block.clear();
                        block.resize(AES_BLOCK_SIZE);
                        AES_ctr128_pseudorandom_EVPencrypt(input.data(), block.data(), AES_BLOCK_SIZE,
                                                           _pseudorandomstate.ivec, _pseudorandomstate.ecount,
                                                           &_pseudorandomstate.num);
                        output.insert(output.end(), block.begin(), block.end());
                    }

                    // Truncate output to n/8 bytes
                    output.resize(n / 8);

                    retVal = 0;
                } else {
                    retVal = -3;
                }
            } else {
                retVal = -2;
            }
        } else {
            retVal = -1;
        }
    } break;

    default: {
        retVal = -4;
    } break;
    }

    return retVal;
}

int JLSRTP::shiftVectorRight(std::vector<unsigned char> &shifted_vec, std::vector<unsigned char> &original_vec,
                             int shift_value)
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

    if (a.size() == b.size()) {
        result.clear();
        result.resize(a.size());
        std::transform(a.begin(), a.end(), b.begin(), result.begin(), std::bit_xor<unsigned char>());
        retVal = 0;
    } else {
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

int JLSRTP::setAESPseudoRandomFunctionKey(ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/)
{
    ActiveCrypto active_crypto = INVALID_CRYPTO;
    int rc = 0;
    int retVal = 0;

    if (_pseudorandomstate.cipher.make())
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
                rc = _pseudorandomstate.cipher.setKey(_primary_crypto.master_key);
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
                rc = _pseudorandomstate.cipher.setKey(_secondary_crypto.master_key);
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
                    rc = _pseudorandomstate.cipher.setKey(_primary_crypto.master_key);
                    if (rc == 1)
                    {
                        rc = EVP_EncryptUpdate(_pseudorandomstate.cipher.get(), ecount_buf, &nb, counter, AES_BLOCK_SIZE);
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
                    rc = _pseudorandomstate.cipher.setKey(_secondary_crypto.master_key);
                    if (rc == 1)
                    {
                        rc = EVP_EncryptUpdate(_pseudorandomstate.cipher.get(), ecount_buf, &nb, counter, AES_BLOCK_SIZE);
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

// --------------- PUBLIC METHODS ----------------

void JLSRTP::resetCryptoContext(unsigned int ssrc, std::string ipAddress, unsigned short port)
{
    _id.ssrc = ssrc;
    _id.address = std::move(ipAddress);
    _id.port = port;
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
    memset(_pseudorandomstate.ivec, 0, sizeof(_pseudorandomstate.ivec));
    _pseudorandomstate.num = 0;
    memset(_pseudorandomstate.ecount, 0, sizeof(_pseudorandomstate.ecount));
    _srtp_header_size = JLSRTP_SRTP_DEFAULT_HEADER_SIZE;
    _srtp_payload_size = 0;
    _active_crypto = PRIMARY_CRYPTO;
}

int JLSRTP::resetCipherState()
{
    unsigned int saltSize = 0;

    saltSize = _session_salt_key.size();
    if (saltSize == JLSRTP_SALTING_KEY_LENGTH) {
        return 0;
    } else {
        return -1;
    }
}

void JLSRTP::freeCiphers()
{
    _pseudorandomstate.cipher.free();
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
    assert(!_session_enc_key.empty());
    if (!_session_enc_key.empty()) {
        /* the stream that takes the key sets it in its own AES context */
        if (aesEcbCipher(_session_enc_key.size())) {
            return 0;
        }

        return -2;
    } else {
        return -1;
    }
}

int JLSRTP::selectDecryptionKey()
{
    assert(!_session_enc_key.empty());
    if (!_session_enc_key.empty()) {
        /* the stream that takes the key sets it in its own AES context */
        if (aesEcbCipher(_session_enc_key.size())) {
            return 0;
        }

        return -2;
    } else {
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
    _id.address = std::move(ipAddress);
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

unsigned int JLSRTP::getCryptoTag(ActiveCrypto crypto_attrib /*= ACTIVE_CRYPTO*/) const
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
    std::cout << "_id                                          : " << "(" << _id.ssrc << ", " << _id.address << ", "
              << _id.port << ")" << std::endl;
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

    std::cout << "_srtp_header_size                            : " << _srtp_header_size << std::endl;
    std::cout << "_srtp_payload_size                           : " << _srtp_payload_size << std::endl;
    std::cout << "_active_crypto                               : " << _active_crypto << std::endl;
}

std::string JLSRTP::dumpCryptoContext()
{
    std::ostringstream oss;

    oss.str("");

    oss << "_id                                          : " << "(" << _id.ssrc << ", " << _id.address << ", "
        << _id.port << ")" << std::endl;
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
    std::swap(_primary_crypto, _secondary_crypto);
    return 0;
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
    memcpy(_pseudorandomstate.ivec, that._pseudorandomstate.ivec, sizeof(_pseudorandomstate.ivec));
    _pseudorandomstate.num = that._pseudorandomstate.num;
    memcpy(_pseudorandomstate.ecount, that._pseudorandomstate.ecount, sizeof(_pseudorandomstate.ecount));
    _srtp_header_size = that._srtp_header_size;
    _srtp_payload_size = that._srtp_payload_size;
    _active_crypto = that._active_crypto;

    return *this;
}

bool JLSRTP::operator==(const JLSRTP& that)
{
    if ((_id.ssrc == that._id.ssrc) && (_id.address == that._id.address) && (_id.port == that._id.port) &&
        (_primary_crypto.cipher_algorithm == that._primary_crypto.cipher_algorithm) &&
        (_primary_crypto.hmac_algorithm == that._primary_crypto.hmac_algorithm) &&
        (_primary_crypto.MKI == that._primary_crypto.MKI) &&
        (_primary_crypto.MKI_length == that._primary_crypto.MKI_length) &&
        (_primary_crypto.active_MKI == that._primary_crypto.active_MKI) &&
        (_primary_crypto.master_key == that._primary_crypto.master_key) &&
        (_primary_crypto.master_key_counter == that._primary_crypto.master_key_counter) &&
        (_primary_crypto.n_e == that._primary_crypto.n_e) && (_primary_crypto.n_a == that._primary_crypto.n_a) &&
        (_primary_crypto.master_salt == that._primary_crypto.master_salt) &&
        (_primary_crypto.master_key_derivation_rate == that._primary_crypto.master_key_derivation_rate) &&
        (_primary_crypto.master_mki_value == that._primary_crypto.master_mki_value) &&
        (_primary_crypto.n_s == that._primary_crypto.n_s) && (_primary_crypto.tag == that._primary_crypto.tag) &&
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
        (_secondary_crypto.tag == that._secondary_crypto.tag) && (_session_enc_key == that._session_enc_key) &&
        (_session_salt_key == that._session_salt_key) && (_session_auth_key == that._session_auth_key) &&
        (memcmp(_pseudorandomstate.ivec, that._pseudorandomstate.ivec, sizeof(_pseudorandomstate.ivec)) == 0) &&
        (_pseudorandomstate.num == that._pseudorandomstate.num) &&
        (memcmp(_pseudorandomstate.ecount, that._pseudorandomstate.ecount, sizeof(_pseudorandomstate.ecount)) == 0) &&
        (_srtp_header_size == that._srtp_header_size) && (_srtp_payload_size == that._srtp_payload_size) &&
        (_active_crypto == that._active_crypto)) {
        return true;
    } else {
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

JLSRTP::JLSRTP(unsigned int ssrc, const std::string& ipAddress, unsigned short port)
{
    resetCryptoContext(ssrc, ipAddress, port);
}

JLSRTP::~JLSRTP()
{
    RAND_cleanup();
}

#ifdef GTEST
#include "gtest/gtest.h"
#include "srtp_stream.hpp"

#include <type_traits>

/* A copy would share the AES and HMAC contexts, and free them twice;
 * operator= copies all else, and each keeps its own. */
static_assert(!std::is_copy_constructible<JLSRTP>::value, "JLSRTP is not copy-constructible");

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
        SrtpStream stream;
        unsigned char iv[AES_BLOCK_SIZE];
        s.selectCipherAlgorithm(cipher, PRIMARY_CRYPTO);
        s._session_enc_key = fromHex(key);
        s._session_salt_key = fromHex(salt);
        stream = s;
        stream.computePacketIV(0, iv);
        stream.crypt(zeros.data(), zeros.size(), iv, out);
        return out;
    }

    // The IV of a packet of the given SSRC and index
    static std::vector<unsigned char> packetIV(JLSRTP &s, const char *salt, unsigned int ssrc, unsigned long long i)
    {
        SrtpStream stream;
        unsigned char iv[AES_BLOCK_SIZE];
        s._session_salt_key = fromHex(salt);
        s.setSSRC(ssrc);
        stream = s;
        stream.computePacketIV(i, iv);
        return std::vector<unsigned char>(iv, iv + JLSRTP_SALTING_KEY_LENGTH);
    }
};

// RFC 3711 section 4.1.1: the salt, the SSRC at bit 64 and the index at bit 16
TEST_F(JLSRTPTest, PacketIV)
{
    JLSRTP s(0, "127.0.0.1", 0);
    EXPECT_EQ(fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfd"), packetIV(s, "f0f1f2f3f4f5f6f7f8f9fafbfcfd", 0, 0));
    EXPECT_EQ(fromHex("f0f1f2f3e6c1a08f6245240bfefe"),
              packetIV(s, "f0f1f2f3f4f5f6f7f8f9fafbfcfd", 0x12345678, 0x9abcdef00203ULL));
    EXPECT_EQ(fromHex("00000000ffffffffffffffffffff"),
              packetIV(s, "0000000000000000000000000000", 0xffffffff, 0xffffffffffffULL));
}

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
    SrtpStream txStream;
    SrtpStream rxStream;
    txStream = tx;
    rxStream = rx;
    EXPECT_EQ(static_cast<int>(suite.tag_len), rxStream.getAuthenticationTagSize());

    for (unsigned short seq = 1000; seq < 1003; seq++) {
        std::vector<unsigned char> header = {0x80, 0x00, static_cast<unsigned char>(seq >> 8), static_cast<unsigned char>(seq),
                                             0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78};
        std::vector<unsigned char> payload(160);
        for (size_t i = 0; i < payload.size(); i++) {
            payload[i] = static_cast<unsigned char>(i + seq);
        }
        std::vector<unsigned char> packet;
        ASSERT_EQ(0, txStream.processOutgoingPacket(seq, header, payload, packet));
        ASSERT_EQ(12 + 160 + suite.tag_len, packet.size());
        EXPECT_NE(payload, std::vector<unsigned char>(packet.begin() + 12, packet.begin() + 172));

        std::vector<unsigned char> rx_header;
        std::vector<unsigned char> rx_payload;
        std::vector<unsigned char> tampered = packet;
        tampered[20] ^= 1;
        EXPECT_EQ(-1, rxStream.processIncomingPacket(seq, tampered, rx_header, rx_payload));
        ASSERT_EQ(0, rxStream.processIncomingPacket(seq, packet, rx_header, rx_payload));
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

