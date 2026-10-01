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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "srtp_stream.hpp"

#include <algorithm>
#include <string.h>

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)

void HMACState::free()
{
    inner.reset();
    outer.reset();
}

/* HMAC() did the key's pads and fetched SHA-1 for each packet, half the
 * CPU of an SRTP echo, where this copies the states they left. */
bool HMACState::digest(const unsigned char *key, size_t key_length, const unsigned char *data, size_t length,
                       const unsigned char *more, size_t more_length, std::array<unsigned char, EVP_MAX_MD_SIZE> &out,
                       unsigned int *out_len)
{
    /* the digest's own, one for all the keys of the thread */
    static thread_local std::unique_ptr<EVP_MD_CTX, Free> work(EVP_MD_CTX_new());
    if (!work) {
        return false;
    }
    if (!inner) {
        inner.reset(EVP_MD_CTX_new());
        outer.reset(EVP_MD_CTX_new());
        unsigned char k[64] = {}; /* the key in a SHA-1 block */
        unsigned int k_len = 0;
        bool made = inner && outer;
        if (made && key_length > sizeof(k)) {
            made = EVP_Digest(key, key_length, k, &k_len, EVP_sha1(), nullptr) == 1;
        } else if (made) {
            memcpy(k, key, key_length);
        }
        if (!made) {
            free();
            return false;
        }
        unsigned char ipad[sizeof(k)], opad[sizeof(k)];
        for (size_t i = 0; i < sizeof(k); i++) {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }
        if (EVP_DigestInit_ex(inner.get(), EVP_sha1(), nullptr) != 1 ||
            EVP_DigestUpdate(inner.get(), ipad, sizeof(ipad)) != 1 ||
            EVP_DigestInit_ex(outer.get(), EVP_sha1(), nullptr) != 1 ||
            EVP_DigestUpdate(outer.get(), opad, sizeof(opad)) != 1) {
            free();
            return false;
        }
    }
    unsigned char inner_hash[EVP_MAX_MD_SIZE];
    unsigned int inner_len = 0;
    return EVP_MD_CTX_copy_ex(work.get(), inner.get()) == 1 && EVP_DigestUpdate(work.get(), data, length) == 1 &&
           EVP_DigestUpdate(work.get(), more, more_length) == 1 &&
           EVP_DigestFinal_ex(work.get(), inner_hash, &inner_len) == 1 &&
           EVP_MD_CTX_copy_ex(work.get(), outer.get()) == 1 &&
           EVP_DigestUpdate(work.get(), inner_hash, inner_len) == 1 &&
           EVP_DigestFinal_ex(work.get(), out.data(), out_len) == 1;
}

SrtpStream &SrtpStream::operator=(const JLSRTP &from)
{
    const CryptoAttribute *active = from._active_crypto == PRIMARY_CRYPTO     ? &from._primary_crypto
                                    : from._active_crypto == SECONDARY_CRYPTO ? &from._secondary_crypto
                                                                              : nullptr;
    const std::vector<unsigned char> &enc_key = from._session_enc_key;
    const std::vector<unsigned char> &salt_key = from._session_salt_key;
    const std::vector<unsigned char> &auth_key = from._session_auth_key;

    _ssrc = from._id.ssrc;
    _tag = from.getCryptoTag();
    _ROC = 0;
    _s_l = 0;
    _s_l_set = false;
    _cipher = active ? active->cipher_algorithm : INVALID_CIPHER;
    _hash = active ? active->hmac_algorithm : INVALID_HASH;
    _srtp_header_size = from._srtp_header_size;
    _srtp_payload_size = from._srtp_payload_size;

    /* A key AES does not take fails to key it, as one of no bytes */
    size_t enc_key_length = enc_key.size() <= _enc_key.size() ? enc_key.size() : 0;
    if (enc_key_length != _enc_key_length ||
        !std::equal(_enc_key.begin(), _enc_key.begin() + enc_key_length, enc_key.begin())) {
        std::copy(enc_key.begin(), enc_key.begin() + enc_key_length, _enc_key.begin());
        _enc_key_length = enc_key_length;
    }
    _salt_key_set = salt_key.size() == _salt_key.size();
    if (_salt_key_set) {
        std::copy(salt_key.begin(), salt_key.end(), _salt_key.begin());
    }
    bool auth_key_set = auth_key.size() == _auth_key.size();
    if (auth_key_set != _auth_key_set ||
        (auth_key_set && !std::equal(_auth_key.begin(), _auth_key.end(), auth_key.begin()))) {
        if (auth_key_set) {
            std::copy(auth_key.begin(), auth_key.end(), _auth_key.begin());
        }
        _auth_key_set = auth_key_set;
        _hmac.free();
    }

    return *this;
}

int SrtpStream::getAuthenticationTagSize() const
{
    if (!_auth_key_set) {
        return -1;
    }
    switch (_hash) {
    case HMAC_SHA1_80:
        return JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_80;
    case HMAC_SHA1_32:
        return JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_32;
    default:
        return -2;
    }
}

unsigned long SrtpStream::determineV(unsigned short SEQ) const
{
    /* Nothing to compare the first packet with: its SEQ becomes s_l
     * (RFC 3711 section 3.3.1). Comparing it with the initial 0 instead
     * took any first SEQ above 32768, as RFC 3550 senders pick at random,
     * for one from before a rollover, and ROC-1 wrapped. */
    if (!_s_l_set) {
        return _ROC;
    }

    if (_s_l < 32768) {
        return (SEQ - _s_l) > 32768 ? ((_ROC > 0) ? _ROC - 1 : 0) : _ROC;
    }
    return (SEQ - _s_l) < -32768 ? _ROC + 1 : _ROC;
}

/* IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16), its last two bytes
 * the block counter */
int SrtpStream::computePacketIV(unsigned long long i, unsigned char iv[AES_BLOCK_SIZE]) const
{
    if (!_salt_key_set) {
        return -1;
    }

    memset(iv, 0, AES_BLOCK_SIZE);
    memcpy(iv, _salt_key.data(), _salt_key.size());
    for (int b = 0; b < 4; b++) {
        iv[4 + b] ^= (_ssrc >> (24 - 8 * b)) & 0xFF; // bytes [4..7]
    }
    for (int b = 0; b < 8; b++) {
        iv[6 + b] ^= (i >> (56 - 8 * b)) & 0xFF; // bytes [6..13]
    }
    iv[14] = iv[15] = 0;

    return 0;
}

/* AES-CM with AES-ECB, for a TLS library without AES-CTR: the key set
 * once for the packet, and the keystream of its blocks made in one call.
 * The context is the thread's, for all its streams, as for AES-CTR. */
void SrtpStream::aesCm(const unsigned char iv[AES_BLOCK_SIZE], const unsigned char *in, unsigned char *out,
                       size_t length)
{
    unsigned char counter[AES_BLOCK_SIZE];
    unsigned char counters[32 * AES_BLOCK_SIZE];
    unsigned char keystream[sizeof(counters)];
    int nb = 0;
    static thread_local AESCipher aes;

    if (aes.setKey(_enc_key.data(), _enc_key_length) != 1) {
        return;
    }
    memcpy(counter, iv, AES_BLOCK_SIZE);
    while (length) {
        size_t blocks = std::min((length + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE, sizeof(counters) / AES_BLOCK_SIZE);
        for (size_t b = 0; b < blocks; b++) {
            memcpy(counters + b * AES_BLOCK_SIZE, counter, AES_BLOCK_SIZE);
            /* the counter is the IV plus the block number */
            for (int c = AES_BLOCK_SIZE - 1; c >= 0 && ++counter[c] == 0; c--) {}
        }
        if (EVP_EncryptUpdate(aes.get(), keystream, &nb, counters, blocks * AES_BLOCK_SIZE) != 1 ||
            nb != static_cast<int>(blocks * AES_BLOCK_SIZE)) {
            return;
        }
        size_t bytes = std::min(length, blocks * AES_BLOCK_SIZE);
        for (size_t i = 0; i < bytes; i++) {
            out[i] = in[i] ^ keystream[i];
        }
        in += bytes;
        out += bytes;
        length -= bytes;
    }
}

int SrtpStream::crypt(const unsigned char *in, size_t length, const unsigned char iv[AES_BLOCK_SIZE],
                      std::vector<unsigned char> &out)
{
    if (!length) {
        return -1;
    }

    switch (_cipher) {
    case AES_CM_128:
    case AES_CM_192:
    case AES_CM_256: {
        /* The context is the thread's, for all its streams: one for each
         * stream cost each call 1.3 KB, for the key it sets in it for each
         * packet anyway. The TLS library makes and XORs the keystream,
         * where encrypting the counter blocks with AES-ECB took twice the
         * instructions. A key AES does not take leaves the zeros. */
        static thread_local AESCipher aes;
        size_t at = out.size();
        out.resize(at + length);
        if (AESCipher::hasCtr(_enc_key_length)) {
            aes.ctr(_enc_key.data(), _enc_key_length, iv, in, out.data() + at, length);
        } else {
            aesCm(iv, in, out.data() + at, length);
        }
        return 0;
    }
    case NULL_CIPHER:
        out.insert(out.end(), in, in + length);
        return 0;
    default:
        return -3;
    }
}

int SrtpStream::authenticationTag(const unsigned char *data, size_t length,
                                  std::array<unsigned char, EVP_MAX_MD_SIZE> &tag)
{
    unsigned char roc[4] = {static_cast<unsigned char>(_ROC >> 24), static_cast<unsigned char>(_ROC >> 16),
                            static_cast<unsigned char>(_ROC >> 8), static_cast<unsigned char>(_ROC)};
    unsigned int tag_len = 0;

    if (!_auth_key_set) {
        return -1;
    }
    if (!_hmac.digest(_auth_key.data(), _auth_key.size(), data, length, roc, sizeof(roc), tag, &tag_len) ||
        tag_len != JLSRTP_SHA1_HASH_LENGTH) {
        return -2;
    }
    return getAuthenticationTagSize() > 0 ? 0 : -3;
}

int SrtpStream::processOutgoingPacket(unsigned short SEQ_s, const std::vector<unsigned char> &rtp_header,
                                      const std::vector<unsigned char> &rtp_payload,
                                      std::vector<unsigned char> &srtp_packet)
{
    /* the packet before its tag, kept by the thread for the next packet */
    static thread_local std::vector<unsigned char> packet;
    std::array<unsigned char, EVP_MAX_MD_SIZE> tag;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned long v_s = determineV(SEQ_s);
    unsigned long long i_s = (JLSRTP_MAX_SEQUENCE_NUMBERS * v_s) + SEQ_s;

    // Encrypt the payload (RFC 3711 section 4.1)
    if (computePacketIV(i_s, iv) != 0) {
        return -3;
    }
    packet.assign(rtp_header.begin(), rtp_header.end());
    if (crypt(rtp_payload.data(), rtp_payload.size(), iv, packet) != 0) {
        return -1; // ENCRYPTION FAILURE
    }

    // Authenticate it and its header with the ROC (section 4.2), and append the tag
    if (authenticationTag(packet.data(), packet.size(), tag) != 0) {
        return -2;
    }
    srtp_packet.assign(packet.begin(), packet.end());
    srtp_packet.insert(srtp_packet.end(), tag.begin(), tag.begin() + getAuthenticationTagSize());

    // Update the ROC and s_l (section 3.3.1)
    _ROC = v_s;
    _s_l = SEQ_s;
    _s_l_set = true;

    return 0;
}

int SrtpStream::processIncomingPacket(unsigned short SEQ_r, const std::vector<unsigned char> &srtp_packet,
                                      std::vector<unsigned char> &rtp_header, std::vector<unsigned char> &rtp_payload)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> tag;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned long v_r = determineV(SEQ_r);
    unsigned long long i_r = (JLSRTP_MAX_SEQUENCE_NUMBERS * v_r) + SEQ_r;
    int tag_len = getAuthenticationTagSize();
    /* the header and the payload, of the sizes the stream has them */
    size_t authenticated = _srtp_header_size + _srtp_payload_size;

    rtp_header.clear();
    rtp_payload.clear();

    // The tag at the end of the packet, the header and the payload
    if (tag_len < 0 || srtp_packet.size() < static_cast<size_t>(tag_len)) {
        return -3;
    }
    if (_srtp_header_size == 0 || srtp_packet.size() < _srtp_header_size) {
        return -4;
    }
    rtp_header.assign(srtp_packet.begin(), srtp_packet.begin() + _srtp_header_size);
    if (_srtp_payload_size == 0 || srtp_packet.size() < authenticated) {
        return -5;
    }

    // Verify the tag (RFC 3711 section 4.2)
    if (authenticationTag(srtp_packet.data(), authenticated, tag) != 0) {
        return -6;
    }
    if (memcmp(tag.data(), srtp_packet.data() + srtp_packet.size() - tag_len, tag_len) != 0) {
        return -1; // AUTHENTICATION FAILURE
    }

    // Decrypt the payload (section 4.1)
    if (computePacketIV(i_r, iv) != 0) {
        return -7;
    }
    if (crypt(srtp_packet.data() + _srtp_header_size, _srtp_payload_size, iv, rtp_payload) != 0) {
        return -2; // DECRYPTION FAILURE
    }

    // Update the ROC and s_l (section 3.3.1)
    _ROC = v_r;
    _s_l = SEQ_r;
    _s_l_set = true;

    return 0;
}

#ifdef GTEST
#include "gtest/gtest.h"

// A stream that takes the keys of another context protects with those,
// and not with the AES and HMAC keys it had
TEST(SrtpStream, TakesNewKeys)
{
    std::vector<unsigned char> header = {0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78};
    std::vector<unsigned char> payload(160, 0x55);
    std::vector<unsigned char> packet;
    std::vector<unsigned char> rx_header;
    std::vector<unsigned char> rx_payload;
    JLSRTP a(0x12345678, "127.0.0.1", 0);
    JLSRTP b(0x12345678, "127.0.0.1", 0);
    SrtpStream tx;
    SrtpStream rx;

    for (JLSRTP *s : {&a, &b}) {
        ASSERT_EQ(0, s->generateMasterKey(PRIMARY_CRYPTO));
        ASSERT_EQ(0, s->generateMasterSalt(PRIMARY_CRYPTO));
        s->setSrtpPayloadSize(160);
        ASSERT_EQ(0, s->deriveSessionEncryptionKey());
        ASSERT_EQ(0, s->deriveSessionSaltingKey());
        ASSERT_EQ(0, s->deriveSessionAuthenticationKey());
    }
    tx = a;
    rx = a;
    ASSERT_EQ(0, tx.processOutgoingPacket(1, header, payload, packet));
    ASSERT_EQ(0, rx.processIncomingPacket(1, packet, rx_header, rx_payload));
    EXPECT_EQ(payload, rx_payload);

    tx = b;
    ASSERT_EQ(0, tx.processOutgoingPacket(1, header, payload, packet));
    EXPECT_EQ(-1, rx.processIncomingPacket(1, packet, rx_header, rx_payload));
    rx = b;
    ASSERT_EQ(0, rx.processIncomingPacket(1, packet, rx_header, rx_payload));
    EXPECT_EQ(payload, rx_payload);
}

#endif // GTEST

#endif // USE_OPENSSL || USE_WOLFSSL
