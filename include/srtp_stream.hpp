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

#ifndef __SRTP_STREAM__
#define __SRTP_STREAM__

#include "jlsrtp.hpp"

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)

/* HMAC-SHA1 with a key: the SHA-1 states after its inner and outer pads,
 * made with the first digest until free(), copied to a context of the
 * thread for each packet. */
class HMACState
{
public:
    /* HMAC-SHA1 with key of data and then more. False if a digest fails. */
    bool digest(const unsigned char *key, size_t key_length, const unsigned char *data, size_t length,
                const unsigned char *more, size_t more_length, std::array<unsigned char, EVP_MAX_MD_SIZE> &out,
                unsigned int *out_len);
    void free();

private:
    struct Free {
        void operator()(EVP_MD_CTX *c) const
        {
            EVP_MD_CTX_free(c);
        }
    };
    std::unique_ptr<EVP_MD_CTX, Free> inner, outer;
};

/* A stream's SRTP packets, in the thread that sends or receives them: the
 * session keys of a JLSRTP context, the tag, cipher and authentication of
 * its active crypto, and the packet index, without the master keys and
 * suites the call keeps in the context. */
class SrtpStream
{
public:
    /* Takes the session keys, the active crypto, the SSRC and the SRTP
     * header and payload sizes of a context, and starts the packet index
     * over */
    SrtpStream &operator=(const JLSRTP &from);

    /* As JLSRTP's */
    unsigned int getCryptoTag() const
    {
        return _tag;
    }
    int getAuthenticationTagSize() const;
    unsigned int getSrtpPayloadSize() const
    {
        return _srtp_payload_size;
    }
    void setSSRC(unsigned int ssrc)
    {
        _ssrc = ssrc;
    }

    /* Encrypts and authenticates an RTP packet into an SRTP one, which is
     * left as it was on failure. Returns 0 on success, -1 if encrypting
     * fails, -2 if issuing the tag does, -3 without a salting key. */
    int processOutgoingPacket(unsigned short SEQ_s, const std::vector<unsigned char> &rtp_header,
                              const std::vector<unsigned char> &rtp_payload, std::vector<unsigned char> &srtp_packet);

    /* Authenticates and decrypts an SRTP packet of the stream's header and
     * payload sizes into its RTP header and payload. Returns 0 on success,
     * -1 for a tag that does not match, -2 if decrypting fails, -3 for no
     * tag, -4 for no header, -5 for no payload, -6 if issuing the tag fails
     * and -7 without a salting key. */
    int processIncomingPacket(unsigned short SEQ_r, const std::vector<unsigned char> &srtp_packet,
                              std::vector<unsigned char> &rtp_header, std::vector<unsigned char> &rtp_payload);

private:
    /* The ROC of a packet's index, from the ROC and s_l (RFC 3711 section 3.3.1) */
    unsigned long determineV(unsigned short SEQ) const;
    /* The IV of the packet of index i: -1 without a salting key */
    int computePacketIV(unsigned long long i, unsigned char iv[AES_BLOCK_SIZE]) const;
    /* AES-CM of length bytes of in to out from the IV, with the session key */
    void aesCm(const unsigned char iv[AES_BLOCK_SIZE], const unsigned char *in, unsigned char *out, size_t length);
    /* Appends length bytes of in, encrypted or decrypted from the IV, to
     * out: -1 for none, -3 for an unknown cipher */
    int crypt(const unsigned char *in, size_t length, const unsigned char iv[AES_BLOCK_SIZE],
              std::vector<unsigned char> &out);
    /* The authentication tag of length bytes of data and the ROC: -1
     * without an authentication key, -2 if the HMAC fails, -3 for an
     * unknown one */
    int authenticationTag(const unsigned char *data, size_t length, std::array<unsigned char, EVP_MAX_MD_SIZE> &tag);

    unsigned int _ssrc = 0;
    unsigned int _tag = 0;
    unsigned long _ROC = 0;
    unsigned short _s_l = 0;
    bool _s_l_set = false; // a packet has set _s_l
    CipherType _cipher = INVALID_CIPHER;
    HashType _hash = INVALID_HASH;
    unsigned int _srtp_header_size = 0;
    unsigned int _srtp_payload_size = 0;
    /* the session keys; none of a length the context has not derived */
    std::array<unsigned char, JLSRTP_AES_256_KEY_LENGTH> _enc_key = {};
    unsigned char _enc_key_length = 0;
    bool _salt_key_set = false;
    bool _auth_key_set = false;
    std::array<unsigned char, JLSRTP_SALTING_KEY_LENGTH> _salt_key = {};
    std::array<unsigned char, JLSRTP_AUTHENTICATION_KEY_LENGTH> _auth_key = {};
    HMACState _hmac;

#ifdef GTEST
    friend class JLSRTPTest;
#endif
};

#endif // USE_OPENSSL || USE_WOLFSSL

#endif // __SRTP_STREAM__
