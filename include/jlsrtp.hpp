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

#ifndef __JLSRTP__
#define __JLSRTP__

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string>
#include <vector>

#define JLSRTP_VERSION				0.3
#define JLSRTP_ENCRYPTION_KEY_LENGTH		16  // bytes
#define JLSRTP_SALTING_KEY_LENGTH       	14  // bytes
#define JLSRTP_AUTHENTICATION_KEY_LENGTH  	20  // bytes

#define JLSRTP_MAX_SEQUENCE_NUMBERS     	65536

#define JLSRTP_PSEUDORANDOM_BITS 		128
#define JLSRTP_KEY_ENCRYPTION_LABEL		0x00
#define JLSRTP_KEY_AUTHENTICATION_LABEL		0x01
#define JLSRTP_KEY_SALTING_LABEL		0x02

#define	JLSRTP_SHA1_HASH_LENGTH			20

#define	JLSRTP_SRTP_DEFAULT_HEADER_SIZE		12  // bytes

#define	JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_80	10  // bytes
#define	JLSRTP_AUTHENTICATION_TAG_SIZE_SHA1_32	4   // bytes

static const std::string base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

typedef struct _CryptoContextID
{
    unsigned int ssrc;    // SSRC
    std::string address;  // IP address
    unsigned short port;  // port
} CryptoContextID;

typedef struct _AESState
{
    unsigned char ivec[AES_BLOCK_SIZE];   // ivec[0..13] (high-order bytes): 'IV' / ivec[14..15] (low-order bytes): 'counter'
    unsigned int num;                     // block byte offset
    unsigned char ecount[AES_BLOCK_SIZE]; // encrypted ivec
} AESState;

typedef union _Conversion32
{
    unsigned long i;
    unsigned char c[4];
} Conversion32;

typedef union _Conversion64
{
    unsigned long long i;
    unsigned char c[8];
} Conversion64;

typedef enum _CipherType
{
    AES_CM_128,
    NULL_CIPHER,
    INVALID_CIPHER
} CipherType;

typedef enum _HashType
{
    HMAC_SHA1_80,
    HMAC_SHA1_32,
    NULL_HASH,
    INVALID_HASH
} HashType;

typedef struct _CryptoAttribute
{
    CipherType    			cipher_algorithm;
    HashType    			hmac_algorithm;
    bool           			MKI;
    unsigned int   			MKI_length;
    unsigned long  			active_MKI;
    std::vector<unsigned char> 		master_key;
    unsigned long  			master_key_counter;
    unsigned short 			n_e;
    unsigned short 			n_a;
    std::vector<unsigned char> 		master_salt;
    unsigned long  			master_key_derivation_rate;
    unsigned long  			master_mki_value;
    unsigned short 			n_s;
    unsigned int                    	tag;
} CryptoAttribute;

typedef enum _ActiveCrypto
{
    PRIMARY_CRYPTO,
    SECONDARY_CRYPTO,
    ACTIVE_CRYPTO,
    INVALID_CRYPTO
} ActiveCrypto;

class JLSRTP
{
    private:
        CryptoContextID			_id;
        unsigned long  			_ROC;
        unsigned short 			_s_l;
        CryptoAttribute			_primary_crypto;
        CryptoAttribute                 _secondary_crypto;
        ActiveCrypto			_active_crypto;
        std::vector<unsigned char>	_session_enc_key;
        std::vector<unsigned char>	_session_salt_key;
        std::vector<unsigned char>	_session_auth_key;
        std::vector<unsigned char>      _packetIV;
        AESState                        _pseudorandomstate;
        AESState                        _cipherstate;
        AES_KEY                         _aes_key;
        unsigned int			_srtp_header_size;
	unsigned int			_srtp_payload_size;

        /**
         * isBase64
         *
         * Checks whether the given character satisfies base64 criterias (true) or not (false)
         *
         * @param[in]	c	Unsigned character to examine
         *
         * @return  TRUE	Given character satisfies base64 criterias
         * @return  FALSE	Given character DOES NOT satisfy base64 criterias
         */
        bool isBase64(unsigned char c);

        /**
         * resetPseudoRandomState
         *
         * Resets the state of the AES counter mode pseudo random function
         *
         * @param[in]		iv	Input vector to use
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE
         */
        int resetPseudoRandomState(std::vector<unsigned char> iv);

        /**
         * pseudorandomFunction
         *
         * Generates the given number of key stream bits from the given master key and input vector
         *
         * @param[in]	iv		Input vector to use
         * @param[in]	n		Number of keystream bits to generate
         * @param[out]	output		Generated keystream bits
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Incorrect salting key length
         * @return  -2  FAILURE -- Incorrect encryption key length
         * @return  -3  FAILURE -- Could not set encryption key
         * @return  -4	FAILURE -- Invalid crypto attribute specified
         */
        int pseudorandomFunction(std::vector<unsigned char> iv, int n, std::vector<unsigned char> &output);

        /**
         * shiftVectorLeft
         *
         * Shifts a given vector to the left by a predetermined number of bytes
         *
         * @param[out]	shifted_vec	Shifted vector
         * @param[in]	original_vec	Original vector to shift
         * @param[in]	shift_value	Number of bytes to shift original vector by
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE
         */
        int shiftVectorLeft(std::vector<unsigned char> &shifted_vec, std::vector<unsigned char> &original_vec, int shift_value);

        /**
         * shiftVectorRight
         *
         * Shifts a given vector to the right by a predetermined number of bytes
         *
         * @param[out]	shifted_vec	Shifted vector
         * @param[in]	original_vec	Original vector to shift
         * @param[in]	shift_value	Number of bytes to shift original vector by
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE
         */
        int shiftVectorRight(std::vector<unsigned char> &shifted_vec, std::vector<unsigned char> &original_vec, int shift_value);

        /**
         * xorVector
         *
         * Performs bitwise exclusive-OR operation between the two given vectors
         *
         * @param[in]	a		First vector to use for exclusive-OR operation
         * @param[in]	b		Second vector to use for exclusive-OR operation
         * @param[out]	result		Result of exclusive-OR operation
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Input vector sizes do not match
         */
        int xorVector(std::vector<unsigned char> &a, std::vector<unsigned char> &b, std::vector<unsigned char> &result);

        /**
         * isBigEndian
         *
         * Checks whether the current machine uses BIG ENDIAN byte ordering or not
         *
         * @return  1	Current machine uses BIG ENDIAN byte ordering
         * @return  0	Current machine does NOT use BIG ENDIAN byte ordering
         */
        int isBigEndian();

        /**
         * isLittleEndian
         *
         * Checks whether the current machine uses LITTLE ENDIAN byte ordering or not
         *
         * @return  1	Current machine uses LITTLE ENDIAN byte ordering
         * @return  0	Current machine does NOT use LITTLE ENDIAN byte ordering
         */
        int isLittleEndian();

        /**
         * convertSsrc
         *
         * Converts the given numeric 32-bit ssrc to its vector version
         *
         * @param[in]	ssrc	Numerical SSRC to convert
         * @param[out]	result	Vector-based SSRC
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE
         */
        int convertSsrc(unsigned long ssrc, std::vector<unsigned char> &result);

        /**
         * convertPacketIndex
         *
         * Converts the given numeric 48-bit packet index to its vector version
         *
         * @param[in]	ssrc	Numerical packet index to convert
         * @param[out]	result	Vector-based packet index
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE
         */
        int convertPacketIndex(unsigned long long i, std::vector<unsigned char> &result);

        /**
         * convertROC
         *
         * Converts the given numeric 32-bit roll-over-counter to its vector version
         *
         * @param[in]	roc	Numerical roll-over-counter to convert
         * @param[out]  result	Vector-based roll-over-counter
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE
         */
        int convertROC(unsigned long ROC, std::vector<unsigned char> &result);

        /**
         * determineV
         *
         * Determines new ROC from existing ROC / s_l / SEQ values
         *
         * @param[in]   SEQ     Packet sequence number
         *
         * @return  <updated_ROC>   Updated ROC based on existing ROC / s_l / SEQ values
         */
        unsigned long determineV(unsigned short SEQ);

        /**
         * updateRollOverCounter
         *
         * Updates ROC with given value v
         *
         * @param[in]   v       Value to update ROC with
         *
         * @return      TRUE    SUCCESS
         * @return      FALSE   FAILURE
         */
        bool updateRollOverCounter(unsigned long v);

        /**
         * fetchRollOverCounter
         *
         * Fetches current ROC value
         *
         * @return  <current_ROC>
         */
        unsigned long fetchRollOverCounter();

        /**
         * updateSL
         *
         * Updates s_l with given value s
         *
         * @param[in]   s       Value to update s_l with
         *
         * @return      TRUE    SUCCESS
         * @return      FALSE   FAILURE
         */
        bool updateSL(unsigned short s);

        /**
         * fetchSL
         *
         * Fetches current s_l value
         *
         * @return  <current_s_l>
         */
        unsigned short fetchSL();

        /**
         * determinePacketIndex
         *
         * Determine index of packet from ROC and SEQ
         *
         * @param[in]   ROC     RollOverCounter
         * @param[in]   SEQ     Packet sequence number
         *
         * @return <packet_index>   Packet index based on ROC and SEQ
         */
        unsigned long long determinePacketIndex(unsigned long ROC, unsigned short SEQ);

        /**
         * setPacketIV
         *
         * Sets the current computed packet IV into the cipher state prior to encryption/decryption of a packet
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE
         */
        int setPacketIV();

        /**
         * computePacketIV
         *
         * Computes the Input Vector for the given session salting key / ssrc / packet index
         *
         * @param[in]	i			Packet index to use
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Incorrect salting key length
         */
        int computePacketIV(unsigned long long i);

        /**
         * displayPacketIV
         *
         * Displays the current computed packet Input Vector
         */
        void displayPacketIV();

        /**
         * encryptVector
         *
         * Encrypts the given plaintext input vector into the ciphertext output one using selected session encryption key
         *
         * @param[in]	invdata			Input plaintext vector
         * @param[out]	ciphertext_output	Output ciphertext vector
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Empty input data vector
         * @return  -2  FAILURE -- AES key rounds is ZERO
         * @return  -3	FAILURE -- Invalid cipher type specified
         * @return  -4	FAILURE -- Invalid crypto attribute specified
         */
        int encryptVector(std::vector<unsigned char> &invdata, std::vector<unsigned char> &ciphertext_output);

        /**
         * decryptVector
         *
         * Decrypts the given ciphertext input vector into the plaintext output one using selected session decryption key
         *
         * @param[in]	ciphertext_input	Input ciphertext vector
         * @param[out]	outvdata		Output plaintext vector
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Empty input data vector
         * @return  -2  FAILURE -- AES key rounds is ZERO
         * @return  -3	FAILURE -- Invalid cipher type specified
         * @return  -4	FAILURE -- Invalid crypto attribute specified
         */
        int decryptVector(std::vector<unsigned char> &ciphertext_input, std::vector<unsigned char> &outvdata);

        /**
         * issueAuthenticationTag
         *
         * Issues a SHA1 hash of a given bit length from the provided data using the given authentication key
         *
         * @param[in]	data		Data to hash
         * @param[out]	hash		Hash
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Empty session authentication key
         * @return  -2  FAILURE -- Internal error generating digest
         * @return  -3	FAILURE -- Invalid HMAC algorithm specified
         * @return  -4	FAILURE -- Internal error converting ROC
         * @return  -5	FAILURE -- Invalid crypto attribute specified
         */
        int issueAuthenticationTag(std::vector<unsigned char> &data, std::vector<unsigned char> &hash);

        /**
         * extractAuthenticationTag
         *
         * Extracts SHA1 hash of a given bit length from the provided SRTP packet
         *
         * @param[in]	srtp_packet	SRTP packet to extract SHA1 hash from
         * @param[out]	hash		Hash
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Empty session authentication key
         * @return  -2	FAILURE -- Given SRTP packet smaller than authentication tag size
         * @return  -3	FAILURE -- Invalid HMAC algorithm specified
         * @return  -4	FAILURE -- Invalid crypto attribute specified
         */
        int extractAuthenticationTag(std::vector<unsigned char> srtp_packet, std::vector<unsigned char> &hash);

        /**
         * extractSRTPHeader
         *
         * Extracts the SRTP header from the provided SRTP packet
         *
         * @param[in]	srtp_packet	SRTP packet to extract SRTP header from
         * @param[out]	header		SRTP header
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- SRTP header size is ZERO
         * @return  -2	FAILURE -- Given SRTP packet smaller than SRTP header size
         */
        int extractSRTPHeader(std::vector<unsigned char> srtp_packet, std::vector<unsigned char> &header);

        /**
         * extractSRTPPayload
         *
         * Extracts the SRTP payload from the provided SRTP packet
         *
         * @param[in]	srtp_packet	SRTP packet to extract SRTP payload from
         * @param[out]	payload		SRTP payload
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- SRTP header size is ZERO
         * @return  -2	FAILURE -- SRTP payload size is ZERO
         * @return  -3	FAILURE -- Given SRTP packet smaller than SRTP header+payload size
         */
        int extractSRTPPayload(std::vector<unsigned char> srtp_packet, std::vector<unsigned char> &payload);

        /**
         * base64Encode
         *
         * Encodes the given bytes to a base64 string
         *
         * @param[in]       s       Decoded bytes to encode
         *
         * @return      Encoded base64 string
         */
        std::string base64Encode(std::vector<unsigned char> const& s);

        /**
         * base64Decode
         *
         * Decodes the given base64 string to bytes
         *
         * @param[in]       s       Encoded base64 string to decode
         *
         * @return      Decoded bytes
         */
        std::vector<unsigned char> base64Decode(std::string const& s);

        /**
         * resetCipherBlockOffset
         *
         * Resets the block offset of the AES counter mode encryption/decryption cipher
         *
         * @return 0	SUCCESS
         * @return -1	FAILURE
         */
        int resetCipherBlockOffset();

        /**
         * resetCipherOutputBlock
         *
         * Resets the output block of the AES counter mode encryption/decryption cipher
         *
         * @return 0	SUCCESS
         * @return -1	FAILURE
         */
        int resetCipherOutputBlock();

        /**
         * resetCipherBlockCounter
         *
         * Resets the block counter of the AES counter mode encryption/decryption cipher
         *
         * @return 0	SUCCESS
         * @return -1	FAILURE
         */
        int resetCipherBlockCounter();

    public:

        /**
         * resetCryptoContext
         *
         * Resets crypto context
         *
         * @param[in]		sssrc		SSRC ID
         * @param[in]		ipAddress	IP address
         * @param[in]		port		Port
         */
        void resetCryptoContext(unsigned int ssrc, std::string ipAddress, unsigned short port);

        /**
         * resetCipherState
         *
         * Resets the state of the AES counter mode encryption/decryption cipher
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Incorrect salting key length
         */
        int resetCipherState();

        /**
         * deriveSessionEncryptionKey
         *
         * Derives the session encryption key from the given master key / master salt
         *
         * @li Assumes the key derivation rate is ZERO
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Incorrect salting key length
         * @return  -2  FAILURE -- Incorrect encryption key length
         * @return  -3  FAILURE -- Could not set encryption key
         * @return  -4	FAILURE -- Invalid crypto attribute specified
         */
        int deriveSessionEncryptionKey();

        /**
         * deriveSessionSaltingKey
         *
         * Derives the session salting key from the given master key / master salt
         *
         * @li Assumes the key derivation rate is ZERO
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Incorrect salting key length
         * @return  -2  FAILURE -- Incorrect encryption key length
         * @return  -3  FAILURE -- Could not set encryption key
         * @return  -4	FAILURE -- Invalid crypto attribute specified
         */
        int deriveSessionSaltingKey();

        /**
         * deriveSessionAuthenticationKey
         *
         * Derives the session authentication key from the given master key / master salt
         *
         * @li Assumes the key derivation rate is ZERO
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Incorrect salting key length
         * @return  -2  FAILURE -- Incorrect encryption key length
         * @return  -3  FAILURE -- Could not set encryption key
         * @return  -4	FAILURE -- Invalid crypto attribute specified
         */
        int deriveSessionAuthenticationKey();

        /**
         * displaySessionEncryptionKey
         *
         * Displays the session encryption key
         */
        void displaySessionEncryptionKey();

        /**
         * displaySessionSaltingKey
         *
         * Displays the session salting key
         */
        void displaySessionSaltingKey();

        /**
         * displaySessionAuthenticationKey
         *
         * Displays the session authentication key
         */
        void displaySessionAuthenticationKey();

        /**
         * selectEncryptionKey
         *
         * Selects the session key used for encryption
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Empty session encryption key
         * @return  -2  FAILURE -- Could not set encryption key
         */
        int selectEncryptionKey();

        /**
         * selectDecryptionKey
         *
         * Selects the session key used for decryption
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Empty session encryption key
         * @return  -2  FAILURE -- Could not set encryption key
         */
        int selectDecryptionKey();

        /**
         * getCipherAlgorithm
         *
         * Gets the cipher algorithm currently in use
         *
         * @param[in]       crypto_attrib	Crypto attribute whose cipher algorithm is to be obtained (PRIMARY_CRYPTO, SECONDARY_CRYPTO or ACTIVE_CRYPTO)
         *
         * @return	<cipher_algorithm>	Cipher algorithm currently in use (AES_CM_128 or NULL_CIPHER)
         */
        CipherType getCipherAlgorithm(ActiveCrypto crypto_attrib = ACTIVE_CRYPTO);

        /**
         * selectCipherAlgorithm
         *
         * Selects the cipher algorithm to use
         *
         * @param[in]	cipherType	Cipher algorithm to use (AES_CM_128 or NULL_CIPHER)
         * @param[in]   crypto_attrib	Crypto attribute whose cipher algorithm is to be set (PRIMARY_CRYPTO, SECONDARY_CRYPTO or ACTIVE_CRYPTO)
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Invalid cipher algorithm specified
         * @return  -2	FAILURE -- Invalid crypto attribute specified
         */
        int selectCipherAlgorithm(CipherType cipherType, ActiveCrypto crypto_attrib = ACTIVE_CRYPTO);

        /**
         * getHashAlgorithm
         *
         * Gets the hashing algorithm currently in use
         *
         * @param[in]       crypto_attrib	Crypto attribute whose hash algorithm is to be obtained (PRIMARY_CRYPTO, SECONDARY_CRYPTO or ACTIVE_CRYPTO)
         *
         * @return	<hash_algorithm>	Hashing algorithm currently in use (HMAC_SHA1_80 or HMAC_SHA1_32)
         */
        HashType getHashAlgorithm(ActiveCrypto crypto_attrib = ACTIVE_CRYPTO);

        /**
         * selectHashAlgorithm
         *
         * Selects the hashing algorithm to use
         *
         * @param[in]	hashType	Hashing algorithm to use (HMAC_SHA1_80 or HMAC_SHA1_32)
         * @param[in]       crypto_attrib	Crypto attribute whose hash algorithm is to be set (PRIMARY_CRYPTO, SECONDARY_CRYPTO or ACTIVE_CRYPTO)
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE -- Invalid HMAC algorithm specified
         * @return  -2	FAILURE -- Invalid crypto attribute specified
         */
        int selectHashAlgorithm(HashType hashType, ActiveCrypto crypto_attrib = ACTIVE_CRYPTO);

        /**
         * getAuthenticationTagSize
         *
         * Gets the authentication tag size
         *
         * @return  >0	SUCCESS -- Authentication tag size (bytes)
         * @return  -1	FAILURE -- Empty session authentication key
         * @return  -2	FAILURE -- Invalid HMAC algorithm specified
         * @return  -3	FAILURE -- Invalid crypto attribute specified
         */
        int getAuthenticationTagSize();

        /**
         * displayAuthenticationTag
         *
         * Displays the given authentication tag
         *
         * @param[in]	authtag		Authentication tag to display
         */
        void displayAuthenticationTag(std::vector<unsigned char> &authtag);

        /**
         * getSSRC
         *
         * Gets the SSRC currently in use
         *
         * @return	<ssrc>		SSRC ID currently in use
         */
        unsigned int getSSRC();

        /**
         * getIPAddress
         *
         * Gets the IP address currently in use
         *
         * @return	<ip_address>	IP address currently in use
         */
        std::string getIPAddress();

        /**
         * getPort
         *
         * Gets the port currently in use
         *
         * @return	<port>		Port currently in use
         */
        unsigned short getPort();

        /**
         * setSSRC
         *
         * Sets the SSRC currently in use
         *
         * @param[in]    ssrc       SSRC ID currently in use
         */
        void setSSRC(unsigned int ssrc);

        /**
         * setIPAddress
         *
         * Sets the IP address currently in use
         *
         * @param[in]    ipAddress  IP address currently in use
         */
        void setIPAddress(std::string ipAddress);

        /**
         * setPort
         *
         * Sets the port currently in use
         *
         * @param[in]    port       Port currently in use
         */
        void setPort(unsigned short port);

        /**
         * setID
         *
         * Sets the cryptographic context ID (<SSRC, IPAddress, Port>) to use
         *
         * @param[in]	id	Cryptograhic context ID (<SSRC, IPAddress, Port>) to use
         */
        void setID(CryptoContextID id);

        /**
         * getSrtpHeaderSize
         *
         * Gets the current SRTP header size
         *
         * @return	<size>	Current SRTP header size in use
         */
        unsigned int getSrtpHeaderSize();

        /**
         * setSrtpHeaderSize
         *
         * Sets the current SRTP header size
         *
         * @param[in]	size	Current SRTP header size to use
         */
        void setSrtpHeaderSize(unsigned int size);

        /**
         * getSrtpPayloadSize
         *
         * Gets the current SRTP payload size
         *
         * @return	<size>	Current SRTP payload size in use
         */
        unsigned int getSrtpPayloadSize();

        /**
         * setSrtpPayloadSize
         *
         * Sets the current SRTP payload size
         *
         * @param[in]	size	Current SRTP payload size to use
         */
        void setSrtpPayloadSize(unsigned int size);

        /**
         * processOutgoingPacket
         *
         * Processes an outgoing RTP packet (encrypt+authenticate) to become an SRTP packet
         *
         * @param[in]	SEQ_s           Input RTP packet sequence number
         * @param[in]	rtp_header	Input RTP header
         * @param[in]	rtp_payload	Input RTP payload
         * @param[out]	srtp_packet	Output SRTP packet
         *
         * @return  0	SUCCESS
         * @return  -1	ENCRYPTION_FAILURE
         * @return  -2	Error issuing authentication tag
         * @return  -3  Error encountered while computing packet IV
         * @return  -4	Error encountered while setting packet IV
         * @return  -5	Error updating rollover counter
         * @return  -6	Error updating SL
         */
        int processOutgoingPacket(unsigned short SEQ_s,
                                  std::vector<unsigned char> &rtp_header,
                                  std::vector<unsigned char> &rtp_payload,
                                  std::vector<unsigned char> &srtp_packet);

        /**
         * processIncomingPacket
         *
         * Processes an incoming SRTP packet (authenticate+decrypt) to become an RTP packet
         *
         * @param[in]	SEQ_r           Input SRTP packet sequence number
         * @param[in]	srtp_packet	Input SRTP packet
         * @param[out]	rtp_header	Output RTP header
         * @param[out]  rtp_payload	Output RTP payload
         *
         * @return  0	SUCCESS
         * @return  -1	AUTHENTICATION_FAILURE
         * @return  -2	DECRYPTION_FAILURE
         * @return  -3	Error extracting authentication tag
         * @return  -4	Error extracting SRTP header
         * @return  -5	Error extracting SRTP payload
         * @return  -6	Error issuing authentication tag
         * @return  -7	Error encountered while computing packet IV
         * @return  -8	Error encoutnered while setting packet IV
         * @return  -9	Error updating rollover counter
         * @return  -10	Error updating SL
         */
        int processIncomingPacket(unsigned short SEQ_r,
                                  std::vector<unsigned char> &srtp_packet,
                                  std::vector<unsigned char> &rtp_header,
                                  std::vector<unsigned char> &rtp_payload);

        /**
         * setCryptoTag
         *
         * Sets the crypto tag parameter value
         *
         * @param[in]       tag     		Crypto tag value to use
         * @param[in]       crypto_attrib	Crypto attribute whose tag is to be set (PRIMARY_CRYPTO, SECONDARY_CRYPTO or ACTIVE_CRYPTO)
         *
         * @return	0	SUCCESS
         * @return	-1	FAILURE
         */
        int setCryptoTag(unsigned int tag, ActiveCrypto crypto_attrib = ACTIVE_CRYPTO);

        /**
         * getCryptoTag
         *
         * Gets the crypto tag parameter value
         *
         * @param[in]       crypto_attrib	Crypto attribute whose tag is to be obtained (PRIMARY_CRYPTO, SECONDARY_CRYPTO or ACTIVE_CRYPTO)
         *
         * @return	<crypto_tag>	Crypto tag value currently in use
         */
        unsigned int getCryptoTag(ActiveCrypto crypto_attrib = ACTIVE_CRYPTO);

        /**
         * getCryptoSuite
         *
         * Fetches the string description of the crypto suite currently in use (e.g. "AES_CM_128_HMAC_SHA1_80" or "AES_CM_128_HMAC_SHA1_32")
         *
         * @return	<cryptosuite_string>	String description of the crypto suite currently in use
         */
        std::string getCryptoSuite();

        /**
         * encodeMasterKeySalt
         *
         * Encodes the current unencoded master key/salt of the context for use in a RFC4568-compliant crypto attribute
         *
         * @param[out]	mks		Encoded master key/salt string (for use in an RFC-4568-compliant crypto attribute)
         * @param[in]   crypto_attrib	Crypto attribute whose master key/salt is to be encoded (PRIMARY_CRYPTO, SECONDARY_CRYPTO or ACTIVE_CRYPTO)
         *
         * @return	0	SUCCESS
         * @return	-1	FAILURE
         */
        int encodeMasterKeySalt(std::string &mks, ActiveCrypto crypto_attrib = ACTIVE_CRYPTO);

        /**
         * decodeMasterKeySalt
         *
         * Decodes the given encoded master key/salt string from an RFC4568-compliant crypto attribute for use in the context
         *
         * @param[in]	mks		Encoded RFC4568-compliant master key/salt value (for use in the context)
         * @param[in]   crypto_attrib	Crypto attribute whose master key/salt is to be decoded (PRIMARY_CRYPTO, SECONDARY_CRYPTO or ACTIVE_CRYPTO)
         *
         * @return	0	SUCCESS
         * @return	-1	FAILURE
         */
        int decodeMasterKeySalt(std::string &mks, ActiveCrypto crypto_attrib = ACTIVE_CRYPTO);

        /**
         * displayCryptoContext
         *
         * Displays current CryptoContext
         */
        void displayCryptoContext();

        /**
         * dumpCryptoContext
         */
        std::string dumpCryptoContext();

        /**
         * generateMasterKey
         *
         * Generates a master key
         *
         * @param[in]   crypto_attrib	Crypto attribute whose master key is to be generated (PRIMARY_CRYPTO, SECONDARY_CRYPTO or ACTIVE_CRYPTO)
         *
         * @return  0   SUCCESS
         * @return  -1  FAILURE
         */
        int generateMasterKey(ActiveCrypto crypto_attrib = ACTIVE_CRYPTO);

        /**
         * generateMasterSalt
         *
         * Generates a master salt
         *
         * @param[in]   crypto_attrib	Crypto attribute whose master salt is to be generated (PRIMARY_CRYPTO, SECONDARY_CRYPTO or ACTIVE_CRYPTO)
         *
         * @return  0   SUCCESS
         * @return  -1  FAILURE
         */
        int generateMasterSalt(ActiveCrypto crypto_attrib = ACTIVE_CRYPTO);

        /**
         * getMasterKey
         *
         * Gets the MASTER KEY
         *
         * @param[in]	crypto_attrib	Crypto attribute whose master key is to be fetched (PRIMARY_CRYPTO, SECONDARY_CRYPTO or ACTIVE_CRYPTO)
         *
         * @return	<master_key>		Master key
         */
        std::vector<unsigned char> getMasterKey(ActiveCrypto crypto_attrib = ACTIVE_CRYPTO);

        /**
         * getMasterSalt
         *
         * Gets the MASTER SALT
         *
         * @param[in]	crypto_attrib	Crypto attribute whose master salt is to be fetched (PRIMARY_CRYPTO, SECONDARY_CRYPTO or ACTIVE_CRYPTO)
         *
         * @return	<master_salt>		Master salt
         */
        std::vector<unsigned char> getMasterSalt(ActiveCrypto crypto_attrib = ACTIVE_CRYPTO);

        /**
         * setMasterKey
         *
         * Sets the MASTER KEY
         *
         * @param[in]	key		Master key to use
         * @param[in]	crypto_attrib	Crypto attribute whose master key is to be set (PRIMARY_CRYPTO, SECONDARY_CRYPTO or ACTIVE_CRYPTO)
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE
         */
        int setMasterKey(std::vector<unsigned char> &key, ActiveCrypto crypto_attrib = ACTIVE_CRYPTO);

        /**
         * setMasterSalt
         *
         * Sets the MASTER SALT
         *
         * @param[in]	salt		Master salt to use
         * @param[in]	crypto_attrib	Crypto attribute whose master salt is to be set (PRIMARY_CRYPTO, SECONDARY_CRYPTO or ACTIVE_CRYPTO)
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE
         */
        int setMasterSalt(std::vector<unsigned char> &salt, ActiveCrypto crypto_attrib = ACTIVE_CRYPTO);

        /**
         * swapCrypto
         *
         * Swaps the PRIMARY and SECONDARY crypto attributes
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE
         */
        int swapCrypto();

        /**
         * selectActiveCrypto
         *
         * Selects the crypto attribute to use (PRIMARY or SECONDARY)
         *
         * @param[in]	activeCrypto	Crypto attribute to use (PRIMARY_CRYPTO or SECONDARY_CRYPTO)
         *
         * @return  0	SUCCESS
         * @return  -1	FAILURE
         */
        int selectActiveCrypto(ActiveCrypto activeCrypto);

        /**
         * getActiveCrypto
         *
         * Gets the crypto attribute currently in use (PRIMARY or SECONDARY)
         *
         * @return	PRIMARY_CRYPTO		Primary crypto attribute is currently in use
         * @return	SECONDARY_CRYPTO	Secondary crypto attribute is currently in use
         * @return	INVALID_CRYPTO		Internal error occurred
         */
        ActiveCrypto getActiveCrypto();

        /**
         * operator=
         *
         * Assigns a given JLSRTP object to the implicit one
         *
         * @param[in]	that		JLSRTP object to assign to the implicit one
         *
         * @return	<JLSRTP_reference>	Reference to the implicit JLSRTP object
         */
        JLSRTP& operator=(const JLSRTP& that);

        /**
         * operator==
         *
         * Compares a given JLSRTP object to the implicit one for equality
         *
         * @param[in]	that		JLSRTP object to compare to the implicit one for equality
         *
         * @return	TRUE	Given JLSRTP object is equal to the implicit one
         * @return	FALSE	Given JLSRTP object is NOT equal to the implicit one
         */
        bool operator==(const JLSRTP& that);

        /**
         * operator!=
         *
         * Compares a given JLSRTP object to the implicit one for inequality
         *
         * @param[in]	that		JLSRTP object to compare to the implicit one for inequality
         *
         * @return	TRUE	Given JLSRTP object is inequal to the implicit one
         * @return	FALSE	Given JLSRTP object is NOT inequal to the implicit one
         */
        bool operator!=(const JLSRTP& that);

        /**
         * JLSTRP
         *
         * Default constructor
         */
        JLSRTP();

        /**
         * JLSRTP
         *
         * Custom constructor
         *
         * @param[in]		sssrc		SSRC ID
         * @param[in]		ipAddress	IP address
         * @param[in]		port		Port
         */
        JLSRTP(unsigned int ssrc, std::string ipAddress, unsigned short port);

        /**
         * ~JLSRTP
         *
         * Default destructor
         */
        ~JLSRTP();

};

#endif // __JLSRTP__

