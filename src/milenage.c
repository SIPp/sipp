/*-------------------------------------------------------------------
 *          Example algorithms f1, f1*, f2, f3, f4, f5, f5*
 *-------------------------------------------------------------------
 *
 *  A sample implementation of the example 3GPP authentication and
 *  key agreement functions f1, f1*, f2, f3, f4, f5 and f5*.  This is
 *  a byte-oriented implementation of the functions, and of the block
 *  cipher kernel function Rijndael.
 *
 *  This has been coded for clarity, not necessarily for efficiency.
 *
 *  The functions f2, f3, f4 and f5 share the same inputs and have
 *  been coded together as a single function.  f1, f1* and f5* are
 *  all coded separately.
 *
 *-----------------------------------------------------------------*/

#include "milenage.h"

#include <stdint.h>

#if defined(USE_OPENSSL)
#include <openssl/evp.h>
#elif defined(USE_WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/openssl/evp.h>
#endif

/*--------------------------- helpers -----------------------------*/

/*-------------------------------------------------------------------
 *  Function to compute OPc from OP and K.  Assumes key schedule has
    already been performed.
 *-----------------------------------------------------------------*/

static void aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outlen;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);  // No PKCS padding for raw blocks
    EVP_EncryptUpdate(ctx, out, &outlen, in, 16);
    EVP_CIPHER_CTX_free(ctx);
}

static void ComputeOPc(const uint8_t k[16], uint8_t op_c[16], uint8_t op[16])
{
    aes128_encrypt_block(k, op, op_c);
    for (uint8_t i = 0; i < 16; i++)
        op_c[i] ^= op[i];
}

/* end of function ComputeOPc */

/*-------------------------------------------------------------------
 *                            Algorithm f1
 *-------------------------------------------------------------------
 *
 *  Computes network authentication code MAC-A from key K, random
 *  challenge RAND, sequence number SQN and authentication management
 *  field AMF.
 *
 *-----------------------------------------------------------------*/

void f1(uint8_t k[16], uint8_t rand[16], uint8_t sqn[6], uint8_t amf[2],
        uint8_t mac_a[8], uint8_t op[16])
{
    uint8_t op_c[16];
    uint8_t temp[16];
    uint8_t in1[16];
    uint8_t out1[16];
    uint8_t rijndaelInput[16];
    uint8_t i;

    ComputeOPc(k, op_c, op);

    for (i=0; i<16; i++)
        rijndaelInput[i] = rand[i] ^ op_c[i];
    aes128_encrypt_block(k, rijndaelInput, temp);

    for (i=0; i<6; i++) {
        in1[i]    = sqn[i];
        in1[i+8]  = sqn[i];
    }
    for (i=0; i<2; i++) {
        in1[i+6]  = amf[i];
        in1[i+14] = amf[i];
    }

    /* XOR op_c and in1, rotate by r1=64, and XOR *
     * on the constant c1 (which is all zeroes)   */

    for (i=0; i<16; i++)
        rijndaelInput[(i+8) % 16] = in1[i] ^ op_c[i];

    /* XOR on the value temp computed before */

    for (i=0; i<16; i++)
        rijndaelInput[i] ^= temp[i];

    aes128_encrypt_block(k, rijndaelInput, out1);
    for (i=0; i<16; i++)
        out1[i] ^= op_c[i];

    for (i=0; i<8; i++)
        mac_a[i] = out1[i];

    return;
} /* end of function f1 */

/*-------------------------------------------------------------------
 *                            Algorithms f2-f5
 *-------------------------------------------------------------------
 *
 *  Takes key K and random challenge RAND, and returns response RES,
 *  confidentiality key CK, integrity key IK and anonymity key AK.
 *
 *-----------------------------------------------------------------*/

void f2345(uint8_t k[16], uint8_t rand[16],
           uint8_t res[8], uint8_t ck[16], uint8_t ik[16], uint8_t ak[6], uint8_t op[16])
{
    uint8_t op_c[16];
    uint8_t temp[16];
    uint8_t out[16];
    uint8_t rijndaelInput[16];
    uint8_t i;

    ComputeOPc(k, op_c, op);

    for (i=0; i<16; i++)
        rijndaelInput[i] = rand[i] ^ op_c[i];
    aes128_encrypt_block(k, rijndaelInput, temp);

    /* To obtain output block OUT2: XOR OPc and TEMP,    *
     * rotate by r2=0, and XOR on the constant c2 (which *
     * is all zeroes except that the last bit is 1).     */

    for (i=0; i<16; i++)
        rijndaelInput[i] = temp[i] ^ op_c[i];
    rijndaelInput[15] ^= 1;

    aes128_encrypt_block(k, rijndaelInput, out);
    for (i=0; i<16; i++)
        out[i] ^= op_c[i];

    for (i=0; i<8; i++)
        res[i] = out[i+8];
    for (i=0; i<6; i++)
        ak[i]  = out[i];

    /* To obtain output block OUT3: XOR OPc and TEMP,        *
     * rotate by r3=32, and XOR on the constant c3 (which    *
     * is all zeroes except that the next to last bit is 1). */

    for (i=0; i<16; i++)
        rijndaelInput[(i+12) % 16] = temp[i] ^ op_c[i];
    rijndaelInput[15] ^= 2;

    aes128_encrypt_block(k, rijndaelInput, out);
    for (i=0; i<16; i++)
        out[i] ^= op_c[i];

    for (i=0; i<16; i++)
        ck[i] = out[i];

    /* To obtain output block OUT4: XOR OPc and TEMP,         *
     * rotate by r4=64, and XOR on the constant c4 (which     *
     * is all zeroes except that the 2nd from last bit is 1). */

    for (i=0; i<16; i++)
        rijndaelInput[(i+8) % 16] = temp[i] ^ op_c[i];
    rijndaelInput[15] ^= 4;

    aes128_encrypt_block(k, rijndaelInput, out);
    for (i=0; i<16; i++)
        out[i] ^= op_c[i];

    for (i=0; i<16; i++)
        ik[i] = out[i];

    return;
} /* end of function f2345 */


/*-------------------------------------------------------------------
 *                            Algorithm f1*
 *-------------------------------------------------------------------
 *
 *  Computes resynch authentication code MAC-S from key K, random
 *  challenge RAND, sequence number SQN and authentication management
 *  field AMF.
 *
 *-----------------------------------------------------------------*/

void f1star(uint8_t k[16], uint8_t rand[16], uint8_t sqn[6], uint8_t amf[2],
            uint8_t mac_s[8], uint8_t op[16])
{
    uint8_t op_c[16];
    uint8_t temp[16];
    uint8_t in1[16];
    uint8_t out1[16];
    uint8_t rijndaelInput[16];
    uint8_t i;

    ComputeOPc(k, op_c, op);

    for (i=0; i<16; i++)
        rijndaelInput[i] = rand[i] ^ op_c[i];
    aes128_encrypt_block(k, rijndaelInput, temp);

    for (i=0; i<6; i++) {
        in1[i]    = sqn[i];
        in1[i+8]  = sqn[i];
    }
    for (i=0; i<2; i++) {
        in1[i+6]  = amf[i];
        in1[i+14] = amf[i];
    }

    /* XOR op_c and in1, rotate by r1=64, and XOR *
     * on the constant c1 (which is all zeroes)   */

    for (i=0; i<16; i++)
        rijndaelInput[(i+8) % 16] = in1[i] ^ op_c[i];

    /* XOR on the value temp computed before */

    for (i=0; i<16; i++)
        rijndaelInput[i] ^= temp[i];

    aes128_encrypt_block(k, rijndaelInput, out1);
    for (i=0; i<16; i++)
        out1[i] ^= op_c[i];

    for (i=0; i<8; i++)
        mac_s[i] = out1[i+8];

    return;
} /* end of function f1star */


/*-------------------------------------------------------------------
 *                            Algorithm f5*
 *-------------------------------------------------------------------
 *
 *  Takes key K and random challenge RAND, and returns resynch
 *  anonymity key AK.
 *
 *-----------------------------------------------------------------*/

void f5star(uint8_t k[16], uint8_t rand[16],
            uint8_t ak[6], uint8_t op[16])
{
    uint8_t op_c[16];
    uint8_t temp[16];
    uint8_t out[16];
    uint8_t rijndaelInput[16];
    uint8_t i;

    ComputeOPc(k, op_c, op);

    for (i=0; i<16; i++)
        rijndaelInput[i] = rand[i] ^ op_c[i];
    aes128_encrypt_block(k, rijndaelInput, temp);

    /* To obtain output block OUT5: XOR OPc and TEMP,         *
     * rotate by r5=96, and XOR on the constant c5 (which     *
     * is all zeroes except that the 3rd from last bit is 1). */

    for (i=0; i<16; i++)
        rijndaelInput[(i+4) % 16] = temp[i] ^ op_c[i];
    rijndaelInput[15] ^= 8;

    aes128_encrypt_block(k, rijndaelInput, out);
    for (i=0; i<16; i++)
        out[i] ^= op_c[i];

    for (i=0; i<6; i++)
        ak[i] = out[i];

    return;
} /* end of function f5star */
