/*
   Adaptatipn of SW from hereafter license
   Author: laurent.thomas@open-cells.com
   The OpenAirInterface project uses this copy under the terms of BSD
   license.
*/
/*
   3GPP AKA - Milenage algorithm (3GPP TS 35.205, .206, .207, .208)
   Copyright (c) 2006-2007 <j@w1.fi>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   Alternatively, this software may be distributed under the terms of BSD
   license.

   See README and COPYING for more details.

   This file implements an example authentication algorithm defined for 3GPP
   AKA. This can be used to implement a simple HLR/AuC into hlr_auc_gw to allow
   EAP-AKA to be tested properly with real USIM cards.

   This implementations assumes that the r1..r5 and c1..c5 constants defined in
   TS 35.206 are used, i.e., r1=64, r2=0, r3=32, r4=64, r5=96, c1=00..00,
   c2=00..01, c3=00..02, c4=00..04, c5=00..08. The block cipher is assumed to
   be AES (Rijndael).
*/

#ifndef MILENAGE_H
#define MILENAGE_H


#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <openssl/evp.h>

// #include <openssl/aes.h>
// #include "openair3/SECU/aes_128_ecb.h"

/**
   milenage_f1 - Milenage f1 and f1* algorithms
   @opc: OPc = 128-bit value derived from OP and K
   @k: K = 128-bit subscriber key
   @_rand: RAND = 128-bit random challenge
   @sqn: SQN = 48-bit sequence number
   @amf: AMF = 16-bit authentication management field
   @mac_a: Buffer for MAC-A = 64-bit network authentication code, or %NULL
   @mac_s: Buffer for MAC-S = 64-bit resync authentication code, or %NULL
   Returns: true on success, false on failure
*/

/** 原始OAI milenage.c的程式碼
void aes_128_encrypt_block(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
  abort();
  assert(0 != 0 && "Here we are!");
  // Precondition: key, in and out occupy 16 bytes
  aes_128_t k_iv = {.type = NONE_INITIALIZATION_VECTOR};
  memcpy(k_iv.key, key, sizeof(k_iv.key));

  byte_array_t msg = {.buf = (uint8_t *)in, .len = 16};
  uint8_t tmp[16] = {0};
  aes_128_ecb(&k_iv, msg, sizeof(tmp), tmp);
  memcpy(out, tmp, sizeof(tmp));
}
*/
static void aes_128_encrypt_block(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    
    // 初始化加密器，設定為 AES 128 ECB 模式
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    
    // 因為 milenage 的數學運算固定是 16 bytes，不需要自動補齊 (padding)
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    // 執行加密
    EVP_EncryptUpdate(ctx, out, &len, in, 16);
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    
    // 釋放記憶體
    EVP_CIPHER_CTX_free(ctx);
}

static bool milenage_f1(const uint8_t *opc,
                        const uint8_t *k,
                        const uint8_t *_rand,
                        const uint8_t *sqn,
                        const uint8_t *amf,
                        uint8_t *mac_a,
                        uint8_t *mac_s)
{
  uint8_t tmp1[16], tmp2[16], tmp3[16];
  int i;

  /* tmp1 = TEMP = E_K(RAND XOR OP_C) */
  for (i = 0; i < 16; i++)
    tmp1[i] = _rand[i] ^ opc[i];

  aes_128_encrypt_block(k, tmp1, tmp1);

  uint8_t cyphered[16] = {0};
  aes_128_encrypt_block(k, tmp1, cyphered);

  /* tmp2 = IN1 = SQN || AMF || SQN || AMF */
  memcpy(tmp2, sqn, 6);
  memcpy(tmp2 + 6, amf, 2);
  memcpy(tmp2 + 8, tmp2, 8);

  /* OUT1 = E_K(TEMP XOR rot(IN1 XOR OP_C, r1) XOR c1) XOR OP_C */

  /* rotate (tmp2 XOR OP_C) by r1 (= 0x40 = 8 bytes) */
  for (i = 0; i < 16; i++)
    tmp3[(i + 8) % 16] = tmp2[i] ^ opc[i];

  /* XOR with TEMP = E_K(RAND XOR OP_C) */
  for (i = 0; i < 16; i++)
    tmp3[i] ^= tmp1[i];

  /* XOR with c1 (= ..00, i.e., NOP) */
  /* f1 || f1* = E_K(tmp3) XOR OP_c */
  aes_128_encrypt_block(k, tmp3, tmp1);

  for (i = 0; i < 16; i++)
    tmp1[i] ^= opc[i];

  if (mac_a)
    memcpy(mac_a, tmp1, 8); /* f1 */

  if (mac_s)
    memcpy(mac_s, tmp1 + 8, 8); /* f1* */

  return true;
}

/**
   milenage_f2345 - Milenage f2, f3, f4, f5, f5* algorithms
   @opc: OPc = 128-bit value derived from OP and K
   @k: K = 128-bit subscriber key
   @_rand: RAND = 128-bit random challenge
   @res: Buffer for RES = 64-bit signed response (f2), or %NULL
   @ck: Buffer for CK = 128-bit confidentiality key (f3), or %NULL
   @ik: Buffer for IK = 128-bit integrity key (f4), or %NULL
   @ak: Buffer for AK = 48-bit anonymity key (f5), or %NULL
   @akstar: Buffer for AK = 48-bit anonymity key (f5*), or %NULL
   Returns: true on success, false on failure
*/
static bool milenage_f2345(const uint8_t *opc,
                           const uint8_t *k,
                           const uint8_t *_rand,
                           uint8_t *res,
                           uint8_t *ck,
                           uint8_t *ik,
                           uint8_t *ak,
                           uint8_t *akstar)
{
  uint8_t tmp1[16], tmp2[16], tmp3[16];
  int i;

  /* tmp2 = TEMP = E_K(RAND XOR OP_C) */
  for (i = 0; i < 16; i++)
    tmp1[i] = _rand[i] ^ opc[i];

  aes_128_encrypt_block(k, tmp1, tmp2);

  /* OUT2 = E_K(rot(TEMP XOR OP_C, r2) XOR c2) XOR OP_C */
  /* OUT3 = E_K(rot(TEMP XOR OP_C, r3) XOR c3) XOR OP_C */
  /* OUT4 = E_K(rot(TEMP XOR OP_C, r4) XOR c4) XOR OP_C */
  /* OUT5 = E_K(rot(TEMP XOR OP_C, r5) XOR c5) XOR OP_C */

  /* f2 and f5 */
  /* rotate by r2 (= 0, i.e., NOP) */
  for (i = 0; i < 16; i++)
    tmp1[i] = tmp2[i] ^ opc[i];

  tmp1[15] ^= 1; /* XOR c2 (= ..01) */
  /* f5 || f2 = E_K(tmp1) XOR OP_c */
  aes_128_encrypt_block(k, tmp1, tmp3);

  for (i = 0; i < 16; i++)
    tmp3[i] ^= opc[i];

  if (res)
    memcpy(res, tmp3 + 8, 8); /* f2 */

  if (ak)
    memcpy(ak, tmp3, 6); /* f5 */

  /* f3 */
  if (ck) {
    /* rotate by r3 = 0x20 = 4 bytes */
    for (i = 0; i < 16; i++)
      tmp1[(i + 12) % 16] = tmp2[i] ^ opc[i];

    tmp1[15] ^= 2; /* XOR c3 (= ..02) */
    aes_128_encrypt_block(k, tmp1, ck);

    for (i = 0; i < 16; i++)
      ck[i] ^= opc[i];
  }

  /* f4 */
  if (ik) {
    /* rotate by r4 = 0x40 = 8 bytes */
    for (i = 0; i < 16; i++)
      tmp1[(i + 8) % 16] = tmp2[i] ^ opc[i];

    tmp1[15] ^= 4; /* XOR c4 (= ..04) */
    aes_128_encrypt_block(k, tmp1, ik);

    for (i = 0; i < 16; i++)
      ik[i] ^= opc[i];
  }

  /* f5* */
  if (akstar) {
    /* rotate by r5 = 0x60 = 12 bytes */
    for (i = 0; i < 16; i++)
      tmp1[(i + 4) % 16] = tmp2[i] ^ opc[i];

    tmp1[15] ^= 8; /* XOR c5 (= ..08) */
    aes_128_encrypt_block(k, tmp1, tmp1);

    for (i = 0; i < 6; i++)
      akstar[i] = tmp1[i] ^ opc[i];
  }

  return true;
}

/**
   milenage_generate - Generate AKA AUTN,IK,CK,RES
   @opc: OPc = 128-bit operator variant algorithm configuration field (encr.)
   @amf: AMF = 16-bit authentication management field
   @k: K = 128-bit subscriber key
   @sqn: SQN = 48-bit sequence number
   @_rand: RAND = 128-bit random challenge
   @autn: Buffer for AUTN = 128-bit authentication token
   @ik: Buffer for IK = 128-bit integrity key (f4), or %NULL
   @ck: Buffer for CK = 128-bit confidentiality key (f3), or %NULL
   @res: Buffer for RES = 64-bit signed response (f2), or %NULL
   @res_len: Max length for res; set to used length or 0 on failure
*/
static bool milenage_generate(const uint8_t *opc,
                              const uint8_t *amf,
                              const uint8_t *k,
                              const uint8_t *sqn,
                              const uint8_t *_rand,
                              uint8_t *autn,
                              uint8_t *ik,
                              uint8_t *ck,
                              uint8_t *res)
{
  int i;
  uint8_t mac_a[8], ak[6];

  if (!milenage_f1(opc, k, _rand, sqn, amf, mac_a, NULL) ||
      !milenage_f2345(opc, k, _rand, res, ck, ik, ak, NULL))
    return false;

  /* AUTN = (SQN ^ AK) || AMF || MAC */
  for (i = 0; i < 6; i++)
    autn[i] = sqn[i] ^ ak[i];

  memcpy(autn + 6, amf, 2);
  memcpy(autn + 8, mac_a, 8);
  return true;
}



#endif