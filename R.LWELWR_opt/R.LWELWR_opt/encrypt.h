#pragma once
#include "param.h"
#include "ntt.h"

void CRYPTO_R_pub_init(CRYPTO_R_pub_t pPubKey);
void CRYPTO_R_pub_clear(CRYPTO_R_pub_t pPubKey);


int CRYPTO_R_KeyGen(CRYPTO_R_pub_t pPubKey, int *pPriKey);

int CRYPTO_R_Enc(int *C, unsigned int *M, CRYPTO_R_pub_t pPubKey);
int CRYPTO_R_dec(unsigned int *M, int *C, int *pPriKey);

int CRYPTO_R_Encap(unsigned int *K, int *C, CRYPTO_R_pub_t pPubKey);
int CRYPTO_R_Decap(unsigned int *K, int *C, CRYPTO_R_pub_t pPubKey, int *pPriKey);
