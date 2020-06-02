
#include "encrypt.h"
#include "ntt.h"
#include "ntt_const.h"
#include <openssl/sha.h>
#include <immintrin.h>
#include <time.h>

clock_t elapsed, start;
float sec;
#define START_WATCH \
{\
 elapsed = -clock(); \
}\

#define STOP_WATCH \
{\
 elapsed += clock();\
 sec = (float)elapsed/CLOCKS_PER_SEC;\
}\

#define PRINT_TIME(qstr) \
{\
 printf("\n[%s: %.5f s]\n",qstr,sec);\
}\


double time_keygen = 0, time_enc = 0, time_dec = 0;
void _BINT_to_OS(unsigned char *a, unsigned int *in, int os_len)
{

	int i;

	for (i = 0; i < os_len; i++)
	{
		a[i] = (in[i >> 2] >> (24 - 8 * (i % 4))) & 0xff;
	}


}

void _OS_to_BINT(unsigned int *a, unsigned char *os, int bint_len)
{
	int i;


	for (i = 0; i < (bint_len); i++)
	{
		a[i] = ((unsigned int)os[(i << 2)] & 0xff) << 24;
		a[i] ^= ((unsigned int)os[(i << 2) + 1] & 0xff) << 16;
		a[i] ^= ((unsigned int)os[(i << 2) + 2] & 0xff) << 8;
		a[i] ^= ((unsigned int)os[(i << 2) + 3] & 0xff);

	}

}

void SHA256_INT (unsigned int *Msg, unsigned int MLen, unsigned int *Digest)
{
	unsigned char *M_tmp;
	unsigned char D_tmp[32];

	M_tmp = (unsigned char*)calloc(MLen, sizeof(unsigned char));
	_BINT_to_OS(M_tmp, Msg, MLen);
	
	SHA256(M_tmp, MLen, D_tmp);

	_OS_to_BINT (Digest, D_tmp, 8);


}

void CRYPTO_R_pub_init(CRYPTO_R_pub_t pPubKey)
{
	pPubKey->A = (int*)calloc(CRYPTO_R_n, sizeof(int));
	pPubKey->B = (int*)calloc(CRYPTO_R_n, sizeof(int));

}


void CRYPTO_R_pub_clear(CRYPTO_R_pub_t pPubKey)
{
	free(pPubKey->A);
	free(pPubKey->B);

}

/* Generates random number modulo q */
int random_modq()
{
	int tmp;
	int check;

	tmp = (rand() & 0xff) | ((rand() & 0xf) << 8);
	check = tmp % CRYPTO_R_q;

	return check;
}

int CDT_TABLE[5] = { 136, 264, 373, 455, 510 };

/* Gaussain sampling from CDT table */
int Sample_CDT(int seed)
{
	int r, sign, sample;
	int i;

	if (seed != 0)
		srand(seed);

	r = rand() & 0x1ff; //11bit
	sign = rand() & 1;
	sample = 0;

	for (i = 0; i<5 - 1; i++)
		sample += (CDT_TABLE[i] - r) >> 11;

	sample = ((-sign) ^ sample) + sign;
	return sample;

}

/* Key generation function : public and private keys are in NTT domain */
int CRYPTO_R_KeyGen(CRYPTO_R_pub_t pPubKey, int *pPriKey)
{
	int i;
START_WATCH;
	/* STEP 1 : Choose a, x, e */
	for (i = 0; i < CRYPTO_R_n; i++)
		pPubKey->A[i] = random_modq();

	for (i = 0; i < CRYPTO_R_n; i++)
		pPriKey[i] = ((rand() % 3 + 1) - 2);

	for (i = 0; i < CRYPTO_R_n; i++)
		pPubKey->B[i] = Sample_CDT(0); 

	/* STEP 2 : b = a*x+e */
	NTT(pPubKey->A, CRYPTO_R_NTT, CRYPTO_R_n);
	NTT(pPriKey, CRYPTO_R_NTT, CRYPTO_R_n);
	NTT(pPubKey->B, CRYPTO_R_NTT, CRYPTO_R_n);
	pmuladd(pPubKey->A, pPriKey, pPubKey->B, pPubKey->B, CRYPTO_R_n);
STOP_WATCH;
time_keygen+=sec;
	return 0;
}


/* CPA encryption function */
int CRYPTO_R_Enc(int *C, unsigned int *M, CRYPTO_R_pub_t pPubKey)
{
	int *m_hat, *r, *e1, *e2;
	int tmp1[CRYPTO_R_n], tmp2[CRYPTO_R_n];
	int i;


	m_hat = (int*)calloc(CRYPTO_R_n, sizeof(int));
	r = (int*)calloc(CRYPTO_R_n, sizeof(int));
	e1 = (int*)calloc(CRYPTO_R_n, sizeof(int));
	e2 = (int*)calloc(CRYPTO_R_n, sizeof(int));

	/* STEP 1 : R_encode */
	for (i = 0; i < CRYPTO_R_msg; i++)
	{
		m_hat[i] ^= 0x800;
		m_hat[i] ^= ((M[i >> 5] >> (31 - (i % 32))) & 1) << 12;
	}


	/* STEP 2 : Generate random r */
	for (i = 0; i < CRYPTO_R_n; i++)
	{
		r[i] = ((rand() % 3 + 1) - 2);
	}

	for (i = 0; i < CRYPTO_R_n; i++)
		e1[i] = Sample_CDT(0);

	for (i = 0; i < CRYPTO_R_n; i++)
		e2[i] = Sample_CDT(0);

	NTT(r, CRYPTO_R_NTT, CRYPTO_R_n);

	/* STEP 3 : C1 = R^T x A + E_1 */
	pmul(pPubKey->A, r, tmp1, CRYPTO_R_n);
	INTT(tmp1, CRYPTO_R_INTT, CRYPTO_N_INV, CRYPTO_R_n);
	padd(tmp1, e1, e1, CRYPTO_R_q, CRYPTO_R_n); 


	/* STEP 4 : C2 = R^T x B + E_1 + M */
	pmul(pPubKey->B, r, tmp2, CRYPTO_R_n);
	INTT(tmp2, CRYPTO_R_INTT, CRYPTO_N_INV, CRYPTO_R_n);

	padd(tmp2, e2, e2, CRYPTO_R_q, CRYPTO_R_n);
	padd(e2, m_hat, e2, CRYPTO_R_q, CRYPTO_R_n);

	/* STEP 5 : C = C1 || C2 */
	memcpy(C, e1, CRYPTO_R_n * sizeof(int));
	memcpy(C + (CRYPTO_R_n), e2, CRYPTO_R_msg * sizeof(int));

	free(m_hat);
	free(r);
	free(e1);
	free(e2);

	return 0;
}


/* CPA decryption function */
int CRYPTO_R_dec(unsigned int *M, int *C, int *pPriKey)
{
	int *d, *m_hat, *C_cpy;
	int i;

	d = (int*)calloc(CRYPTO_R_n, sizeof(int));
	m_hat = (int*)calloc(CRYPTO_R_n, sizeof(int));
	C_cpy = (int*)calloc(CRYPTO_R_n, sizeof(int));

	/* Ciphertext to NTT domain */
	NTT_new(C_cpy, C, CRYPTO_R_NTT, CRYPTO_R_n);
	pmul(C_cpy, pPriKey, d, CRYPTO_R_n);
	INTT(d, CRYPTO_R_INTT, CRYPTO_N_INV, CRYPTO_R_n);

	for (i = 0; i < CRYPTO_R_msg; i++)
	{
		m_hat[i] = (C[i + CRYPTO_R_n] - d[i]) % CRYPTO_R_q;
		if (m_hat[i] < 0) m_hat[i] += CRYPTO_R_q;

	}

	memset(M, 0, 8 * sizeof(int));

	for (i = 0; i < CRYPTO_R_msg; i++)
	{

		M[i >> 5] ^= ((m_hat[i] >> 12) & 1) << (31 - (i % 32));

	}

	free(d);
	free(m_hat);
	free(C_cpy);

	return 0;
}


/* CPA encryption module for CCA.KEM */
int _R_KEM_Enc(int *C, unsigned int *delta, CRYPTO_R_pub_t pPubKey, int *r, int seed)
{
	int *m_hat, *e1, *e2;
	int i;
	int tmp1[CRYPTO_R_n], tmp2[CRYPTO_R_n];

	m_hat = (int*)calloc(CRYPTO_R_n, sizeof(int));
	e1 = (int*)calloc(CRYPTO_R_n, sizeof(int));
	e2 = (int*)calloc(CRYPTO_R_n, sizeof(int));

	/* STEP 1 : R_encode */
	for (i = 0; i < CRYPTO_R_msg; i++)
	{

		m_hat[i] ^= 0x800;
		m_hat[i] ^= ((delta[i >> 5] >> (31 - (i % 32))) & 1) << 12;

	}

	for (i = 0; i < CRYPTO_R_n; i++)
		e1[i] = Sample_CDT(seed);

	for (i = 0; i < CRYPTO_R_n; i++)
		e2[i] = Sample_CDT(seed);

	NTT(r, CRYPTO_R_NTT, CRYPTO_R_n);

	/* STEP 3 : C1 = R^T x A + E_1 */
	pmul(pPubKey->A, r, tmp1, CRYPTO_R_n);
	INTT(tmp1, CRYPTO_R_INTT, CRYPTO_N_INV, CRYPTO_R_n);
	padd(tmp1, e1, e1, CRYPTO_R_q, CRYPTO_R_n);


	/* STEP 4 : C2 = R^T x B + E_1 + M */
	pmul(pPubKey->B, r, tmp2, CRYPTO_R_n);
	INTT(tmp2, CRYPTO_R_INTT, CRYPTO_N_INV, CRYPTO_R_n);
	padd(tmp2, e2, e2, CRYPTO_R_q, CRYPTO_R_n);
	padd(e2, m_hat, e2, CRYPTO_R_q, CRYPTO_R_n);

	/* STEP 5 : C = C1 || C2 */
	memcpy(C, e1, CRYPTO_R_n * sizeof(int));
	memcpy(C + (CRYPTO_R_n), e2, CRYPTO_R_msg * sizeof(int));

	free(m_hat);
	free(e1);
	free(e2);

	return 0;
}


/* CPA decryption module for CCA.KEM */
int _R_KEM_dec(unsigned int *delta, int *C, int *pPriKey)
{
	int *d, *m_hat, *C_cpy;
	int i;

	d = (int*)calloc(CRYPTO_R_n, sizeof(int));
	m_hat = (int*)calloc(CRYPTO_R_n, sizeof(int));
	C_cpy = (int*)calloc(CRYPTO_R_n, sizeof(int));

	NTT_new(C_cpy, C, CRYPTO_R_NTT, CRYPTO_R_n);
	pmul(C_cpy, pPriKey, d, CRYPTO_R_n);
	INTT(d, CRYPTO_R_INTT, CRYPTO_N_INV, CRYPTO_R_n);

	for (i = 0; i < CRYPTO_R_msg; i++)
	{

		m_hat[i] = (C[i + CRYPTO_R_n] - d[i]) % CRYPTO_R_q;
		if (m_hat[i] < 0) m_hat[i] += CRYPTO_R_q;
		

	}

	memset(delta, 0, 8 * sizeof(int));
	for (i = 0; i < CRYPTO_R_msg; i++)
	{
		delta[i >> 5] ^= ((m_hat[i] >> 12) & 1) << (31 - (i % 32));
	}
	free(d);
	free(m_hat);
	free(C_cpy);
	return 0;
}

/* Generates seed and random number in {-1, 0, 1} from delta */
unsigned int _R_KEM_GenTrinary(int *r, unsigned int *delta)
{
	unsigned int d_tmp[8];
	unsigned int tmp[8];
	int cnt = 0;
	int j;

	memcpy(d_tmp, delta, 8 * sizeof(int));
	memset(tmp, 0, 8 * sizeof(int));

	/* While every coefficient is set */
	while (cnt < CRYPTO_R_n)
	{
		SHA256_INT(d_tmp, CRYPTO_R_msg >> 3, tmp);
		for (j = 0; j < 8; j++)
		{
			while ((tmp[j] != 0) && (cnt<CRYPTO_R_n))
			{
				r[cnt] = (((tmp[j] % 3) + 1) - 2);
				tmp[j] = tmp[j] / 3;
				cnt++;
			}

		}

		d_tmp[0]++;
		memset(tmp, 0, 8 * sizeof(int));

	}

	// Generate Seed
	memcpy(d_tmp, delta, 8 * sizeof(int));
	SHA256_INT(d_tmp, CRYPTO_R_msg >> 3, tmp);

	return tmp[0];

}

/* CCA KEM encapsulation scheme */
int CRYPTO_R_Encap(unsigned int *K, int *C, CRYPTO_R_pub_t pPubKey)
{
	unsigned int delta[9], tmp[8];
	unsigned int seed, KLen;
	unsigned int *K_tmp;
	int *r, *C_KEM;
	int i;

	r = (int*)calloc(CRYPTO_R_n, sizeof(int));
	C_KEM = (int*)calloc(CRYPTO_R_n + CRYPTO_R_msg, sizeof(int));
	K_tmp = (unsigned int*)calloc(CRYPTO_R_n + CRYPTO_R_msg + 16, sizeof(unsigned int));

	KLen = CRYPTO_R_n + CRYPTO_R_msg + 16;
	KLen = KLen << 2;

START_WATCH;
	/* STEP 1 : Select delta */
	for (i = 0; i < 8; i++)
	{
		delta[i] = (rand() & 0xff) | ((rand() & 0xff) << 8) | ((rand() & 0xff) << 16) | ((rand() & 0xff) << 24);
	}

	/* STEP 2 : Generate ciphertext */
	seed = _R_KEM_GenTrinary(r, delta);
	_R_KEM_Enc(C_KEM, delta, pPubKey, r, seed);

	/* STEP 3 : Generate hash */
	delta[8] = 0x02000000;
	SHA256_INT(delta, 33, tmp);

	// C = C1 || H(delta)
	memcpy(C, C_KEM, (CRYPTO_R_n + CRYPTO_R_msg) * sizeof(unsigned int));
	memcpy(C + (CRYPTO_R_n + CRYPTO_R_msg), tmp, 8 * sizeof(unsigned int));

	/* STEP 4 : Generate key */
	// K_tmp = delta || C
	memcpy(K_tmp, delta, 8 * sizeof(unsigned int));
	memcpy(K_tmp + 8, C, (CRYPTO_R_n + CRYPTO_R_msg + 8) * sizeof(unsigned int));


	SHA256_INT(K_tmp, KLen, K);
STOP_WATCH;
time_enc+=sec;
	free(r);
	free(C_KEM);
	free(K_tmp);

	return 0;
}

/* CCA KEM decapsulation scheme */
int CRYPTO_R_Decap(unsigned int *K, int *C, CRYPTO_R_pub_t pPubKey, int *pPriKey)
{
	unsigned int delta[9], tmp[8];
	unsigned int seed, KLen;
	unsigned int *K_tmp;
	int *C_tmp, *r;
	int ret;

	C_tmp = (int*)calloc(CRYPTO_R_n + CRYPTO_R_msg, sizeof(int));
	r = (int*)calloc(CRYPTO_R_n, sizeof(int));
	K_tmp = (unsigned int*)calloc(CRYPTO_R_n + CRYPTO_R_msg + 16, sizeof(unsigned int));

	KLen = CRYPTO_R_n + CRYPTO_R_msg + 16;
	KLen = KLen << 2;
START_WATCH;
	/* STEP 1 : Decrypt and obtain delta */
	_R_KEM_dec(delta, C, pPriKey);

	/* STEP 2 : Generate r and seed from delta */
	seed = _R_KEM_GenTrinary(r, delta);

	/* STEP 3 : Encrypt */
	_R_KEM_Enc(C_tmp, delta, pPubKey, r, seed);


	delta[8] = 0x02000000;
	SHA256_INT(delta, 33, tmp);


	if (memcmp(C_tmp, C, (CRYPTO_R_n + CRYPTO_R_msg) * sizeof(int)) != 0)
	{
		ret = -1;
		goto err;
	}

	if (memcmp(tmp, C + (CRYPTO_R_n + CRYPTO_R_msg), 8 * sizeof(int)) != 0)
	{
		ret = -1;
		goto err;
	}

	/* STEP 4 : Generate key*/
	memcpy(K_tmp, delta, 8 * sizeof(unsigned int));
	memcpy(K_tmp + 8, C, (CRYPTO_R_n + CRYPTO_R_msg + 8) * sizeof(unsigned int));

	SHA256_INT(K_tmp, KLen, K);

STOP_WATCH;
time_dec+=sec;
err:

	free(C_tmp);
	free(r);
	free(K_tmp);

	return 0;
}



void main()
{

	int pPriKey[CRYPTO_R_n], C[CRYPTO_R_n + CRYPTO_R_msg], C_CCA[CRYPTO_R_n + CRYPTO_R_msg + 8];
	unsigned int Msg[8] = { 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f };
	unsigned int MsgPrime[8];
	unsigned int K[8], KPrime[8];

	int i, j;
	int loop = 10000;


	CRYPTO_R_pub_t pPubKey;
	CRYPTO_R_pub_init(pPubKey);

	


	/* R-CPA Test */
/*
	for (i = 0; i < 10000; i++)
	{
	
		CRYPTO_R_Enc(C, Msg, pPubKey);
		CRYPTO_R_dec(MsgPrime, C, pPriKey);
	
	
	
		for (j = 0; j < 8; j++)
		{
			if (Msg[j] != MsgPrime[j])
			{
				printf(" ERROR CPA %d !! \n", i);
				return;
			}
		}
		memset(MsgPrime, 0, 8 * sizeof(int));
		memset(C, 0, (CRYPTO_R_n + CRYPTO_R_msg) * sizeof(int));
		printf(" Round  %d !! \n", i);
	}
*/

	/* R-CCA Test */
	for (i = 0; i < loop; i++)
	{
	
		CRYPTO_R_KeyGen(pPubKey, pPriKey);
		CRYPTO_R_Encap(K, C_CCA, pPubKey);
		CRYPTO_R_Decap(KPrime, C_CCA, pPubKey, pPriKey);
	
		for (j = 0; j < 8; j++)
		{
			if (K[j] != KPrime[j])
			{
				printf(" ERROR %d !! \n", i);
	//
				return;
			}
		}
	
		memset(KPrime, 0, 8 * sizeof(int));
		//printf(" Round  %d !! \n", i);
	}
	
	printf(" Keygen Time  : %.5f ms \n", ((time_keygen / loop) * 1000));
	printf(" Encryption Time  : %.5f ms \n", ((time_enc / loop) * 1000));
	printf(" Decryption Time  : %.5f ms \n", ((time_dec / loop) * 1000));
	CRYPTO_R_pub_clear(pPubKey);

}
