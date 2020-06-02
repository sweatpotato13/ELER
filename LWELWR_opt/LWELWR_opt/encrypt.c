
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include "param.h"

//#include "SHA256.h"
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

int shift_right = CRYPTO_logp - 8;
int index = CRYPTO_v * CRYPTO_n;
int idx = CRYPTO_v * CRYPTO_k;
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
void CRYPTO_public_init(CRYPTO_public_t pPubKey, int s1, int s2)
{
	pPubKey->A = (int*)calloc(s1, sizeof(int));
	pPubKey->B = (int*)calloc(s2, sizeof(int));

}

void CRYPTO_public_clear(CRYPTO_public_t pPubKey)
{
	free(pPubKey->A);
	free(pPubKey->B);
}

/* Generates seed and random number in {-1, 0, 1} from delta */
unsigned int _KEM_GenTrinary(int *r, unsigned int *delta, int CNT)
{
	unsigned int d_tmp[9];
	unsigned int tmp[8];
	int cnt = 0;
	int j;

	memcpy(d_tmp, delta, 8 * sizeof(int));
	memset(tmp, 0, 8 * sizeof(int));

	while (cnt < CNT)
	{
		SHA256_INT(d_tmp, CRYPTO_msg, tmp);
		for (j = 0; j < 8; j++)
		{
			while ((tmp[j] != 0) && (cnt<CNT))
			{
				r[cnt] = (((tmp[j] % CRYPTO_RGen) + 1) - 2);
				tmp[j] = tmp[j] / CRYPTO_RGen;
				cnt++;
			}

		}

		d_tmp[0]++;
		memset(tmp, 0, 8 * sizeof(int));

	}

	// Generate Seed
	memcpy(d_tmp, delta, 8 * sizeof(int));
	SHA256_INT(d_tmp, 32, tmp);

	return tmp[0];

}

int CDT_TABLE[54] = { 65, 130, 196, 259, 323, 387, 450, 512, 574, 635, 695,
754, 812, 869, 924, 978, 1031, 1082, 1132, 1180, 1227, 1272, 1316, 1358, 1399, 1438, 1476, 1512, 1546,
1580, 1611, 1641, 1669, 1696, 1721, 1745, 1768, 1789, 1809, 1828, 1846, 1863, 1878, 1892, 1905, 1917, 1929, 1940, 1950, 1959, 1967, 1974, 1980, 1985 };

/* Gaussain sampling from CDT table */
int Sample_CDT(int seed)
{
	int r, sign, sample;
	int i;

	if (seed != 0)
		srand(seed);

	r = rand() & 0x7ff; //11bit
	sign = rand() & 1;
	sample = 0;

	for (i = 0; i<54 - 1; i++)
		sample += (CDT_TABLE[i] - r) >> 11;

	sample = ((-sign) ^ sample) + sign;
	return sample;

}

/* Key generation function : public and private keys */
int inline CRYPTO_KeyGen(CRYPTO_public_t pPubKey, int *pPriKey)
{
	int i, j, k;
	int ret = 0;
	int cnt = 0;
	unsigned int d_tmp[9];
	unsigned int tmp[8];
	int val = CRYPTO_m * CRYPTO_n;
	int tmp1, tmp2;

	memset(d_tmp, 0, 8 * sizeof(int));
	if (pPubKey == NULL || pPriKey == NULL)
	{
		ret = CRYPTO_ERR_KEYGEN_OUTPUT_NOT_INITIALIZED;
		goto err;
	}
	START_WATCH;
	//for (i = 0; i < CRYPTO_m*CRYPTO_n; i++) {
	//	pPubKey->A[i] = (rand() & 0xff) | ((rand() & 0xff)<<8);
	//}
	/* Public Key A Generation */
	for (i = 0; i < val/16; i++) {
		SHA256_INT(d_tmp, CRYPTO_msg, tmp);
		for (j = 0; j < 8; j++) {
			tmp1 = tmp[j] >> 16;
			tmp2 = tmp[j] & 0x0000ffff;
			pPubKey->A[(i * 16) + (j * 2)] = tmp1;
			pPubKey->A[(i * 16) + (j * 2) + 1] = tmp2;
		}
	}

	for (i = 0; i < CRYPTO_n*CRYPTO_k; i++)
		pPriKey[i] = ((rand() % 5 + 1) - 3);
	

	for (i = 0; i < CRYPTO_m*CRYPTO_k; i++)
		pPubKey->B[i] = Sample_CDT(0);


	/* Public Key B Generation */


	for (i = 0; i < CRYPTO_m; ++i)
	{
		int* A = pPubKey->A + CRYPTO_n * i;
		int* B = pPubKey->B + CRYPTO_k * i;

		for (k = 0; k < CRYPTO_n; ++k)
		{
			int* pk = pPriKey + CRYPTO_k * k;
			int A_ik = A[k];

			for (j = 0; j < CRYPTO_k; ++j)
			{
				B[j] += A_ik * pk[j];
				B[j] = B[j] & CRYPTO_MASK;
			}
		}
	}
	STOP_WATCH;
	time_keygen += sec;
err:

	return ret;
}

/* CPA encryption function */
int CRYPTO_Enc(int *pCipher, CRYPTO_public_t pPubKey, unsigned int *Msg, int MsgLen)
{
	int *M, *X, *Y, *r;

	int	i, j, k;
	int	ret = 0, cnt = 0;

	int shift_left = CRYPTO_logq - CRYPTO_t;

	r = (int*)calloc(CRYPTO_m*CRYPTO_v, sizeof(int));
	M = (int*)calloc(CRYPTO_v*CRYPTO_k, sizeof(int));
	X = (int*)calloc(CRYPTO_v*CRYPTO_n, sizeof(int));
	Y = (int*)calloc(CRYPTO_v*CRYPTO_k, sizeof(int));

	if (pPubKey == NULL)
	{
		ret = CRYPTO_ERR_ENC_PARAMETER;
		goto err;
	}

	if (Msg == NULL)
	{
		ret = CRYPTO_ERR_ENC_MISSING_MSG;
		goto err;
	}


	if (MsgLen == NULL)
	{
		ret = CRYPTO_ERR_ENC_MSGLEN_ERROR;
		goto err;
	}

	if (pCipher == NULL)
	{
		ret = CRYPTO_ERR_ENC_NOT_INITIALIZED;
		goto err;
	}

	START_WATCH
	/* STEP 1 : Message matrix Generation */
	for (i = 0; i < CRYPTO_v*CRYPTO_k; i++)
	{
		M[i] ^= 0x8000; // 10
		M[i] ^= (((Msg[i >> 2] >> (24 - 8 * (i % 4))) & 0xff) << (shift_left));
	}

	/* STEP 2 : random matrix Generation */
	for (i = 0; i<CRYPTO_m*CRYPTO_v; i++) //transposed 
		r[i] = ((rand() % 5 + 1) - 3);

	/* STEP 3 : Error matrix generation */
	//for (i = 0; i<CRYPTO_v*CRYPTO_n; i++)
	//	X[i] = Sample_CDT(0);
	//
	//for (i = 0; i<CRYPTO_v*CRYPTO_k; i++)
	//	Y[i] = Sample_CDT(0);


	for (i = 0; i < CRYPTO_v; ++i)
	{
		int* pR = r + (CRYPTO_m * i);
		int* pX = X + (CRYPTO_n * i);

		for (k = 0; k < CRYPTO_m; ++k)
		{
			int* pA = pPubKey->A + (CRYPTO_n * k);
			int pRk = pR[k];

			for (j = 0; j < CRYPTO_n; ++j)
			{
				pX[j] += pRk * pA[j];
				pX[j] = pX[j] & CRYPTO_MASK;
			}
		}
	}

	for (i = 0; i < CRYPTO_v; ++i)
	{
		int* pR = r + (CRYPTO_m * i);
		int* pY = Y + (CRYPTO_k * i);

		for (k = 0; k < CRYPTO_m; ++k)
		{
			int* pB = pPubKey->B + (CRYPTO_k * k);
			int pRk = pR[k];

			for (j = 0; j < CRYPTO_k; ++j)
			{
				pY[j] += pRk * pB[j];
				pY[j] = pY[j] & CRYPTO_MASK;
			}
		}
	}
	_Rounding(X, CRYPTO_v, CRYPTO_n);
	_Rounding(Y, CRYPTO_v, CRYPTO_k);
	_Rounding(M, CRYPTO_v, CRYPTO_k);
	_MatADD(Y, Y, M, CRYPTO_v, CRYPTO_k);
	STOP_WATCH
	time_enc += sec;
	memcpy(pCipher, X, CRYPTO_v*CRYPTO_n * sizeof(int));
	memcpy(pCipher + CRYPTO_v*CRYPTO_n, Y, CRYPTO_v*CRYPTO_k * sizeof(int));


err:


	free(r);
	free(M);
	free(X);
	free(Y);

	return ret;

}

/* CPA decryption function */
int CRYPTO_Dec(unsigned int *Msg, int *pPriKey, int *pCipher)
{

	int i, j, k;
	int MsgByteLen;
	int ret = 0;
	int cnt = 0;
	int *Mprime;

	Mprime = (int*)calloc(CRYPTO_v*CRYPTO_k, sizeof(int));

	START_WATCH
	for (i = 0; i < CRYPTO_v; ++i)
	{
		int* pX = pCipher + (CRYPTO_n * i);
		int* pM = Mprime + (CRYPTO_k * i);

		for (k = 0; k < CRYPTO_n; ++k)
		{
			int* pK = pPriKey + (CRYPTO_k * k);
			int pXk = pX[k];

			for (j = 0; j < CRYPTO_k; ++j)
			{
				pM[j] += pXk * pK[j];
				pM[j] = pM[j] & CRYPTO_MASK;
			}
		}
	}

	int shift_right = CRYPTO_logp - 8;
	int index = CRYPTO_v * CRYPTO_n;
	for (i = 0; i < CRYPTO_v*CRYPTO_k; i++)
	{

		Mprime[i] = (pCipher[i + index] - Mprime[i])& CRYPTO_MASK;
		Mprime[i] = Mprime[i] >> (shift_right);
	}

	for (i = 0; i < 8; i++)
	{
		Msg[i] = ((unsigned int)Mprime[(i << 2)] & 0xff) << 24;
		Msg[i] ^= ((unsigned int)Mprime[(i << 2) + 1] & 0xff) << 16;
		Msg[i] ^= ((unsigned int)Mprime[(i << 2) + 2] & 0xff) << 8;
		Msg[i] ^= ((unsigned int)Mprime[(i << 2) + 3] & 0xff);

	}
	STOP_WATCH;
	time_dec += sec;
	free(Mprime);
	return ret;
}

/* CPA encryption module for CCA.KEM */
int _KEM_Enc(int *C1, CRYPTO_public_t pPubKey, int *r, unsigned int *Msg, int MsgLen, unsigned int seed)
{

	int	i, j, k;
	int *M, *X, *Y;
	int	ret = 0;

	M = (int*)calloc(CRYPTO_v*CRYPTO_k, sizeof(int));
	X = (int*)calloc(CRYPTO_v*CRYPTO_n, sizeof(int));
	Y = (int*)calloc(CRYPTO_v*CRYPTO_k, sizeof(int));

	/* STEP 1 : Message matrix Generation */

	for (i = 0; i < CRYPTO_v*CRYPTO_k; i++)
	{
		M[i] ^= 0x8000; // 10
		M[i] ^= (((Msg[i >> 2] >> (24 - 8 * (i % 4))) & 0xff) << (CRYPTO_logq - CRYPTO_t));
	}

	/* STEP 3 : Error matrix generation */

	//for (i = 0; i < CRYPTO_v*CRYPTO_n; i++)
	//	X[i] = Sample_CDT(seed);
	//
	//for (i = 0; i<CRYPTO_v*CRYPTO_k; i++)
	//	Y[i] = Sample_CDT(seed);


	/* Transpose Public Key for faster multiplication */
	for (i = 0; i < CRYPTO_v; ++i)
	{
		int* pR = r + (CRYPTO_m * i);
		int* pX = X + (CRYPTO_n * i);

		for (k = 0; k < CRYPTO_m; ++k)
		{
			int* pK = pPubKey->A + (CRYPTO_n * k);
			int pRk = pR[k];

			for (j = 0; j < CRYPTO_n; ++j)
			{
				pX[j] += pRk * pK[j];
				pX[j] = pX[j] & CRYPTO_MASK;
			}
		}
	}

	for (i = 0; i < CRYPTO_v; ++i)
	{
		int* pR = r + (CRYPTO_m * i);
		int* pY = Y + (CRYPTO_k * i);

		for (k = 0; k < CRYPTO_m; ++k)
		{
			int* pK = pPubKey->B + (CRYPTO_k * k);
			int pRk = pR[k];

			for (j = 0; j < CRYPTO_k; ++j)
			{
				pY[j] += pRk * pK[j];
				pY[j] = pY[j] & CRYPTO_MASK;
			}
		}
	}
	_Rounding(X, CRYPTO_v, CRYPTO_n);
	_Rounding(Y, CRYPTO_v, CRYPTO_k);
	_Rounding(M, CRYPTO_v, CRYPTO_k);
	_MatADD(Y, Y, M, CRYPTO_v, CRYPTO_k);

	memcpy(C1, X, CRYPTO_v*CRYPTO_n * sizeof(int));
	memcpy(C1 + CRYPTO_v*CRYPTO_n, Y, CRYPTO_v*CRYPTO_k * sizeof(int));

	free(M);
	free(X);
	free(Y);

	return ret;

}

/* CPA decryption module for CCA.KEM */
int _KEM_Dec(unsigned int *Msg, int *pPriKey, int *pCipher)
{

	int i, j, k, *MP;
	int MsgByteLen;
	int ret = 0;

	MP = (int*)calloc(CRYPTO_v*CRYPTO_k, sizeof(int));

	for (i = 0; i < CRYPTO_v; ++i)
	{
		int* pX = pCipher + (CRYPTO_n * i);
		int* pM = MP + (CRYPTO_k * i);

		for (k = 0; k < CRYPTO_n; ++k)
		{
			int* pK = pPriKey + (CRYPTO_k * k);
			int pXk = pX[k];

			for (j = 0; j < CRYPTO_k; ++j)
			{
				pM[j] += pXk * pK[j];
				pM[j] = pM[j] & CRYPTO_MASK;
			}
		}
	}


	for (i = 0; i < idx; i++)
	{

		MP[i] = (pCipher[i + index] - MP[i])& CRYPTO_MASK;
		MP[i] = MP[i] >> (shift_right);
		//__dropBits(MP[i], MP[i]);
	}

	for (i = 0; i < 8; i++)
	{
		int a = i << 2;
		Msg[i]  = ((unsigned int)MP[(a)] & 0xff) << 24;
		Msg[i] ^= ((unsigned int)MP[(a) + 1] & 0xff) << 16;
		Msg[i] ^= ((unsigned int)MP[(a) + 2] & 0xff) << 8;
		Msg[i] ^= ((unsigned int)MP[(a) + 3] & 0xff);

	}

	free(MP);
	return ret;
}

/* CCA KEM encapsulation scheme */
int CRYPTO_KEM_Encap(unsigned int *Key, int *pCipher, CRYPTO_public_t pPubKey)
{
	unsigned int delta[9], tmp[8] = {0,};
	unsigned int *KeyIn;
	unsigned int seed_in;
	int i, KLen, CLen;
	int *r;
	int ret = CRYPTO_OK;


	/* Input length to generate key = delta+C1 len <<2, C_2*/
	KLen = 16 + ((CRYPTO_v*(CRYPTO_n + CRYPTO_k)));
	CLen = CRYPTO_v*(CRYPTO_n + CRYPTO_k) + 8;

	r = (int*)calloc(CRYPTO_m*CRYPTO_v, sizeof(int*));
	KeyIn = (unsigned int*)calloc(KLen, sizeof(unsigned int*));

	START_WATCH;
	/* STEP 1 : Select random 256 bit sizeof v*k */
	//for (i = 0; i < 8; i++)
	//{
	//	delta[i] = (rand() & 0xff) | ((rand() & 0xff) << 8) | ((rand() & 0xff) << 16) | ((rand() & 0xff) << 24);
	//}
	SHA256_INT(tmp, CRYPTO_msg, delta);

	/* STEP 2 : r=G(delta), C_1=Enc(delta) */
	seed_in = _KEM_GenTrinary(r, delta, CRYPTO_m*CRYPTO_v);
	_KEM_Enc(pCipher, pPubKey, r, delta, CRYPTO_delta << 3, seed_in);

	/* STEP 3 : C2=H(delta||02)*/
	delta[8]=0x02000000;
	SHA256_INT(delta, 33, tmp);

	memcpy(pCipher + CRYPTO_v*(CRYPTO_n + CRYPTO_k), tmp, 8 * sizeof(int));


	/* STEP 4 : K=H(delta || C1 || C2 )*/
	memcpy(KeyIn, delta, 8 * sizeof(int));
	memcpy(KeyIn + 8, pCipher, CLen * sizeof(int));

	SHA256_INT(KeyIn, KLen << 2, Key);
	STOP_WATCH;
	time_enc += sec;

	free(r);
	free(KeyIn);

	return ret;
}

/* CCA KEM decapsulation scheme */
int CRYPTO_KEM_Decap(unsigned int *Key, int *pCipher, CRYPTO_public_t pPubKey, int *pPriKey)
{
	unsigned int delta[8], tmp[8];
	unsigned int seed_in;
	unsigned int *KeyIn;
	int *r, *C_1;
	int i, KLen, CLen;
	int ret = CRYPTO_OK;

	/* Input length to generate key = delta+C1 len <<2, C_2*/
	KLen = 16 + ((CRYPTO_v*(CRYPTO_n + CRYPTO_k)));
	CLen = CRYPTO_v*(CRYPTO_n + CRYPTO_k) + 8;

	r = (int*)calloc(CRYPTO_m*CRYPTO_v, sizeof(int*));
	C_1 = (int*)calloc(CRYPTO_v*(CRYPTO_n + CRYPTO_k), sizeof(int*));
	KeyIn = (unsigned int*)calloc(KLen, sizeof(unsigned int*));
	START_WATCH;
	/* STEP 1 : Compute delta */
	_KEM_Dec(delta, pPriKey, pCipher);

	/* STEP 2 : Compute r=G(delta) */
	seed_in = _KEM_GenTrinary(r, delta, CRYPTO_m*CRYPTO_v);

	_KEM_Enc(C_1, pPubKey, r, delta, CRYPTO_delta << 3, seed_in);

	/* STEP 3 : C2=H(delta||02)*/
	delta[8]=0x02000000;
	SHA256_INT(delta, 33, tmp);



	if (memcmp(C_1, pCipher, CRYPTO_v*(CRYPTO_n + CRYPTO_k) * sizeof(int)))
	{
		ret = CRYPTO_ERROR;
		goto err;
	}

	if (memcmp(tmp, pCipher + CRYPTO_v*(CRYPTO_n + CRYPTO_k), 8 * sizeof(int)))
	{
		ret = CRYPTO_ERROR;
		goto err;
	}

	/* STEP 4 : K=H(delta || C1 || C2 )*/
	memcpy(KeyIn, delta, 8 * sizeof(int));
	memcpy(KeyIn + 8, pCipher, CLen * sizeof(int));

	SHA256_INT(KeyIn, KLen << 2, Key);
	STOP_WATCH;
	time_dec += sec;
err:
	memset(delta, 0, CRYPTO_delta);

	free(r);
	free(C_1);
	free(KeyIn);

	return ret;
}


/* Test function for CPA */
void CRYPTO_TEST_CPA(int iter)
{
	unsigned int Msg[8] = { 0x19edd4d6,0x3174b71a,0xe409640f,0x7e95fe4,0x6f004c67,0x6264bc6e,0x4c234775,0xb33edb88 };
	unsigned int MsgPrime[8];
	int *pCipher;
	int *pPriKey;
	int cnt_s = 0, cnt_f = 0;
	int i;
	CRYPTO_public_t pPubKey;

	CRYPTO_public_init(pPubKey, CRYPTO_m*CRYPTO_n, CRYPTO_m*CRYPTO_k);

	pPriKey = (int*)calloc(CRYPTO_n*CRYPTO_k, sizeof(int));
	pCipher = (int*)calloc(CRYPTO_v*(CRYPTO_n + CRYPTO_k), sizeof(int));


	for (i = 0; i < iter; i++)
	{
		CRYPTO_KeyGen(pPubKey, pPriKey);
		CRYPTO_Enc(pCipher, pPubKey, Msg, 256);
		CRYPTO_Dec(MsgPrime, pPriKey, pCipher);
		if (memcmp(MsgPrime, Msg, 8 * sizeof(int)) != 0)
		{
			cnt_f++;
			printf("FAILED \n");
		}

		memset(pPubKey->A, 0, CRYPTO_m*CRYPTO_n * sizeof(int));
		memset(pPubKey->B, 0, CRYPTO_m*CRYPTO_k * sizeof(int));
		memset(pCipher, 0, CRYPTO_v*(CRYPTO_n + CRYPTO_k) * sizeof(int));
		memset(MsgPrime, 0, 8 * sizeof(int));
		printf("Round : %d \n", i);
	}

	printf(" Keygen Time  : %.5f ms \n", ((time_keygen / iter) * 1000));
	printf(" Enc Time  : %.5f ms \n", ((time_enc / iter) * 1000));
	printf(" Dec Time  : %.5f ms \n", ((time_dec / iter) * 1000));

	free(pCipher);
	free(pPriKey);


}

/* Test function for CCA */
void CRYPTO_TEST_CCA(int iter)
{
	unsigned int Key[8];
	unsigned int KeyPrime[8];
	int i;
	int *pCipher;
	int *pPriKey;
	CRYPTO_public_t pPubKey;

	CRYPTO_public_init(pPubKey, CRYPTO_m*CRYPTO_n, CRYPTO_m*CRYPTO_k);

	pPriKey = (int*)calloc(CRYPTO_n*CRYPTO_k, sizeof(int));
	pCipher = (int*)calloc(CRYPTO_v*(CRYPTO_n + CRYPTO_k) + 8, sizeof(int));

	for (i = 0; i < iter; i++)
	{
		CRYPTO_KeyGen(pPubKey, pPriKey);
		CRYPTO_KEM_Encap(Key, pCipher, pPubKey);
		CRYPTO_KEM_Decap(KeyPrime, pCipher, pPubKey, pPriKey);
		if (memcmp(Key, KeyPrime, 8 * sizeof(int)) != 0)
		{

			printf("FAILED \n");
		}

		memset(pPubKey->A, 0, CRYPTO_m*CRYPTO_n * sizeof(int));
		memset(pPubKey->B, 0, CRYPTO_m*CRYPTO_k * sizeof(int));
		memset(pCipher, 0, (CRYPTO_v*(CRYPTO_n + CRYPTO_k) + 8) * sizeof(int));
		memset(Key, 0, 8 * sizeof(int));
		memset(KeyPrime, 0, 8 * sizeof(int));
		printf("Round : %d \n", i);
	}
	printf(" Keygen Time  : %.5f ms \n", ((time_keygen / iter) * 1000));
	printf(" Enc Time  : %.5f ms \n", ((time_enc / iter) * 1000));
	printf(" Dec Time  : %.5f ms \n", ((time_dec / iter) * 1000));
	CRYPTO_public_clear(pPubKey);
	free(pPriKey);
	free(pCipher);

}



void main()
{
	//CRYPTO_TEST_CPA(1000);
	CRYPTO_TEST_CCA(300);
}
