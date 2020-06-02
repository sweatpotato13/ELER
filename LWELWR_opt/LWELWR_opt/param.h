#pragma once

#include <stdlib.h>
#include <stdio.h>

#define SEVEN

#define CRYPTO_OK 0
#define CRYPTO_ERROR 1


#ifdef ONE

#define CRYPTO_m 1003
#define CRYPTO_n 770
#define CRYPTO_k 1
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 32
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_RGen 3
#define CRYPTO_MASK 0x0ffffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif
#ifdef TWO

#define CRYPTO_m 1003
#define CRYPTO_n 770
#define CRYPTO_k 2
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 16
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_RGen 3
#define CRYPTO_MASK 0x0ffffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif

#ifdef THREE

#define CRYPTO_m 1003
#define CRYPTO_n 770
#define CRYPTO_k 4
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 8
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_RGen 3
#define CRYPTO_MASK 0x0ffffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif

#ifdef FOUR

#define CRYPTO_m 1003
#define CRYPTO_n 770
#define CRYPTO_k 8
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 4
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_RGen 3
#define CRYPTO_MASK 0x0ffffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif

#ifdef FIVE

#define CRYPTO_m 1003
#define CRYPTO_n 770
#define CRYPTO_k 16
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 2
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_RGen 3
#define CRYPTO_MASK 0x0ffffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif

#ifdef SIX

#define CRYPTO_m 1003
#define CRYPTO_n 770
#define CRYPTO_k 32
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 1
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_RGen 3
#define CRYPTO_MASK 0x0ffffff

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32


#endif

#ifdef SEVEN

#define CRYPTO_m 832
#define CRYPTO_n 611
#define CRYPTO_k 4
#define CRYPTO_SIGMA 25

#define CRYPTO_t 8
#define CRYPTO_v 8
#define CRYPTO_msg 32

#define CRYPTO_logq 24
#define CRYPTO_logp 22
#define CRYPTO_RGen 3			// RING
#define CRYPTO_MASK 0x0ffffff	// ???

#define RD_ADD 0x2
#define RD_AND 0xfffffc
#define _32_LOG_Q 8

#define CRYPTO_KeyLen 32
#define CRYPTO_delta 32			// RING


#endif

#define _Rounding(x,row_x, column_x)\
{\
int _i;\
for ( _i = 0; _i < row_x*column_x; _i++) \
{ x[_i] = ((x[_i] + RD_ADD) & RD_AND) >> (2); \
}\
}

#define _MatADD(r, x, y, row_x, column_x)\
{\
int _i;\
for(_i=0; _i<row_x*column_x;_i++)\
{\
r[_i]=(x[_i]+y[_i])&CRYPTO_MASK;\
}\
}

#define _MatSUB(r, x, y, row_x, column_x)\
{\
int _i;\
for(_i=0; _i<row_x*column_x;_i++)\
{\
r[_i]=(x[_i]-y[_i])&CRYPTO_MASK;\
}\
}

#define _dropBits(dx, x)\
{\
int _tmp=0;\
_tmp = x >> (CRYPTO_logq-CRYPTO_t);\
_tmp = _tmp & 0xff;\
dx = _tmp;\
}

#define __dropBits(dx, x)\
{\
int _tmp=0;\
_tmp = x >> (CRYPTO_logp - 8);\
_tmp = _tmp & 0xff;\
dx = _tmp;\
}

typedef struct
{
	int *A;
	int *B;

}_CRYPTO_public_struct;

typedef _CRYPTO_public_struct CRYPTO_public_t[1];

enum CRYPTO_ERR_KEYGEN {

	/* Error codes for block cipher en/decryption */
	CRYPTO_ERR_KEYGEN_ALLOCATION_FAILED = 1000,
	CRYPTO_ERR_KEYGEN_FAILED,
	CRYPTO_ERR_KEYGEN_OUTPUT_NOT_INITIALIZED,

};

enum CRYPTO_ERR_ENC {

	/* Error codes for block cipher en/decryption */
	CRYPTO_ERR_ENC_ALLOCATION_FAILED = 2000,
	CRYPTO_ERR_ENC_NOT_INITIALIZED,
	CRYPTO_ERR_ENC_MSGLEN_ERROR,
	CRYPTO_ERR_ENC_PARAMETER,
	CRYPTO_ERR_ENC_MISSING_MSG,


};