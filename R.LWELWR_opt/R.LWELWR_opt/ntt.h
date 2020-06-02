
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


void padd(int *a, int *b, int *c, int p, int N);
void pmul(int *a, int *b, int *c, int N);
void pmuladd(int *a, int *b, int *c, int *d, int N);

void NTT(int *a, const int *psi, int N);
void INTT(int *a, const int *psi_inv, int Ninv, int N);
void NTT_new(int *aout, int *a, const int *psi, int N);
