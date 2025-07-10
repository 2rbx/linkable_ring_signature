#ifndef HASHES_H
#define HASHES_H

#include "common.h"

void H2(mpz_t result,const unsigned char* input,size_t input_size,const group_parameters* gr);
void H1(mpz_t result,const unsigned char* input,size_t input_size,const group_parameters* gr);
char* build_H1_input(const key** key_array, int n, const mpz_t y0, const char* message, mpz_t* z1, mpz_t* z2);

#endif
