#ifndef COMMON_H
#define COMMON_H

#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define GROUP_N 64
#define QSIZE 128 

typedef struct {
    mpz_t pri;
    mpz_t pub;
} key;

typedef struct {
    mpz_t y0;
    mpz_t* s;
    mpz_t* c;
} signature;

typedef struct {
	mpz_t g;
	mpz_t p;
	mpz_t q;
} group_parameters;

#endif

