#include "group.h"

// function that generates a QSIZE bit prime q, a prime p such that p = 2 * q + 1, and generator g 
void generate_group_parameters(group_parameters* gr){
	mpz_inits(gr->g,gr->p,gr->q,NULL);
	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state,time(NULL));
	while(1){
		mpz_urandomb(gr->q,state,QSIZE);
		mpz_nextprime(gr->q,gr->q);
		mpz_mul_ui(gr->p,gr->q,2);
		mpz_add_ui(gr->p,gr->p,1);
		if(mpz_probab_prime_p(gr->p,50) != 0) break;
	}
	mpz_t exp,ub;
	mpz_inits(exp,ub,NULL);
	mpz_set(ub,gr->p);
	mpz_sub_ui(ub,ub,1);
	while(1){
		mpz_urandomm(gr->g,state,gr->p);
		if(mpz_cmp_ui(gr->g,1) <= 0 || mpz_cmp(gr->g,ub) >= 0) continue;
		mpz_powm(exp,gr->g,gr->q,gr->p);
		if(mpz_cmp_ui(exp,1) != 0) continue;
		mpz_powm_ui(exp,gr->g,2,gr->p);
		if(mpz_cmp_ui(exp,1) == 0) continue;
		break;
	}
	mpz_clear(ub);
	mpz_clear(exp);
	gmp_randclear(state);
}

void clear_group_parameters(group_parameters* gr){
	mpz_clears(gr->g,gr->p,gr->q);
	free(gr);
}
