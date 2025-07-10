#include "keys.h"

// generated n set of private and public keys, make sure n <= GROUP_N
void key_gen(key** keys,int n,const group_parameters* gr){
	for(int i = 0 ; i < n ; i++){
		mpz_inits(keys[i]->pri,keys[i]->pub,NULL);
	}
	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state,time(NULL));
	for(int i = 0 ; i < n ; i++){
		mpz_urandomm(keys[i]->pri,state,gr->q);
		mpz_powm(keys[i]->pub,gr->g,keys[i]->pri,gr->p);
	}
	gmp_randclear(state);
}

// function to free the key array
void clear_key_array(key** k,int n){
	for(int i = 0 ; i < n ; i++){
		mpz_clears(k[i]->pri,k[i]->pub,NULL);
		free(k[i]);
	}
	free(k);
}
