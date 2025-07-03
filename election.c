#include<stdio.h> 
#include<gmp.h>
#include<stdlib.h>
#include<openssl/sha.h>
#include<openssl/evp.h>
#include<string.h>
#include<time.h>

#define GROUP_N 64
#define QSIZE 2048 // keep > 1024 to be safe from NSA


/* THINGS TO DO:
 * make a struct for signatures
 * possibly refactor for r != 2 
 */


// function that generates a QSIZE bit prime q, a prime p such that p = 2 * q + 1, and generator g 
void gen_g_p_q(mpz_t g,mpz_t q,mpz_t p){
	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state,time(NULL));
	while(1){
		mpz_urandomb(q,state,QSIZE);
		mpz_nextprime(q,q);
		mpz_mul_ui(p,q,2);
		mpz_add_ui(p,p,1);
		if(mpz_probab_prime_p(p,50) != 0) break;
	}
	mpz_t exp,ub;
	mpz_inits(exp,ub,NULL);
	mpz_set(ub,p);
	mpz_sub_ui(ub,ub,1);
	while(1){
		mpz_urandomm(g,state,p);
		if(mpz_cmp_ui(g,1) <= 0 || mpz_cmp(g,ub) >= 0) continue;
		mpz_powm(exp,g,q,p);
		if(mpz_cmp_ui(exp,1) != 0) continue;
		mpz_powm_ui(exp,g,2,p);
		if(mpz_cmp_ui(exp,1) == 0) continue;
	}
	mpz_clear(ub);
	mpz_clear(exp);
	gmp_randclear(state);
}

// function called "H2" in the paper, has to be refactored if we want to use r != 2
void H2(mpz_t result,const unsigned char* input,size_t input_size,const mpz_t p,const mpz_t q){ 
	// first we make function H that maps input to an integer in [2,q]
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256(input,input_size,digest);
	mpz_t H_out;
	mpz_init(H_out);
	mpz_import(H_out,SHA256_DIGEST_LENGTH,1,1,0,0,digest);
	mpz_t temp;
	mpz_init(temp);
	mpz_sub_ui(temp,q,1); // setting temp to be q - 1 
	mpz_mod(H_out,H_out,temp); // H_out is now in range [0,q-2]
	mpz_add_ui(H_out,H_out,2); // H_out is now in range [2,q]
	mpz_mul_ui(temp,q,2);
	mpz_add_ui(temp,temp,1); //temp is 2q + 1 
	mpz_powm_ui(result,H_out,2,temp); // H2 is H ^ 2 mod 2q + 1
	mpz_clear(H_out);
	mpz_clear(temp);
}

// function called "H1" in the paper
void H1(mpz_t result,const unsigned char* input,size_t input_size,const mpz_t q){
	size_t q_bits = mpz_sizeinbase(q,2);
	size_t k = q_bits + 128; // k >= log2(q) + 128
	k = (k + 7)/8; // rounding up to next byte
	
	unsigned char shake_output[k];
    	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    	EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL);
    	EVP_DigestUpdate(mdctx, input, input_size);
    	EVP_DigestFinalXOF(mdctx, shake_output, k);
    	EVP_MD_CTX_free(mdctx);

    	mpz_import(result, k, 1, 1, 0, 0, shake_output);
    	mpz_mod(result, result, q); 
}

void signature_generation(const char* message,const int pi,const mpz_t* x,const mpz_t* y,int n,const mpz_t p,const mpz_t q,mpz_t* c,mpz_t* s,const mpz_t g,mpz_t y0){
	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state,time(NULL));

	mpz_t h;
	mpz_init(h);
	size_t size_of_L = 0;
	for(int i = 0 ; i < n ; i++){
		size_of_L += mpz_sizeinbase(y[i],10) + 1;
	}
	char* buffer = (char*)malloc(size_of_L);
	if(!buffer){
		perror("malloc failed in signature generation");
		exit(1);
	}
	size_t offset = 0;
	for (int i = 0; i < n; i++) {
    		offset += gmp_snprintf(buffer + offset, size_of_L - offset, "%Zd", y[i]);
	}
	H2(h,(unsigned char*)buffer,offset,p,q); // calculating h <- H2(L) 
	free(buffer);
	mpz_powm(y0,h,x[pi],p);
	mpz_t z1[GROUP_N];
	mpz_t z2[GROUP_N];
	mpz_t tmp1,tmp2;
	mpz_inits(tmp1,tmp2,NULL);
	for(int i = 0 ; i < n ; i++){
		mpz_inits(z1[i],z2[i],s[i],c[i],NULL);
	}
	for(int i = 0 ; i < n ; i++){
		if(i == pi) continue;
		mpz_urandomm(s[i],state,q);
		mpz_urandomm(c[i],state,q);
		mpz_powm(tmp1,g,s[i],p);
		mpz_powm(tmp2,y[i],c[i],p);
		mpz_mul(z1[i],tmp1,tmp2);
		mpz_mod(z1[i],z1[i],p);
		mpz_powm(tmp1,h,s[i],p);
		mpz_powm(tmp2,y0,c[i],p);
		mpz_mul(z2[i],tmp1,tmp2);
		mpz_mod(z2[i],z2[i],p);
	}
	mpz_t r;
	mpz_init(r);
	mpz_urandomm(r,state,q);
	mpz_powm(z1[pi],g,r,p);
	mpz_powm(z2[pi],h,r,p);
	size_t h1_input_size = mpz_sizeinbase(y0, 10) + strlen(message) + 2;
	for (int i = 0; i < n; i++) {
        	h1_input_size += mpz_sizeinbase(z1[i], 10) + mpz_sizeinbase(z2[i], 10) + 2;
    	}
    	char* h1_input = malloc(h1_input_size);
    	offset = gmp_snprintf(h1_input, h1_input_size, "%Zd%s", y0, message);
    	for (int i = 0; i < n; i++) {
        	offset += gmp_snprintf(h1_input + offset, h1_input_size - offset, "%Zd%Zd", z1[i], z2[i]);
    	}
	mpz_t h1_output;
	mpz_init(h1_output);
	H1(h1_output,(unsigned char*)h1_input,strlen(h1_input),q); // calculating h1(L||y0||message||z1[i]||z2[i])
	free(h1_input);
	mpz_t cum;
	mpz_init(cum);
	for(int i = 0 ; i < n ; i++){
		if(i != pi) mpz_add(cum,cum,c[i]);
	}
	mpz_mod(cum,cum,q);
	mpz_sub(h1_output,h1_output,cum);
	mpz_set(c[pi],h1_output);
	mpz_mod(c[pi],c[pi],q); // calculating appropriate c[pi]
	mpz_mul(tmp1,c[pi],x[pi]);
	mpz_sub(tmp2,r,tmp1);
	mpz_mod(tmp2,tmp2,q);
	mpz_set(s[pi],tmp2); // calculating appropriate s[pi]
	mpz_clears(h,r,h1_output,tmp1,tmp2,NULL);
	for(int i = 0 ; i < n ; i++){
		mpz_clears(z1[i],z2[i],NULL);
	}
	gmp_randclear(state);
}

int sign_verification(const mpz_t y0,const mpz_t* s,const mpz_t* c,const mpz_t* y,const mpz_t g,const mpz_t p,const mpz_t q,const mpz_t* x,int pi,int n,const char* message){
	mpz_t h,z1,z2;
	mpz_inits(h,z1,z2,NULL);
	size_t size_of_L = 0;
	for(int i = 0 ; i < n ; i++){
		size_of_L += mpz_sizeinbase(y[i],10) + 1;
	}
	char* buffer = (char*)malloc(size_of_L);
	if(!buffer){
		perror("malloc failed in signature generation");
		exit(1);
	}
    	size_t h1_input_size = mpz_sizeinbase(y0, 10) + strlen(message) + 2;
    	for (int i = 0; i < n; i++) {
        	h1_input_size += mpz_sizeinbase(z1, 10) + mpz_sizeinbase(z2, 10) + 2;
	}
    	char* h1_input = malloc(h1_input_size);
    	if (!h1_input) {
        	perror("malloc failed in h1_input, in verification");
        	exit(1);
    	}
    	size_t offset = gmp_snprintf(h1_input, h1_input_size, "%Zd%s", y0, message);
	mpz_t tmp1,tmp2,cum_c;
	mpz_inits(tmp1,tmp2,cum_c,NULL);
    	for (int i = 0; i < n; i++) {
        	mpz_powm(tmp1, g, s[i], p);
        	mpz_powm(tmp2, y[i], c[i], p);
        	mpz_mul(z1, tmp1, tmp2); mpz_mod(z1, z1, p);

        	mpz_powm(tmp1, h, s[i], p);
        	mpz_powm(tmp2, y0, c[i], p);
        	mpz_mul(z2, tmp1, tmp2); mpz_mod(z2, z2, p);

        	offset += gmp_snprintf(h1_input + offset, h1_input_size - offset, "%Zd%Zd", z1, z2);
        	mpz_add(cum_c, cum_c, c[i]);
        	mpz_mod(cum_c, cum_c, q);
    	}
    	mpz_t h1_check;
    	mpz_init(h1_check);
    	H1(h1_check, (unsigned char*)h1_input, strlen(h1_input), q);
    	free(h1_input);
    	int valid = (mpz_cmp(h1_check, cum_c) == 0);
    	mpz_clears(h, z1, z2, tmp1, tmp2, cum_c, h1_check, NULL);
    	return valid;
}

int link_verification(const mpz_t y01,const mpz_t y02){
	return mpz_cmp(y01,y02) == 0 ? 1 : 0;
}






