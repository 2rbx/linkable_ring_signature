#include "hashes.h"

// function called "H2" in the paper, has to be refactored if we want to use r != 2
void H2(mpz_t result,const unsigned char* input,size_t input_size,const group_parameters* gr){ 
	// first we make function H that maps input to an integer in [2,q]
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256(input,input_size,digest);
	mpz_t H_out;
	mpz_init(H_out);
	mpz_import(H_out,SHA256_DIGEST_LENGTH,1,1,0,0,digest);
	mpz_t temp;
	mpz_init(temp);
	mpz_sub_ui(temp,gr->q,1); // setting temp to be q - 1 
	mpz_mod(H_out,H_out,temp); // H_out is now in range [0,q-2]
	mpz_add_ui(H_out,H_out,2); // H_out is now in range [2,q]
	mpz_mul_ui(temp,gr->q,2);
	mpz_add_ui(temp,temp,1); //temp is 2q + 1 
	mpz_powm_ui(result,H_out,2,temp); // H2 is H ^ 2 mod 2q + 1
	mpz_clear(H_out);
	mpz_clear(temp);
}

// function called "H1" in the paper
void H1(mpz_t result,const unsigned char* input,size_t input_size,const group_parameters* gr){
	size_t q_bits = mpz_sizeinbase(gr->q,2);
	size_t k = q_bits + 128; // k >= log2(q) + 128
	k = (k + 7)/8; // rounding up to next byte
	
	unsigned char shake_output[k];
    	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    	EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL);
    	EVP_DigestUpdate(mdctx, input, input_size);
    	EVP_DigestFinalXOF(mdctx, shake_output, k);
    	EVP_MD_CTX_free(mdctx);

    	mpz_import(result, k, 1, 1, 0, 0, shake_output);
    	mpz_mod(result, result, gr->q); 
}

char* build_H1_input(const key** key_array, int n, const mpz_t y0, const char* message, mpz_t* z1, mpz_t* z2) {
    // computing size of L
    size_t size_L = 0;
    for (int i = 0; i < n; i++) {
        size_L += mpz_sizeinbase(key_array[i]->pub, 10) + 1;
    }

    size_t size_y0 = mpz_sizeinbase(y0, 10) + 1;
    size_t size_msg = strlen(message) + 1;
    size_t size_z = 0;
    for (int i = 0; i < n; i++) {
        size_z += mpz_sizeinbase(z1[i], 10) + mpz_sizeinbase(z2[i], 10) + 2;
    }

    size_t total = size_L + size_y0 + size_msg + size_z;
    char* buffer = (char*)malloc(total);
    if (!buffer) {
        perror("malloc failed in build_H1_input");
        exit(1);
    }

    size_t offset = 0;
    for (int i = 0; i < n; i++) {
        offset += gmp_snprintf(buffer + offset, total - offset, "%Zd", key_array[i]->pub);
    }

    offset += gmp_snprintf(buffer + offset, total - offset, "%Zd", y0);
    offset += snprintf(buffer + offset, total - offset, "%s", message);

    for (int i = 0; i < n; i++) {
        offset += gmp_snprintf(buffer + offset, total - offset, "%Zd%Zd", z1[i], z2[i]);
    }
    return buffer;
}
