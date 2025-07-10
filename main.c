#include "common.h"
#include "keys.h"
#include "hashes.h"
#include "group.h"
#include "signatures.h"

int main(){ 
	int n = 5;
	group_parameters* gr = (group_parameters*)malloc(sizeof(group_parameters));
	generate_group_parameters(gr);
	key** k;
	k = (key**)malloc(n * sizeof(key*));
	for(int i = 0 ; i < n ; i++) k[i] = (key*)malloc(sizeof(key));
	key_gen(k,n,gr);
	int id = 2;
	signature* sign = signature_init(n);
	signature* sign2 = signature_init(n);
	signature* sign3 = signature_init(n);
	signature_generation("myvote",id,(const key**)k,n,sign,gr);
	signature_generation("myvote2",id,(const key**)k,n,sign2,gr);
	id = 3;
	signature_generation("myvote3",id,(const key**)k,n,sign3,gr);

	printf("testing link verification,should print 1 if the signatures were signed by the same person\n");
	printf("sign and sign2 : %d\n",link_verification(sign,sign2));
	printf("sign and sign3 : %d\n",link_verification(sign,sign3));

	printf("testing signature verification, prints 1 if the signature message matches the string passed\n");
	printf("myvote : %d\n", signature_verification(sign, (const key **)k,n,"myvote",gr));
	printf("notmyvote : %d\n", signature_verification(sign, (const key **)k,n,"notmyvote",gr));

	return 0;
}


