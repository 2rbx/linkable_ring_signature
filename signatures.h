#ifndef SIGNATURES_H
#define SIGNATURES_H

#include "common.h"

signature* signature_init(int n);
void print_signature(const signature* sign, int n);
void signature_generation(const char* message,const int pi,const key** key_array,int n,signature* sign,const group_parameters* gr);
int signature_verification(const signature* sign,const key** key_array ,int n,const char* message,const group_parameters* gr);
int link_verification(const signature* sign1,const signature* sign2);
void clear_signature(signature* sign,int n);

#endif
