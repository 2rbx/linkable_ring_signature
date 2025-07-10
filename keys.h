#ifndef KEYS_H
#define KEYS_H

#include "common.h"

void key_gen(key** keys,int n,const group_parameters* gr);
void clear_key_array(key** k,int n);

#endif
