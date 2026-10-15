#ifndef EXPOSUREPROOF_ASN_H
#define EXPOSUREPROOF_ASN_H

#include "model.h"

/* Fills in the network (ASN, BGP prefix, country) that announces the address. */
void asn_lookup(address_info *address);

#endif
