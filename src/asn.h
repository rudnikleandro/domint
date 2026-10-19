#ifndef EXPOSUREPROOF_ASN_H
#define EXPOSUREPROOF_ASN_H

#include "model.h"

/* Asks Team Cymru which network announces `ip`, recording the answer. */
void asn_collect(const char *ip, observation_list *observations);

/* Fills in the network (ASN, BGP prefix, country) of `address` from the
 * recorded answer for its IP. */
void asn_interpret(const observation_list *observations, address_info *address);

/* Fills the network fields of `address` from a Team Cymru response. The
 * buffer is modified while parsing. Network-free, for testing. */
void asn_parse(char *response, address_info *address);

#endif
