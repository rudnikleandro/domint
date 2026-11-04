#ifndef DOMINT_ASN_H
#define DOMINT_ASN_H

#include "core/model.h"

#define ASN_COLLECTOR "asn"

/* Asks Team Cymru which network announces `ip`, recording the answer. */
void asn_collect(const char *ip, observation_list *observations);

/* Fills in the network (ASN, BGP prefix, country) of `address` from the
 * recorded answer for its IP. */
void asn_interpret(const observation_list *observations, address_info *address);

/* Asks for the network of each live subdomain's IP not already queried. */
void asn_collect_subdomains(const subdomain_list *subdomains, observation_list *observations);

/* Fills in the network of each live subdomain from the recorded answers. */
void asn_interpret_subdomains(const observation_list *observations, subdomain_list *subdomains);

/* Fills the network fields of `address` from a Team Cymru response. The
 * buffer is modified while parsing. Network-free, for testing. */
void asn_parse(char *response, address_info *address);

#endif
