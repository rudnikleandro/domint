#ifndef DOMINT_REPUTATION_H
#define DOMINT_REPUTATION_H

#include <stddef.h>

#include "core/model.h"

#define REPUTATION_COLLECTOR "reputation"

/* Asks threat-intelligence sources about `domain`: AlienVault OTX (pulses
 * that reference it; OTX_API_KEY raises the rate limit) and, when
 * ABUSECH_AUTH_KEY holds a key, abuse.ch URLhaus (malware URLs, Spamhaus DBL
 * and SURBL) and ThreatFox (IOCs). None of them contacts the target. */
void reputation_collect(const char *domain, observation_list *observations);

/* Builds `info` from the recorded answers. */
void reputation_interpret(const observation_list *observations, const char *domain, reputation_info *info);

/* Parsers for one answer each, network-free for tests. Return 0 on a
 * well-formed answer, -1 otherwise. */
int reputation_parse_otx(const char *text, size_t length, reputation_info *info);
int reputation_parse_urlhaus(const char *text, size_t length, reputation_info *info);
int reputation_parse_threatfox(const char *text, size_t length, reputation_info *info);

#endif
