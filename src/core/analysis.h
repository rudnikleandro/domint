#ifndef DOMINT_ANALYSIS_H
#define DOMINT_ANALYSIS_H

#include "core/model.h"

/* Derives the summary (hosting, providers, services) and the risk signals
 * of a report whose lookups have already run. Only the modules in
 * `report->modules` are judged. */
void analyze_domain(domain_report *report);

#endif
