#ifndef DOMINT_REPORT_H
#define DOMINT_REPORT_H

#include <stddef.h>
#include <stdio.h>

#include "correlate.h"
#include "model.h"

typedef struct
{
    int passive;
    int full;
    int raw;
    /* MODULE_* bits that ran (0: all), and whether they were picked on the
     * command line, which shows their sections without --full. */
    unsigned modules;
    int selected;
} report_options;

/* Writes the plain-text report: summary and signals per domain, the
 * collected data and sources with `full`, raw answers with `raw`. `links`
 * is only used when count > 1, and may be NULL to leave correlation out. */
void print_report(FILE *out, const domain_report *reports, size_t count, const correlation *links,
                  const report_options *options);

/* The same report as one JSON document, for tools: every module that ran,
 * the signals, the gaps, the indicators (domains and IPs) and, for several
 * domains, the indicators they share. */
void print_report_json(FILE *out, const domain_report *reports, size_t count, const correlation *links,
                       const report_options *options);

#endif
