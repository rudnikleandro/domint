#ifndef EXPOSUREPROOF_REPORT_H
#define EXPOSUREPROOF_REPORT_H

#include <stddef.h>
#include <stdio.h>

#include "correlate.h"
#include "model.h"

typedef struct
{
    int passive;
    int raw;
} report_options;

/* Writes the plain-text report. `links` is only used when count > 1. */
void print_report(FILE *out, const domain_report *reports, size_t count, const correlation *links,
                  const report_options *options);

#endif
