#ifndef DOMINT_PROGRESS_H
#define DOMINT_PROGRESS_H

#include <stddef.h>

/* A status line on stderr while a domain is investigated: spinner, a bar
 * of the collection steps, the current step and the elapsed time. It is
 * redrawn from a background thread, so it keeps moving while a lookup
 * blocks. When stderr is not a terminal only the final line is written. */

/* Starts the line for domain `index` (1-based) of `total`. */
void progress_begin(size_t index, size_t total, const char *name);

/* Moves to the next of `PROGRESS_STEPS` steps, labelled `label`. */
void progress_step(const char *label);

/* Replaces the current step's label, e.g. with a counter. No-op when idle. */
void progress_detail(const char *format, ...) __attribute__((format(printf, 1, 2)));

/* Clears the line and writes "[i/n] name ... done (12.3s)". */
void progress_end(double seconds);

/* The steps collect_domain() announces, for the bar. */
#define PROGRESS_STEPS 10

#endif
