#ifndef DOMINT_STATUS_H
#define DOMINT_STATUS_H

/* How collection reports what it is doing, without knowing who listens.
 * The front end installs the handlers (the terminal progress line); with
 * none installed, as in the tests, the calls do nothing. */

typedef void (*status_handler)(const char *text);

/* `step` is called when a new collection step starts, `detail` when the
 * current step's label changes (a counter, for instance). NULL clears one. */
void status_set_handlers(status_handler step, status_handler detail);

void status_step(const char *label);
void status_detail(const char *format, ...) __attribute__((format(printf, 1, 2)));

#endif
