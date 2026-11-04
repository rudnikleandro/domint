#include "support/status.h"

#include <stdarg.h>
#include <stdio.h>

static status_handler step_handler;
static status_handler detail_handler;

void status_set_handlers(status_handler step, status_handler detail)
{
    step_handler = step;
    detail_handler = detail;
}

void status_step(const char *label)
{
    if (step_handler != NULL)
    {
        step_handler(label);
    }
}

void status_detail(const char *format, ...)
{
    char text[256];
    va_list args;

    if (detail_handler == NULL)
    {
        return;
    }

    va_start(args, format);
    vsnprintf(text, sizeof(text), format, args);
    va_end(args);
    detail_handler(text);
}
