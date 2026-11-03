#include "progress.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "model.h"

#define BAR_WIDTH 20
#define REDRAW_NANOSECONDS 100000000L

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t ticker;
static int active;
static int stopping;
static size_t domain_index;
static size_t domain_total;
static char domain_name[DOMAIN_SIZE];
static size_t step;
static size_t steps_total;
static char label[FIELD_SIZE];
static struct timespec started;

static double elapsed(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    return (double)(now.tv_sec - started.tv_sec) + (double)(now.tv_nsec - started.tv_nsec) / 1e9;
}

static size_t terminal_width(void)
{
    struct winsize size;

    if (ioctl(STDERR_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_col > 0)
    {
        return size.ws_col;
    }

    return 80;
}

/* Called with `lock` held. The line is cut to the terminal width: a
 * wrapped line could no longer be overwritten with \r. */
static void draw(unsigned frame)
{
    static const char spinner[] = "|/-\\";
    char bar[BAR_WIDTH + 1];
    char line[512];
    size_t filled = steps_total > 0 ? step * BAR_WIDTH / steps_total : 0;

    for (size_t i = 0; i < BAR_WIDTH; i++)
    {
        bar[i] = i < filled ? '#' : '-';
    }

    bar[BAR_WIDTH] = '\0';

    int length = snprintf(line, sizeof(line), "%c [%zu/%zu] %s [%s] %s (%.0fs)", spinner[frame % 4], domain_index,
                          domain_total, domain_name, bar, label, elapsed());
    size_t width = terminal_width() - 1;

    if (length > 0 && (size_t)length > width)
    {
        line[width] = '\0';
    }

    fprintf(stderr, "\r\033[K%s", line);
    fflush(stderr);
}

static void *tick(void *unused)
{
    (void)unused;

    struct timespec pause = {0, REDRAW_NANOSECONDS};
    unsigned frame = 0;

    for (;;)
    {
        pthread_mutex_lock(&lock);

        if (stopping)
        {
            pthread_mutex_unlock(&lock);
            return NULL;
        }

        draw(frame++);
        pthread_mutex_unlock(&lock);
        nanosleep(&pause, NULL);
    }
}

void progress_begin(size_t index, size_t total, const char *name, size_t steps)
{
    steps_total = steps;
    clock_gettime(CLOCK_MONOTONIC, &started);
    domain_index = index;
    domain_total = total;
    snprintf(domain_name, sizeof(domain_name), "%s", name);
    step = 0;
    snprintf(label, sizeof(label), "starting");
    stopping = 0;

    active = isatty(STDERR_FILENO) && pthread_create(&ticker, NULL, tick, NULL) == 0;
}

void progress_step(const char *text)
{
    pthread_mutex_lock(&lock);

    if (step < steps_total)
    {
        step++;
    }

    snprintf(label, sizeof(label), "%s", text);
    pthread_mutex_unlock(&lock);
}

void progress_detail(const char *format, ...)
{
    va_list args;

    pthread_mutex_lock(&lock);
    va_start(args, format);
    vsnprintf(label, sizeof(label), format, args);
    va_end(args);
    pthread_mutex_unlock(&lock);
}

void progress_end(double seconds)
{
    if (active)
    {
        pthread_mutex_lock(&lock);
        stopping = 1;
        pthread_mutex_unlock(&lock);
        pthread_join(ticker, NULL);
        fprintf(stderr, "\r\033[K");
        active = 0;
    }

    fprintf(stderr, "[%zu/%zu] %s ... done (%.1fs)\n", domain_index, domain_total, domain_name, seconds);
}
