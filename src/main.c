#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "correlate.h"
#include "domain.h"
#include "model.h"
#include "pipeline.h"
#include "report.h"
#include "util.h"

typedef struct
{
    int passive;
    int full;
    int raw;
    const char *resolver;
    const char *input_file;
    const char *output_file;
} options;

static void print_usage(FILE *out, const char *program)
{
    fprintf(out, "Usage: %s [options] <domain> [domain ...]\n", program);
    fprintf(out, "       %s [options] -f <file>\n", program);
    fprintf(out, "\n");
    fprintf(out, "Options:\n");
    fprintf(out, "  -f, --file <path>      Read domains from a file, one per line (# starts a comment)\n");
    fprintf(out, "  -o, --output <path>    Write the report to a file instead of the terminal\n");
    fprintf(out, "      --full             Include the collected data and every source queried\n");
    fprintf(out, "      --raw              Also append the raw WHOIS and HTTP responses\n");
    fprintf(out, "      --passive          Do not contact the targets (skips the HTTP request)\n");
    fprintf(out, "      --resolver <ipv4>  Send the DNS record queries to this resolver; it will\n");
    fprintf(out, "                         see which domains you investigate\n");
    fprintf(out, "  -h, --help             Show this help\n");
    fprintf(out, "\n");
    fprintf(out, "Domains can be given as URLs or defanged (hxxps://example[.]com/path).\n");
}

static void add_domain(string_list *domains, const char *input)
{
    char name[DOMAIN_SIZE];
    int result = normalize_domain(input, name, sizeof(name));

    if (result == 0)
    {
        string_list_add_unique(domains, name);
        return;
    }

    char shown[128];
    snprintf(shown, sizeof(shown), "%s", input);
    sanitize_text(shown, strlen(shown), 0);

    fprintf(stderr, "Skipping \"%s\": %s\n", shown,
            result == DOMAIN_IS_IP ? "IP addresses are not supported, only domain names" : "not a valid domain name");
}

static int read_domain_file(const char *path, string_list *domains)
{
    FILE *file = fopen(path, "r");

    if (file == NULL)
    {
        return -1;
    }

    char *line = NULL;
    size_t capacity = 0;

    while (getline(&line, &capacity, file) != -1)
    {
        line[strcspn(line, "#\r\n")] = '\0';

        char *start = line;

        while (*start == ' ' || *start == '\t')
        {
            start++;
        }

        if (*start != '\0')
        {
            add_domain(domains, start);
        }
    }

    free(line);
    fclose(file);
    return 0;
}

static double seconds_since(const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    return (double)(now.tv_sec - start->tv_sec) + (double)(now.tv_nsec - start->tv_nsec) / 1e9;
}

/* Returns 0 to go on, 1 to stop with an error. Sets *done after --help. */
static int parse_arguments(int argc, char *argv[], options *opts, string_list *domains, int *done)
{
    for (int i = 1; i < argc; i++)
    {
        const char *arg = argv[i];
        int has_value = i + 1 < argc;

        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0)
        {
            print_usage(stdout, argv[0]);
            *done = 1;
            return 0;
        }
        else if (strcmp(arg, "--passive") == 0)
        {
            opts->passive = 1;
        }
        else if (strcmp(arg, "--full") == 0)
        {
            opts->full = 1;
        }
        else if (strcmp(arg, "--raw") == 0)
        {
            opts->raw = 1;
        }
        else if (strcmp(arg, "--resolver") == 0 && has_value)
        {
            opts->resolver = argv[++i];
        }
        else if ((strcmp(arg, "-f") == 0 || strcmp(arg, "--file") == 0) && has_value)
        {
            opts->input_file = argv[++i];
        }
        else if ((strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0) && has_value)
        {
            opts->output_file = argv[++i];
        }
        else if (arg[0] == '-')
        {
            fprintf(stderr, "Unknown option or missing value: %s\n\n", arg);
            print_usage(stderr, argv[0]);
            return 1;
        }
        else
        {
            add_domain(domains, arg);
        }
    }

    if (opts->input_file != NULL && read_domain_file(opts->input_file, domains) != 0)
    {
        fprintf(stderr, "Cannot read %s: %s\n", opts->input_file, strerror(errno));
        return 1;
    }

    if (domains->count == 0)
    {
        if (argc == 1)
        {
            print_usage(stderr, argv[0]);
        }
        else
        {
            fprintf(stderr, "No valid domains to investigate.\n");
        }

        return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    options opts = {0};
    string_list domains = {0};
    int done = 0;

    if (parse_arguments(argc, argv, &opts, &domains, &done) != 0 || done)
    {
        string_list_free(&domains);
        return done ? 0 : 1;
    }

    struct in_addr resolver_addr;
    const struct in_addr *custom_resolver = NULL;

    if (opts.resolver != NULL)
    {
        if (inet_pton(AF_INET, opts.resolver, &resolver_addr) != 1)
        {
            fprintf(stderr, "Invalid resolver address (IPv4 expected): %s\n", opts.resolver);
            string_list_free(&domains);
            return 1;
        }

        custom_resolver = &resolver_addr;
    }

    /* Open the output before the lookups so a bad path fails immediately. */
    FILE *out = stdout;

    if (opts.output_file != NULL)
    {
        out = fopen(opts.output_file, "w");

        if (out == NULL)
        {
            fprintf(stderr, "Cannot write %s: %s\n", opts.output_file, strerror(errno));
            string_list_free(&domains);
            return 1;
        }
    }

    domain_report *reports = xcalloc(domains.count, sizeof(*reports));

    for (size_t i = 0; i < domains.count; i++)
    {
        domain_report *report = &reports[i];
        struct timespec start;

        snprintf(report->name, sizeof(report->name), "%s", domains.items[i]);
        fprintf(stderr, "[%zu/%zu] %s ... ", i + 1, domains.count, report->name);

        clock_gettime(CLOCK_MONOTONIC, &start);
        collect_domain(report, opts.passive, custom_resolver);
        interpret_domain(report);

        fprintf(stderr, "done (%.1fs)\n", seconds_since(&start));
    }

    correlation links = {0};

    if (domains.count > 1)
    {
        correlate(reports, domains.count, &links);
    }

    report_options report_opts = {opts.passive, opts.full || opts.raw, opts.raw};
    print_report(out, reports, domains.count, &links, &report_opts);

    int status = 0;

    if (out != stdout)
    {
        if (fclose(out) != 0)
        {
            fprintf(stderr, "Cannot write %s: %s\n", opts.output_file, strerror(errno));
            status = 1;
        }
        else
        {
            fprintf(stderr, "Report written to %s\n", opts.output_file);
        }
    }

    correlation_free(&links);

    for (size_t i = 0; i < domains.count; i++)
    {
        domain_report_free(&reports[i]);
    }

    free(reports);
    string_list_free(&domains);

    return status;
}
