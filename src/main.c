#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "correlate.h"
#include "domain.h"
#include "https.h"
#include "model.h"
#include "pipeline.h"
#include "progress.h"
#include "report.h"
#include "util.h"

typedef struct
{
    int active;
    int passive;
    int full;
    int raw;
    int json;
    int no_subdomains;
    int no_probe;
    unsigned modules; /* MODULE_* picked with -a, -d, -w, -t, -H, -s; 0: all */
    const char *resolver;
    const char *input_file;
    const char *output_file;
} options;

static void print_usage(FILE *out, const char *program)
{
    fprintf(out, "Usage: %s [options] <domain> [domain ...]\n", program);
    fprintf(out, "       %s [options] -f <file>\n", program);
    fprintf(out, "\n");
    fprintf(out, "Modules (default: all of them; pick one or more, e.g. -wd):\n");
    fprintf(out, "  -a, --addresses        Addresses, reverse DNS and network (ASN)\n");
    fprintf(out, "  -d, --dns              DNS records: NS, MX, SPF, DMARC, CAA, DNSSEC, SOA, TXT\n");
    fprintf(out, "  -w, --whois            Registration data (RDAP, falling back to WHOIS)\n");
    fprintf(out, "  -t, --tls              TLS certificate on port 443 (contacts the target)\n");
    fprintf(out, "  -H, --http             HTTP response on port 80 (contacts the target)\n");
    fprintf(out, "  -s, --subdomains       Subdomains from passive sources, with their CNAMEs;\n");
    fprintf(out, "                         with --active, which of them answer over HTTP/HTTPS\n");
    fprintf(out, "  -r, --reputation       Threat intel: AlienVault OTX, plus abuse.ch URLhaus\n");
    fprintf(out, "                         and ThreatFox when ABUSECH_AUTH_KEY holds a key\n");
    fprintf(out, "Picked modules show their full sections.\n");
    fprintf(out, "\n");
    fprintf(out, "Options:\n");
    fprintf(out, "  -f, --file <path>      Read domains from a file, one per line (# comments)\n");
    fprintf(out, "  -o, --output <path>    Write the report to a file instead of the terminal\n");
    fprintf(out, "  -j, --json             Write the report as JSON (for MISP, OpenCTI, a SIEM...)\n");
    fprintf(out, "      --full             Show every section with the collected data\n");
    fprintf(out, "      --raw              Also list every query made (SOURCES) and append the raw\n");
    fprintf(out, "                         WHOIS and HTTP responses\n");
    fprintf(out, "      --active           Contact the targets from your IP: HTTP and TLS requests\n");
    fprintf(out, "                         and subdomain probes. The default is passive: only\n");
    fprintf(out, "                         third-party sources are asked (-t and -H still reach\n");
    fprintf(out, "                         the target)\n");
    fprintf(out, "      --passive          Never contact the targets, even with -t or -H\n");
    fprintf(out, "      --no-subdomains    Skip passive subdomain enumeration\n");
    fprintf(out, "      --no-probe         Skip HTTP/HTTPS liveness probing of subdomains\n");
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
static const struct
{
    char letter;
    const char *name;
    unsigned module;
} module_flags[] = {{'a', "--addresses", MODULE_ADDRESSES}, {'d', "--dns", MODULE_DNS},
                    {'w', "--whois", MODULE_WHOIS},         {'t', "--tls", MODULE_TLS},
                    {'H', "--http", MODULE_HTTP},           {'s', "--subdomains", MODULE_SUBDOMAINS},
                    {'r', "--reputation", MODULE_REPUTATION}};

static unsigned module_of_letter(char letter)
{
    for (size_t i = 0; i < sizeof(module_flags) / sizeof(module_flags[0]); i++)
    {
        if (module_flags[i].letter == letter)
        {
            return module_flags[i].module;
        }
    }

    return 0;
}

/* The modules in "--dns" or in "-w", "-wd", "-adw": short module flags can be
 * combined. Returns 0 when `arg` is not a module flag. */
static unsigned parse_module_flag(const char *arg)
{
    for (size_t i = 0; i < sizeof(module_flags) / sizeof(module_flags[0]); i++)
    {
        if (strcmp(arg, module_flags[i].name) == 0)
        {
            return module_flags[i].module;
        }
    }

    if (arg[0] != '-' || arg[1] == '-' || arg[1] == '\0')
    {
        return 0;
    }

    unsigned modules = 0;

    for (const char *letter = arg + 1; *letter != '\0'; letter++)
    {
        unsigned module = module_of_letter(*letter);

        if (module == 0)
        {
            return 0;
        }

        modules |= module;
    }

    return modules;
}

static int parse_arguments(int argc, char *argv[], options *opts, string_list *domains, int *done)
{
    for (int i = 1; i < argc; i++)
    {
        const char *arg = argv[i];
        int has_value = i + 1 < argc;

        unsigned modules = parse_module_flag(arg);

        if (modules != 0)
        {
            opts->modules |= modules;
        }
        else if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0)
        {
            print_usage(stdout, argv[0]);
            *done = 1;
            return 0;
        }
        else if (strcmp(arg, "--passive") == 0)
        {
            opts->passive = 1;
        }
        else if (strcmp(arg, "--active") == 0)
        {
            opts->active = 1;
        }
        else if (strcmp(arg, "--no-subdomains") == 0)
        {
            opts->no_subdomains = 1;
        }
        else if (strcmp(arg, "--no-probe") == 0)
        {
            opts->no_probe = 1;
        }
        else if (strcmp(arg, "--full") == 0)
        {
            opts->full = 1;
        }
        else if (strcmp(arg, "--raw") == 0)
        {
            opts->raw = 1;
        }
        else if (strcmp(arg, "-j") == 0 || strcmp(arg, "--json") == 0)
        {
            opts->json = 1;
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

    if (opts->active && opts->passive)
    {
        fprintf(stderr, "--active and --passive cannot be used together.\n");
        return 1;
    }

    if (opts->modules == MODULE_SUBDOMAINS && opts->no_subdomains)
    {
        fprintf(stderr, "--no-subdomains leaves no module to run with -s.\n");
        return 1;
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

    if (https_init() != 0)
    {
        fprintf(stderr, "Cannot initialize libcurl.\n");
        string_list_free(&domains);
        return 1;
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

    unsigned modules = opts.modules != 0 ? opts.modules : MODULE_ALL;

    if (opts.no_subdomains)
    {
        modules &= ~MODULE_SUBDOMAINS;
    }

    /* Asking for -t or -H is asking for the request they make. */
    collect_options collect = {0};
    collect.contact_target = !opts.passive && (opts.active || (opts.modules & (MODULE_TLS | MODULE_HTTP)) != 0);
    collect.probe_subdomains = !opts.passive && opts.active && !opts.no_probe;
    collect.no_probe = opts.no_probe;
    collect.resolver = custom_resolver;

    int contacted = (collect.contact_target && (modules & (MODULE_TLS | MODULE_HTTP)) != 0) ||
                    (collect.probe_subdomains && (modules & MODULE_SUBDOMAINS) != 0);

    domain_report *reports = xcalloc(domains.count, sizeof(*reports));

    for (size_t i = 0; i < domains.count; i++)
    {
        domain_report *report = &reports[i];
        struct timespec start;

        snprintf(report->name, sizeof(report->name), "%s", domains.items[i]);
        report->modules = modules;
        progress_begin(i + 1, domains.count, report->name, collect_steps(report));

        clock_gettime(CLOCK_MONOTONIC, &start);
        collect_domain(report, &collect);
        interpret_domain(report);

        progress_end(seconds_since(&start));
    }

    correlation links = {0};

    if (domains.count > 1)
    {
        correlate(reports, domains.count, &links);
    }

    report_options report_opts = {!contacted, opts.full || opts.raw, opts.raw, modules, opts.modules != 0};
    if (opts.json)
    {
        print_report_json(out, reports, domains.count, &links, &report_opts);
    }
    else
    {
        print_report(out, reports, domains.count, &links, &report_opts);
    }

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
    https_cleanup();

    return status;
}
