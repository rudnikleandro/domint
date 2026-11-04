# domint

[![CI](https://github.com/rudnikleandro/domint/actions/workflows/ci.yml/badge.svg)](https://github.com/rudnikleandro/domint/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

domint is a command-line tool for domain intelligence, written for cyber threat
intelligence (CTI) analysts. For one or more domains it collects registration, hosting,
DNS, certificate, subdomain, reputation and lookalike data, correlates it, and produces a
report that ranks findings by severity. Every value in the report can be traced to the
query that produced it.

domint is passive by default. It queries third-party sources only (registries, DNS
resolvers, Certificate Transparency logs and threat-intelligence feeds), so the
investigated domain does not receive traffic from the analyst's address unless active
mode is requested explicitly. Passive or active, every investigation requires prior
authorization from the domain owner, formalized in a contract; see
[Authorized use](#authorized-use).

![domint demo](docs/demo.gif)

## Contents

- [Authorized use](#authorized-use)
- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
- [Output formats](#output-formats)
- [Signals](#signals)
- [Operational security](#operational-security)
- [Environment variables](#environment-variables)
- [Exit status](#exit-status)
- [Testing](#testing)
- [Limitations](#limitations)
- [License](#license)

## Authorized use

domint must only be used against domains that you own or that you are authorized to
assess. Before any investigation carried out for a client, prior authorization is
mandatory and must be formalized in a contract with the client (a statement of work or
rules of engagement) that defines at least:

- the domains and subdomains in scope;
- the techniques permitted: passive collection only, or active mode as well;
- the period during which the assessment may take place;
- how the collected data will be stored, shared and deleted.

This applies to passive mode too. Passive collection sends no traffic to the target, but
it still gathers and processes information about the client and about third parties,
such as registrant records, which may be subject to data protection law (for example
LGPD or GDPR).

Active mode (`--active`, `-t`, `-H`) sends requests to the client's systems and to its
subdomains. Without written authorization, this may constitute an offence under the
computer-crime laws of many jurisdictions.

The authors provide domint as is, without warranty, and accept no liability for its use;
the user is solely responsible for ensuring that each use is authorized and lawful.

## Features

| Module | Data collected |
|---|---|
| Registration | Registrar, creation, update and expiry dates, domain age, EPP status codes, registrant and privacy service. RDAP first, WHOIS as fallback. |
| Addresses | IPv4 and IPv6 addresses, reverse DNS, announcing network (ASN), BGP prefix, CDN or reverse proxy in front of the origin. |
| DNS | NS, MX, TXT, SPF, DMARC, CAA, DNSSEC (DS and DNSKEY) and SOA records; DNS and mail providers; SaaS verification tokens. |
| TLS | Certificate subject, issuer, validity period, trust status and subject alternative names. |
| HTTP | Status line, redirect target and server banner. |
| Subdomains | Names from Certificate Transparency (crt.sh) and passive DNS (AlienVault OTX, HackerTarget), their CNAME targets and, in active mode, which ones serve content over HTTP or HTTPS. |
| Reputation | AlienVault OTX pulses; abuse.ch URLhaus, ThreatFox, Spamhaus DBL and SURBL listings. |
| Lookalikes | Typosquatting variants of the domain (omission, transposition, keyboard neighbours, homoglyphs, bit flips, phishing keywords, alternative TLDs), checked for registration, addresses and mail servers. |

Results from several domains are correlated: shared addresses, BGP prefixes, networks,
nameservers, mail servers, SOA contacts, verification tokens, registrars and creation
dates are reported as indicators linking them, ranked by how specific they are.

Reports are available as plain text, JSON and STIX 2.1.

## Installation

domint requires a C99 compiler, make and the libcurl development headers. It builds on
Linux and macOS.

Debian and Ubuntu:

```sh
sudo apt-get install build-essential libcurl4-openssl-dev
```

macOS (libcurl is included with the Xcode command line tools):

```sh
xcode-select --install
```

Build and install:

```sh
git clone https://github.com/rudnikleandro/domint.git
cd domint
make
sudo make install    # installs /usr/local/bin/domint
```

`make uninstall` removes the installed binary. Set `PREFIX` to install elsewhere, for
example `make install PREFIX=$HOME/.local`.

## Quick start

```sh
# All modules except lookalikes, without contacting the target
domint example.com

# Registration and DNS only
domint -w -d example.com
domint -wd example.com           # the same, with combined flags

# Lookalike domains
domint -l example.com

# Every collected value, contacting the target (HTTP, TLS, subdomain probes)
domint --active --full example.com

# Several domains from a file, with correlation, written to a file
domint -f domains.txt -o report.txt

# STIX 2.1 bundle for a threat-intelligence platform
domint --stix -o example.stix.json example.com
```

Domains can be given as host names, URLs or defanged indicators; all of the following
investigate `example.com`:

```sh
domint example.com
domint https://www.example.com/login
domint hxxps://example[.]com
```

## Command reference

```text
domint [options] <domain> [domain ...]
domint [options] -f <file>
```

### Modules

Without module flags, every module runs except `-l`. With one or more module flags, only
those modules run, and their detailed sections are shown without `--full`. Short module
flags can be combined: `-wds` is the same as `-w -d -s`.

| Option | Description |
|---|---|
| `-a`, `--addresses` | Addresses, reverse DNS and announcing network (ASN). |
| `-d`, `--dns` | DNS records: NS, MX, SPF, DMARC, CAA, DNSSEC, SOA and TXT. |
| `-w`, `--whois` | Registration data (RDAP, falling back to WHOIS). |
| `-t`, `--tls` | TLS certificate on port 443. Contacts the target. |
| `-H`, `--http` | HTTP response on port 80. Contacts the target. |
| `-s`, `--subdomains` | Subdomains from passive sources and their CNAME targets; with `--active`, which of them answer over HTTP or HTTPS. |
| `-r`, `--reputation` | Threat-intelligence lookups: AlienVault OTX, and abuse.ch URLhaus and ThreatFox when `ABUSECH_AUTH_KEY` is set. |
| `-l`, `--lookalikes` | Typosquatting: which variants of the name are registered and which can receive mail. Sends about a thousand DNS queries per domain. |

### Input and output

| Option | Description |
|---|---|
| `-f`, `--file <path>` | Read domains from a file, one per line. Lines starting with `#` and blank lines are ignored. Can be combined with domains on the command line; duplicates are removed. |
| `-o`, `--output <path>` | Write the report to a file instead of standard output. |
| `-j`, `--json` | Write the report as JSON. |
| `--stix` | Write the report as a STIX 2.1 bundle. Cannot be combined with `--json`. |
| `--full` | Show every section with all collected data, not only the summary and signals. |
| `--raw` | In addition to `--full`, list every query made (the SOURCES section) and append the raw WHOIS, RDAP and HTTP responses. |

### Network behaviour

| Option | Description |
|---|---|
| `--active` | Contact the targets from the local address: HTTP and TLS requests to the domain and HTTP/HTTPS probes to its subdomains. Requires the client's prior written authorization for active testing (see [Authorized use](#authorized-use)). |
| `--passive` | Never contact the targets, even when `-t` or `-H` is given. Cannot be combined with `--active`. |
| `--no-subdomains` | Skip subdomain enumeration. |
| `--no-probe` | In active mode, skip the HTTP/HTTPS probes of subdomains. |
| `--resolver <ipv4>` | Send DNS queries to this resolver instead of the system ones. The resolver learns which domains are investigated. |

### General

| Option | Description |
|---|---|
| `-V`, `--version` | Print the version and exit. |
| `-h`, `--help` | Print the usage summary and exit. |

## Output formats

### Text

The default report contains, for each domain:

- **SUMMARY**: registration, hosting, DNS and mail providers, certificate, reputation,
  subdomain and lookalike counts, and a **Gaps** line listing any source that failed, so
  that a missing value is read as unknown rather than absent.
- **SIGNALS**: findings ranked HIGH, MEDIUM, LOW and INFO.
- **SUBDOMAINS**: online hosts with status, address and network; aliases to other
  domains; hosts that did not answer, grouped by reason.

`--full` adds the ADDRESSES, HTTP, TLS CERTIFICATE, DNS, REGISTRATION, REPUTATION and
LOOKALIKES sections. `--raw` adds SOURCES and the raw responses. With more than one
domain, the report opens with an OVERVIEW table and closes with a CORRELATION section.

Example (`domint example.com`, abridged):

```text
SUMMARY
  Signals       2 info
  Registered    1995-08-14 (31 years, 3 months ago), RESERVED-Internet Assigned
                Numbers Authority
  Hosting       AS13335 CLOUDFLARENET - Cloudflare, Inc., US
  DNS provider  Cloudflare
  Mail          accepts no mail (null MX)
  Reputation    no listings in OTX; OTX marks it known-good
  Subdomains    1 discovered (not probed; --active checks which answer)

SIGNALS
  [INFO]   Served through Cloudflare, which hides the origin server's real
           address.
  [INFO]   No CAA record: any certificate authority may issue certificates for
           this domain.
```

### JSON

`-j` writes one document with the tool metadata, the mode, the modules that ran and, for
each domain, the collected data, the signals, the gaps and an `indicators` object with the
domain, its online subdomains, their addresses and the registered lookalikes. Values that
could not be determined are `null`.

### STIX 2.1

`--stix` writes a bundle containing:

- `domain-name`, `ipv4-addr`, `ipv6-addr` and `autonomous-system` observables, linked by
  `resolves-to` and `belongs-to` relationships;
- an `indicator` for each registered lookalike (`anomalous-activity`) and for each
  threat-feed listing of the domain (`malicious-activity`);
- a `note` with the signals and a `report` that references every object of the domain.

Observable identifiers are derived from their values as the specification requires, so
importing the same domain more than once updates the existing objects instead of
duplicating them. Bundles are validated with the OASIS
[stix2-validator](https://github.com/oasis-open/cti-stix-validator).

## Signals

| Severity | Examples |
|---|---|
| HIGH | Subdomain takeover risk (CNAME to a deleted resource on a claimable service such as Azure App Service, GitHub Pages, Heroku or S3); domain listed on ThreatFox, URLhaus or the Spamhaus DBL; domain registered in the last 30 days; open directory listing; SPF `+all`. |
| MEDIUM | Lookalike domains that can receive mail; dangling CNAME; first certificate issued in the last 30 days; missing SPF or DMARC on a mail domain; expired or untrusted certificate; private or unannounced address; broken DNSSEC; exposed non-production environments. |
| LOW | Lookalike domains pointing to a server; DMARC in monitoring mode; SPF softfail; server version disclosure; stale DNS records served by a CDN; OTX pulses. |
| INFO | Parked or for-sale lookalikes; lookalikes registered by the domain owner; CDN in front of the origin; missing CAA; unsigned zone; other domains on the same certificate. |

## Operational security

Passive mode limits what the target can observe; it does not replace the authorization
described in [Authorized use](#authorized-use), which is required in both modes.

- In passive mode, the sources contacted are RDAP and WHOIS registries, the configured DNS
  resolver, crt.sh, AlienVault OTX, HackerTarget, Team Cymru and, with a key, abuse.ch.
  None of them is the investigated domain.
- DNS queries go through the configured resolver, which learns the names investigated.
  The domain's authoritative nameservers receive queries from the resolver, not from the
  analyst. Use `--resolver` to choose the resolver.
- `--active`, `-t` and `-H` connect to the domain, and `--active` also to its subdomains,
  from the local address. The report header states which mode was used.
- All text received from the network is sanitized before it is printed, so a crafted
  WHOIS record, HTTP header or threat-feed entry cannot inject terminal escape sequences.

## Environment variables

| Variable | Description |
|---|---|
| `ABUSECH_AUTH_KEY` | Key for the abuse.ch APIs. Enables URLhaus and ThreatFox lookups. A free key is available at <https://auth.abuse.ch>. |
| `OTX_API_KEY` | Key for AlienVault OTX. Optional; raises the rate limit of anonymous requests. |

Keys are sent only to their own service and are never written to reports.

## Exit status

| Status | Meaning |
|---|---|
| 0 | The report was written. Individual source failures are reported in the Gaps line and do not change the status. |
| 1 | Invalid arguments, no valid domain, an unreadable input file or an unwritable output file. |

## Testing

```sh
make test                    # unit tests; no network access required
make fuzz                    # mutation fuzzing with AddressSanitizer and UndefinedBehaviorSanitizer
make fuzz FUZZ_RUNS=300000   # a longer fuzzing run
```

The fuzzer covers every parser of network data (JSON, WHOIS, RDAP, DNS, HTTP, TLS,
Certificate Transparency, reputation feeds), the interpretation pipeline and the text,
JSON and STIX writers. Continuous integration builds the project and runs both suites on
Linux (gcc) and macOS (clang) for every push.

## Limitations

- Subdomain discovery depends on public sources that are sometimes unavailable or rate
  limited; the Gaps line reports when the list may be incomplete.
- Lookalike checks rely on DNS only: a registered variant is one that is delegated, and
  its owner is not identified.
- Internationalized domain names (IDN) are not accepted as input.
- Active probes use a short timeout and check at most 100 subdomains per domain, chosen
  by relevance.

## License

domint is released under the [MIT License](LICENSE).
