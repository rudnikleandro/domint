# Security policy

## Supported versions

Security fixes are made for the latest release.

| Version | Supported |
|---|---|
| 1.0.x | Yes |

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately through
[GitHub's vulnerability reporting](https://github.com/rudnikleandro/domint/security/advisories/new),
with the steps to reproduce it, the version (`domint --version`) and the platform.

You can expect an acknowledgement within seven days and a fix or an assessment within
thirty. Once a fix is released, the advisory is published with credit to the reporter,
unless they prefer otherwise.

## Scope

domint processes data from third parties and, in active mode, from the investigated
systems, which an adversary may control. Reports in scope include:

- memory-safety errors or undefined behaviour triggered by a crafted response (DNS, WHOIS,
  RDAP, HTTP, TLS, Certificate Transparency or threat-feed data);
- terminal escape sequences or other control characters reaching the output;
- injection into the requests domint sends (queries, headers, URLs);
- traffic sent to an investigated domain in passive mode.

Results that are wrong because a third-party source returned wrong data are not security
issues; please report them as ordinary issues.
