# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-11-04

### Added

- Manual page (`man domint`), installed by `make install`.
- `make format` and `make format-check`, with a `.clang-format` describing the code style;
  CI checks the formatting.
- `SECURITY.md` and this changelog.

### Changed

- Sources are organized in layers: `src/collect`, `src/core`, `src/output` and
  `src/support`. The large analysis, report and subdomain modules are split by topic.
- The build states `-std=c11` and the POSIX feature macros.
- Tests are split by topic into separate suites.

### Fixed

- The RDAP bootstrap file and the WHOIS server cache are released at exit.
- DNS lookups no longer share static buffers, so they are reentrant.

## [1.0.0] - 2026-11-04

First stable release.

### Added

- Modules for registration (RDAP and WHOIS), addresses and networks, DNS and mail
  security, TLS, HTTP, subdomains with their CNAMEs, reputation (AlienVault OTX, abuse.ch
  URLhaus and ThreatFox) and lookalike domains.
- Signals ranked by severity, including subdomain takeover risk, lookalikes that can
  receive mail, threat-feed listings, young domains and mail spoofing exposure.
- Passive mode by default; `--active` to contact the target.
- Text, JSON and STIX 2.1 output.
- Unit tests and a fuzzer with AddressSanitizer and UndefinedBehaviorSanitizer; CI on Linux
  and macOS.

[1.0.1]: https://github.com/rudnikleandro/domint/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/rudnikleandro/domint/releases/tag/v1.0.0
