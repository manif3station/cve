# CVE

CVE is a Developer Dashboard skill that watches recent vulnerability reports
for issues mentioning C/C++, Java, Go, Perl, PHP, Python or Rust. It stores
matching records in `~/.cve/<language>/` for review. The collector reads the public CIRCL
vulnerability feed and keeps HIGH or CRITICAL reports (CVSS score of at least
7.0) that were updated or published within the last 24 hours. Language
detection uses OSV package ecosystems, package URLs, CVE affected-product data
and descriptions. Rust advisories use the `crates.io` ecosystem. Perl CVEs from
[CPANSec](https://security.metacpan.org/docs/cna-disclosure-policy.html) are
recognised through `pkg:cpan/` package URLs in CVE affected-product data.
WordPress plugin advisories are classified as PHP. Numeric
CVSS base scores are used when present; CVSS 3.0 and 3.1 vectors are scored
when the feed supplies only a vector. Records without a supported score are
skipped.

The collector requests recent updates in pages of 100, up to five pages per
run, then applies the exact 24-hour timestamp and CVSS threshold checks before
saving a report. It logs a warning if it reaches the page limit. The threshold
defaults to 7.0 and the time window defaults to 24 hours; both values are
configured in `.env.pl`.

Current version: `1.1.0`.

## Requirements

- Developer Dashboard (`d2`), available from the [Developer Dashboard page](https://michael.vu/?tag=Developer%20Dashboard)

## Install

Install the skill from the Developer Dashboard project directory:

```sh
d2 skill install cve
```

## Run the collectors

Start the research collector:

```sh
d2 restart collector cve.research
d2 collector run cve.research
```

It is configured to run hourly. To view the stored report count,
start the count collector:

```sh
d2 restart collector cve.count
d2 collector run cve.count
```

The count collector is configured to run every 30 minutes. Its indicator is
shown in the Developer Dashboard. Reports are stored under language-specific
directories in `~/.cve/`, including `c/c++`, `java`, `go`, `perl`, `php`,
`python` and `rust`.

## Configuration

Collector schedules and commands are in `config/config.json`. The default
CVSS severity threshold (7.0) and 24-hour time window are set in `.env.pl`.
Optionally set `CVE_TARGET` to restrict both collectors to selected languages.
Use a comma-separated list; values are case-insensitive and surrounding spaces
are ignored. If it is unset or blank, all supported languages are used.

```sh
CVE_TARGET="php, Rust"
```

`cc`, `c`, `c++` and `c/c++` select C/C++; `cpan` selects Perl. `cargo` and
`rustlang` select Rust. The count collector reports only the selected language
directories when `CVE_TARGET` is set.

## Help and tests

The collector commands accept `--help`, `-h` and `/?`. Run the test suite
through the Developer Dashboard environment so it receives the configured
severity threshold and time window:

```sh
d2 env prove -Ilib t
```

## Licence

This project is licensed under the MIT License. See [LICENSE](LICENSE).
