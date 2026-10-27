# CVE

CVE is a Developer Dashboard skill that watches recent vulnerability reports
for issues mentioning C/C++, Java, Go, Perl, PHP or Python. It stores matching
records in `~/.cve/<language>/` for review. The collector reads the public CIRCL
vulnerability feed and keeps HIGH or CRITICAL reports (CVSS score of at least
7.0) that were updated or published within the last 24 hours. Language
detection uses OSV package ecosystems, package URLs, CVE affected-product data
and descriptions.
WordPress plugin advisories are classified as PHP. Numeric CVSS base scores
are used when present; CVSS 3.0 and 3.1 vectors are scored when the feed
supplies only a vector. Records without a supported score are skipped.

The collector requests recent updates in paginated batches and applies an exact
24-hour timestamp and CVSS threshold check before saving a report.

Current version: `1.0.7`.

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
directories in `~/.cve/`, including `cc`, `java`, `go`, `perl`, `php` and
`python`.

## Configuration

Collector schedules and commands are in `config/config.json`. The CVSS
severity threshold and 24-hour time window are set in `.env.pl`.

## Help and tests

The collector commands accept `--help`, `-h` and `/?`. Run the test suite
through the Developer Dashboard environment so it receives the configured
severity threshold and time window:

```sh
d2 env prove -Ilib t
```

## Licence

This project is licensed under the MIT License. See [LICENSE](LICENSE).
