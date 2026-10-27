# CVE

CVE is a Developer Dashboard skill that watches recent vulnerability reports
for critical issues mentioning C/C++, Java, Go, Perl, PHP or Python. It stores
matching records in `~/.cve/<language>/` for review. The collector reads the public CIRCL
vulnerability feed and, by default, keeps reports with a CVSS score of at least
5.0 that were published within the last 24 hours.

Current version: `1.0.2`.

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

It is configured to run hourly. To view the stored critical report count,
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

Collector schedules and commands are in `config/config.json`. The critical
CVSS threshold and 24-hour time window are set in `.env.pl`.

## Licence

This project is licensed under the MIT License. See [LICENSE](LICENSE).
