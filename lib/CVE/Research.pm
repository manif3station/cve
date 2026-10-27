package CVE::Research;

use strict;
use warnings;
use JSON qw(decode_json encode_json);
use HTTP::Tiny;
use Time::Piece;
use CVE::Folder;
use Env qw(CVSS_SEVERITY_THRESHOLD SECONDS_IN_24H);

my $API_URL = 'https://vulnerability.circl.lu/api/last';

sub run {
    my ( $class, %options ) = @_;
    my $out = $options{out} // \*STDOUT;
    my $err = $options{err} // \*STDERR;
    my $current_time = defined $options{now} ? $options{now} : time;
    my $threshold = defined $options{threshold}
        ? $options{threshold}
        : defined $CVSS_SEVERITY_THRESHOLD ? $CVSS_SEVERITY_THRESHOLD : 5.0;
    my $window = defined $options{window}
        ? $options{window}
        : defined $SECONDS_IN_24H ? $SECONDS_IN_24H : 24 * 60 * 60;
    my $fetch = $options{fetch};
    if ( !defined $fetch ) {
        $fetch = sub { HTTP::Tiny->new->get($API_URL) };
    }
    my %tech_filters = CVE::Folder->filters->%*;

    $| = 1;
    print {$out} "[*] ["
        . localtime($current_time)->strftime('%Y-%m-%d %H:%M:%S')
        . "] Initialization: Setting up environment...\n";

    my $base_cve_dir = CVE::Folder->base;
    print {$out} "[+] Target tracking base directory configured at: $base_cve_dir\n";
    print {$out} "[*] Querying global vulnerability stream: $API_URL\n";

    my $response = $fetch->($API_URL);
    unless ( $response->{success} ) {
        die "[-] ERROR: Feed ingestion failed: $response->{status} $response->{reason}\n";
    }
    print {$out} "[+] API response successfully retrieved ("
        . length( $response->{content} )
        . " bytes)\n";

    my $cves = eval { decode_json( $response->{content} ) };
    if ($@) {
        die "[-] FATAL ERROR: JSON payload evaluation failure: $@\n";
    }

    my $total_ingested = scalar(@$cves);
    print {$out} "[+] Processing $total_ingested raw vulnerability entries from stream...\n";
    print {$out} "-" x 95 . "\n";

    my $severity_count = 0;
    my @processed_alerts;

    foreach my $item (@$cves) {
        my $cve_id = $item->{id}
                  // $item->{cveMetadata}{cveId}
                  // 'UNKNOWN-CVE';
        my $summary = $item->{summary}
                   // $item->{details}
                   // (defined $item->{containers}{cna}{descriptions} ? $item->{containers}{cna}{descriptions}[0]{value} : undef)
                   // '';

        if ( $summary eq '' ) {
            print {$out} "    [-] [$cve_id] SKIPPED: Entry lacks an identifiable summary or description field.\n";
            next;
        }

        my $matched_lang = '';
        foreach my $lang ( keys %tech_filters ) {
            if ( $summary =~ $tech_filters{$lang} ) {
                $matched_lang = $lang;
                last;
            }
        }
        next unless $matched_lang;

        print {$out} "[?] Match Triggered: $cve_id aligns with tracked language stack -> [" . uc($matched_lang) . "]\n";
        my $cvss = _score($item);

        if ( $cvss < $threshold ) {
            printf {$out} "    [-] [$cve_id] SKIPPED: Severity score (CVSS: %.1f) is below threshold (%.1f)\n",
                $cvss, $threshold;
            next;
        }

        my $raw_pub_time = $item->{Published}
                        // $item->{published}
                        // $item->{cveMetadata}{datePublished};
        my $pub_time = parse_publication_time($raw_pub_time);
        unless ($pub_time) {
            print {$out} "    [-] [$cve_id] SKIPPED: Invalid or missing publication timestamp format: "
                . ( $raw_pub_time // 'NULL' ) . "\n";
            next;
        }

        my $age_seconds = $current_time - $pub_time;
        my $age_hours = $age_seconds / 3600;
        if ( $age_seconds > $window ) {
            printf {$out} "    [-] [$cve_id] SKIPPED: Published %.1f hours ago (exceeds maximum 24-hour analysis window)\n",
                $age_hours;
            next;
        }

        $severity_count++;
        printf {$out} "    [+] [$cve_id] PASSED: Severity threshold met. CVSS: %.1f | Age: %.1f hours\n",
            $cvss, $age_hours;

        my $lang_dir = CVE::Folder->$matched_lang;
        my $file_path = "$lang_dir/$cve_id.json";
        my $status = 'NEW';

        if ( -e $file_path ) {
            $status = 'OLD';
            print {$out} "    [*] Record Check: $cve_id tracking file already exists. Classifying as OLD.\n";
        }
        else {
            print {$out} "    [!] Record Check: $cve_id is completely unseen! Classifying as NEW.\n";
            if ( open my $fh, '>', $file_path ) {
                print {$fh} encode_json($item);
                close $fh;
                print {$out} "    [+] State Synchronized: Persistent cache written to $file_path\n";
            }
            else {
                print {$err} "    [-] SYSTEM ERROR: Failed writing state mapping payload to $file_path: $!\n";
            }
        }

        push @processed_alerts, {
            id     => $cve_id,
            lang   => $matched_lang,
            cvss   => $cvss,
            status => $status,
            age    => sprintf('%.1f hrs', $age_hours),
            desc   => substr( $summary, 0, 75 ) . '...',
        };
    }

    print {$out} "-" x 95 . "\n";
    print {$out} "[*] Evaluation phase complete. Parsing results summary matrix...\n";
    if ( $severity_count == 0 ) {
        print {$out} "[+] Summary: 0 reports matching the severity threshold were published in the last 24h.\n";
        print {$out} "[+] Operational Sweep Complete. Exiting cleanly with status 0.\n";
        return 0;
    }

    print {$out} "\n" . '!' x 36 . " ACTIONABLE SEVERITY REPORT " . '!' x 32 . "\n";
    print {$out} "=" x 95 . "\n";
    foreach my $alert (@processed_alerts) {
        printf {$out} "[%s] [%-5s] %s (CVSS: %.1f | %-9s) - %s\n",
            $alert->{status}, uc( $alert->{lang} ), $alert->{id},
            $alert->{cvss}, $alert->{age}, $alert->{desc};
    }
    print {$out} "=" x 95 . "\n";
    print {$out} "[!] Actionable threats identified. Exiting with alert status 1.\n";
    return 1;
}

sub _score {
    my ($item) = @_;
    my $cvss = 0;
    if ( defined $item->{cvss} ) {
        $cvss = $item->{cvss};
    }
    elsif ( defined $item->{containers}{cna}{metrics} ) {
        foreach my $metric ( @{ $item->{containers}{cna}{metrics} } ) {
            $cvss = $metric->{cvssV4_0}{baseScore}
                 // $metric->{cvssV3_1}{baseScore}
                 // $metric->{cvssV3_0}{baseScore}
                 // 0;
            last if $cvss > 0;
        }
    }
    elsif ( defined $item->{severity} ) {
        foreach my $severity ( @{ $item->{severity} } ) {
            my $score = $severity->{score} // '';
            if ( $score =~ /^CVSS:[^:]+:([\d\.]+)/ || $score =~ /^([\d\.]+)$/ ) {
                $cvss = $1;
                last if $cvss > 0;
            }
        }
    }
    return $cvss;
}

sub parse_publication_time {
    my ($time_str) = @_;
    return undef unless $time_str;

    $time_str =~ s/\.\d+//;
    $time_str =~ s/Z$//;
    $time_str =~ s/([\+\-]\d{2}):(\d{2})$/$1$2/;

    my $time;
    if ( $time_str =~ /[\+\-]\d{4}$/ ) {
        $time = eval { Time::Piece->strptime( substr( $time_str, 0, 24 ), '%Y-%m-%dT%H:%M:%S%z' ) };
    }
    else {
        $time = eval { Time::Piece->strptime( substr( $time_str, 0, 19 ), '%Y-%m-%dT%H:%M:%S' ) };
    }
    return $time ? $time->epoch : undef;
}

1;

=head1 NAME

CVE::Research - collect and triage recent vulnerability reports

=head1 SYNOPSIS

  CVE::Research->run;

=head1 DESCRIPTION

Fetches the latest vulnerability reports, matches supported language
filters, checks CVSS severity and publication age, and stores qualifying
reports in the corresponding C<~/.cve/> language directory. The C<run>
method accepts optional C<fetch>, C<now>, C<threshold>, C<window>, C<out>
and C<err> values to support deterministic testing.

=cut
