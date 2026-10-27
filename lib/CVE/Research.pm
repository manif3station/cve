package CVE::Research;

use strict;
use warnings;
use List::Util qw(max min);
use JSON qw(decode_json encode_json);
use HTTP::Tiny;
use Time::Piece;
use CVE::Folder;
use Env qw(CVSS_SEVERITY_THRESHOLD SECONDS_IN_24H);

my $API_URL = 'https://vulnerability.circl.lu/api/vulnerability/';
my $PAGE_SIZE = 100;

sub run {
    my ( $class, %options ) = @_;
    my $out = $options{out} // \*STDOUT;
    my $err = $options{err} // \*STDERR;
    my $current_time = defined $options{now} ? $options{now} : time;
    my $threshold = defined $options{threshold}
        ? $options{threshold}
        : defined $CVSS_SEVERITY_THRESHOLD ? $CVSS_SEVERITY_THRESHOLD : 7.0;
    my $window = defined $options{window}
        ? $options{window}
        : defined $SECONDS_IN_24H ? $SECONDS_IN_24H : 24 * 60 * 60;
    my $fetch = $options{fetch};
    if ( !defined $fetch ) {
        $fetch = sub { HTTP::Tiny->new->get(shift) };
    }
    my $max_pages = $options{max_pages} // 5;
    my $since = gmtime( $current_time - $window )->strftime('%Y-%m-%d');
    my %tech_filters = CVE::Folder->target_filters->%*;

    $| = 1;
    print {$out} "[*] ["
        . localtime($current_time)->strftime('%Y-%m-%d %H:%M:%S')
        . "] Initialization: Setting up environment...\n";

    my $base_cve_dir = CVE::Folder->base;
    print {$out} "[+] Target tracking base directory configured at: $base_cve_dir\n";
    print {$out} "[*] Querying global vulnerability stream: $API_URL\n";

    my @raw_cves;
    my $page = 1;
    my $last_page_size = 0;
    while ( $page <= $max_pages ) {
        my $url = $API_URL
            . "?since=$since&per_page=$PAGE_SIZE&date_sort=updated&sort_order=desc&page=$page";
        my $response = $fetch->($url);
        unless ( $response->{success} ) {
            die "[-] ERROR: Feed ingestion failed: $response->{status} $response->{reason}\n";
        }
        print {$out} "[+] API page $page retrieved ("
            . length( $response->{content} )
            . " bytes)\n";

        my $batch = eval { decode_json( $response->{content} ) };
        if ($@) {
            die "[-] FATAL ERROR: JSON payload evaluation failure: $@\n";
        }
        die "[-] FATAL ERROR: API payload must be a JSON array\n"
            unless ref $batch eq 'ARRAY';

        $last_page_size = scalar @$batch;
        push @raw_cves, @$batch;
        last if $last_page_size < $PAGE_SIZE;
        $page++;
    }
    if ( $page > $max_pages ) {
        print {$err} "[-] WARNING: Reached the CVE feed page limit ($max_pages).\n";
    }

    my $cves = _normalise_records(\@raw_cves);
    my $total_ingested = scalar @raw_cves;
    print {$out} "[+] Processing $total_ingested raw vulnerability entries from stream...\n";
    print {$out} "-" x 95 . "\n";

    my $severity_count = 0;
    my @processed_alerts;

    foreach my $item (@$cves) {
        my $cve_id = $item->{id}
                  // $item->{cveMetadata}{cveId}
                  // 'UNKNOWN-CVE';
        my $summary = $item->{summary} || $item->{details}
                   || (defined $item->{containers}{cna}{descriptions} ? $item->{containers}{cna}{descriptions}[0]{value} : undef)
                   || '';

        if ( $summary eq '' ) {
            print {$out} "    [-] [$cve_id] SKIPPED: Entry lacks an identifiable summary or description field.\n";
            next;
        }

        my $matched_lang = _identify_language( $item, $summary, \%tech_filters );
        next unless $matched_lang;

        print {$out} "[?] Match Triggered: $cve_id aligns with tracked language stack -> [" . uc($matched_lang) . "]\n";
        my $cvss = _score($item);
        unless ( defined $cvss ) {
            print {$out} "    [-] [$cve_id] SKIPPED: No supported numeric CVSS base score is available.\n";
            next;
        }
        my $severity = _severity_level($cvss);

        if ( $cvss < $threshold ) {
            printf {$out} "    [-] [$cve_id] SKIPPED: %s severity (CVSS: %.1f) is below threshold (%.1f)\n",
                $severity, $cvss, $threshold;
            next;
        }

        my $raw_event_time = _raw_event_time($item);
        my $event_time = parse_publication_time($raw_event_time);
        unless ($event_time) {
            print {$out} "    [-] [$cve_id] SKIPPED: Invalid or missing update/publication timestamp: "
                . ( $raw_event_time // 'NULL' ) . "\n";
            next;
        }

        my $age_seconds = $current_time - $event_time;
        my $age_hours = $age_seconds / 3600;
        if ( $age_seconds < 0 ) {
            printf {$out} "    [-] [$cve_id] SKIPPED: Timestamp is %.1f hours in the future.\n",
                abs($age_hours);
            next;
        }
        if ( $age_seconds > $window ) {
            printf {$out} "    [-] [$cve_id] SKIPPED: Last updated %.1f hours ago (exceeds maximum 24-hour analysis window)\n",
                $age_hours;
            next;
        }

        $severity_count++;
        printf {$out} "    [+] [$cve_id] PASSED: %s severity. CVSS: %.1f | Age: %.1f hours\n",
            $severity, $cvss, $age_hours;

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
            severity => $severity,
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
        printf {$out} "[%s] [%-8s] [%-6s] %s (CVSS: %.1f | %-9s) - %s\n",
            $alert->{status}, $alert->{severity}, uc( $alert->{lang} ), $alert->{id},
            $alert->{cvss}, $alert->{age}, $alert->{desc};
    }
    print {$out} "=" x 95 . "\n";
    print {$out} "[!] Actionable threats identified. Exiting with alert status 1.\n";
    return 1;
}

sub _raw_event_time {
    my ($item) = @_;
    for my $candidate (
        $item->{modified},
        $item->{cveMetadata}{dateUpdated},
        $item->{Published},
        $item->{published},
        $item->{cveMetadata}{datePublished},
        $item->{document}{tracking}{current_release_date},
        $item->{document}{tracking}{initial_release_date},
    ) {
        return $candidate if defined $candidate;
    }
    return;
}

sub _normalise_records {
    my ($items) = @_;
    my @records;
    for my $item (@$items) {
        if ( ref $item->{vulnerabilities} eq 'ARRAY'
            && ref $item->{document} eq 'HASH' ) {
            my $tracking = $item->{document}{tracking} // {};
            my $index = 0;
            for my $vulnerability ( @{ $item->{vulnerabilities} } ) {
                $index++;
                next unless ref $vulnerability eq 'HASH';
                my $id = $vulnerability->{cve};
                if ( !$id && ref $vulnerability->{ids} eq 'ARRAY' ) {
                    ($id) = map { $_->{text} }
                        grep { ref $_ eq 'HASH' && ($_->{text} // '') =~ /^CVE-/ }
                        @{ $vulnerability->{ids} };
                }
                if (!defined $id) {
                    if ($tracking->{id}) {
                        $id = sprintf( '%s-%03d', $tracking->{id}, $index );
                    }
                    else {
                        $id = "UNKNOWN-CSAF-$index";
                    }
                }

                my $summary = _csaf_summary( $vulnerability, $item->{document} );
                my $score = _csaf_score($vulnerability);
                my %record = ( %$item,
                    id => $id,
                    summary => $summary,
                    modified => $tracking->{current_release_date}
                        // $item->{modified},
                    published => $vulnerability->{release_date}
                        // $tracking->{initial_release_date}
                        // $item->{published},
                    vulnerabilities => [$vulnerability],
                );
                $record{cvss} = $score if defined $score;
                push @records, \%record;
            }
        }
        else {
            push @records, $item;
        }
    }
    return \@records;
}

sub _csaf_summary {
    my ( $vulnerability, $document ) = @_;
    my $notes = ref $vulnerability->{notes} eq 'ARRAY'
        ? $vulnerability->{notes} : [];
    for my $category (qw(description summary)) {
        for my $note (@$notes) {
            return $note->{text}
                if ref $note eq 'HASH'
                    && ($note->{category} // '') eq $category
                    && defined $note->{text} && $note->{text} ne '';
        }
    }
    return $vulnerability->{title}
        if defined $vulnerability->{title} && $vulnerability->{title} ne '';

    my $document_notes = ref $document->{notes} eq 'ARRAY' ? $document->{notes} : [];
    for my $category (qw(summary general)) {
        for my $note (@$document_notes) {
            return $note->{text}
                if ref $note eq 'HASH'
                    && ($note->{category} // '') eq $category
                    && defined $note->{text} && $note->{text} ne '';
        }
    }
    return '';
}

sub _csaf_score {
    my ($vulnerability) = @_;
    my @numeric_scores;
    my @vectors;
    my $scores = ref $vulnerability->{scores} eq 'ARRAY'
        ? $vulnerability->{scores} : [];
    for my $score_entry (@$scores) {
        next unless ref $score_entry eq 'HASH';
        for my $key (qw(cvss_v4 cvss_v3 cvss_v2)) {
            my $metric = $score_entry->{$key};
            next unless ref $metric eq 'HASH';
            push @numeric_scores, $metric->{baseScore}
                if defined $metric->{baseScore}
                    && $metric->{baseScore} =~ /^\d+(?:\.\d+)?$/;
            push @vectors, $metric->{vectorString}
                if defined $metric->{vectorString}
                    && $metric->{vectorString} ne '';
        }
    }
    return max(@numeric_scores) if @numeric_scores;
    return $vectors[0] if @vectors;
    return undef;
}

sub _score {
    my ($item) = @_;
    if ( defined $item->{cvss} ) {
        return $item->{cvss} if $item->{cvss} =~ /^\d+(?:\.\d+)?$/;
        my $score = _cvss31_score( $item->{cvss} );
        return $score if defined $score;
    }
    if ( ref $item->{containers}{cna}{metrics} eq 'ARRAY' ) {
        foreach my $metric ( @{ $item->{containers}{cna}{metrics} } ) {
            foreach my $version (qw(cvssV4_0 cvssV3_1 cvssV3_0 cvssV2_0)) {
                my $score = $metric->{$version}{baseScore};
                return $score if defined $score && $score =~ /^\d+(?:\.\d+)?$/;
            }
        }
    }
    if ( ref $item->{severity} eq 'ARRAY' ) {
        foreach my $severity ( @{ $item->{severity} } ) {
            my $score = $severity->{score} // '';
            return 0 + $score if $score =~ /^\d+(?:\.\d+)?$/;
            my $vector_score = _cvss31_score($score);
            return $vector_score if defined $vector_score;
        }
    }
    return undef;
}

sub _identify_language {
    my ( $item, $summary, $filters ) = @_;
    my @affected;
    push @affected, @{ $item->{affected} }
        if ref $item->{affected} eq 'ARRAY';
    push @affected, @{ $item->{containers}{cna}{affected} }
        if ref $item->{containers}{cna}{affected} eq 'ARRAY';

    for my $entry (@affected) {
        next unless ref $entry eq 'HASH';
        my $package = ref $entry->{package} eq 'HASH' ? $entry->{package} : {};
        my $ecosystem = lc( $package->{ecosystem} // $entry->{ecosystem} // '' );
        my $purl = lc( $package->{purl} // $entry->{purl}
            // $entry->{packageURL} // $entry->{packageUrl} // '' );
        my $structured_language = _ecosystem_language($ecosystem)
            // _purl_language($purl);
        return $structured_language if $structured_language;
    }

    my @text = ($summary);
    for my $entry (@affected) {
        next unless ref $entry eq 'HASH';
        my $package = ref $entry->{package} eq 'HASH' ? $entry->{package} : {};
        push @text, map { defined $_ && !ref $_ ? $_ : () }
            ( $package->{name}, $package->{ecosystem}, $package->{purl},
              $entry->{vendor}, $entry->{product}, $entry->{packageName},
              $entry->{purl}, $entry->{packageURL}, $entry->{packageUrl} );
    }
    my $match_text = join ' ', @text;
    for my $language ( sort keys %$filters ) {
        return $language if $match_text =~ $filters->{$language};
    }
    return '';
}

sub _ecosystem_language {
    my ($ecosystem) = @_;
    return 'python' if $ecosystem =~ /^(?:pypi|python)$/;
    return 'perl'   if $ecosystem =~ /^(?:cpan|perl)$/;
    return 'java'   if $ecosystem =~ /^(?:maven|maven central|java)$/;
    return 'go'     if $ecosystem =~ /^(?:go|golang|go modules?)$/;
    return 'rust'   if $ecosystem =~ /^(?:crates\.io|cargo|rust)$/;
    return 'php'    if $ecosystem =~ /^(?:packagist|composer|php)$/;
    return undef;
}

sub _purl_language {
    my ($purl) = @_;
    return 'python' if $purl =~ m{^pkg:pypi/};
    return 'perl'   if $purl =~ m{^pkg:cpan/};
    return 'java'   if $purl =~ m{^pkg:maven/};
    return 'go'     if $purl =~ m{^pkg:golang/};
    return 'rust'   if $purl =~ m{^pkg:cargo/};
    return 'php'    if $purl =~ m{^pkg:composer/};
    return undef;
}

sub _cvss31_score {
    my ($vector) = @_;
    return undef unless defined $vector && $vector =~ /^CVSS:3\.[01]\/(.+)$/;
    my %metric = map { split /:/, $_, 2 } split m{/}, $1;
    return undef unless $metric{AV} && $metric{AC} && $metric{PR}
        && $metric{UI} && $metric{S} && exists $metric{C}
        && exists $metric{I} && exists $metric{A};

    my %av = ( N => 0.85, A => 0.62, L => 0.55, P => 0.20 );
    my %ac = ( L => 0.77, H => 0.44 );
    my %ui = ( N => 0.85, R => 0.62 );
    my %impact = ( N => 0, L => 0.22, H => 0.56 );
    return undef unless exists $av{$metric{AV}} && exists $ac{$metric{AC}}
        && exists $ui{$metric{UI}} && exists $impact{$metric{C}}
        && exists $impact{$metric{I}} && exists $impact{$metric{A}}
        && $metric{S} =~ /^(?:U|C)$/;

    my $scope_changed = $metric{S} eq 'C';
    my %pr = $scope_changed
        ? ( N => 0.85, L => 0.68, H => 0.50 )
        : ( N => 0.85, L => 0.62, H => 0.27 );
    return undef unless exists $pr{$metric{PR}};

    my $isc = 1 - (1 - $impact{$metric{C}})
        * (1 - $impact{$metric{I}})
        * (1 - $impact{$metric{A}});
    my $impact_score = $scope_changed
        ? 7.52 * ($isc - 0.029) - 3.25 * ($isc - 0.02) ** 15
        : 6.42 * $isc;
    return 0 if $impact_score <= 0;

    my $exploitability = 8.22 * $av{$metric{AV}} * $ac{$metric{AC}}
        * $pr{$metric{PR}} * $ui{$metric{UI}};
    my $base_score = $impact_score + $exploitability;
    $base_score *= 1.08 if $scope_changed;
    $base_score = min( $base_score, 10 );

    # FIRST defines Roundup as the smallest one-decimal score at or above input.
    my $scaled = int( $base_score * 100_000 + 0.0001 );
    my $tenths = int( $scaled / 10_000 );
    $tenths++ if $scaled % 10_000;
    return $tenths / 10;
}

sub _severity_level {
    my ($score) = @_;
    return 'CRITICAL' if $score >= 9.0;
    return 'HIGH'     if $score >= 7.0;
    return 'MEDIUM'   if $score >= 4.0;
    return 'LOW'      if $score > 0;
    return 'NONE';
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

Fetches recently updated vulnerability reports from the paginated CIRCL
vulnerability feed. Supported languages are C/C++, Java, Go, Perl, PHP, Python
and Rust. Detection uses OSV ecosystems, package URLs (including CPAN
C<pkg:cpan/> metadata), affected product metadata and descriptions. The
collector stores only HIGH or CRITICAL reports with a supported CVSS score of
at least 7.0 that fall within the 24-hour window. Numeric CVSS base scores are
used when present; CVSS 3.0 and 3.1 vectors are scored when a numeric base
score is absent. Unsupported vectors and missing scores are skipped. Reports
are stored in the corresponding C<~/.cve/> language directory. The collector
requests up to five pages of 100 records per run and warns when the page limit
is reached. If C<CVE_TARGET> is set, matching and storage are limited to its
comma-separated, case-insensitive language names; otherwise all supported
languages are enabled. The default threshold and window are set by
C<CVSS_SEVERITY_THRESHOLD> and C<SECONDS_IN_24H>. The C<run> method accepts
optional C<fetch>, C<now>, C<threshold>, C<window>, C<max_pages>, C<out> and
C<err> values to support deterministic testing.

=cut
