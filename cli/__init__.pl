#!/usr/bin/env perl
use strict;
use warnings;
use utf8;
use CVE::Folder;
use HTTP::Tiny;
use JSON;
use File::Path qw(make_path);
use Time::Piece;
use Folder;
use Env qw(
    CVSS_CRITICAL_THRESHOLD
    SECONDS_IN_24H
);

# Force immediate flush of stdout to ensure real-time log tracking
$| = 1;

# Configurable Targets & Rules
my $CURRENT_TIME = time;

my %TECH_FILTERS = CVE::Folder->filters->%*;

print "[*] ["
    . localtime->strftime('%Y-%m-%d %H:%M:%S')
    . "] Initialization: Setting up environment...\n";

# Base storage directory
my $base_cve_dir = CVE::Folder->base;
print "[+] Target tracking base directory configured at: $base_cve_dir\n";

# Query the live public cve-search API database feed
my $api_url = 'https://vulnerability.circl.lu/api/last';
print "[*] Querying global vulnerability stream: $api_url\n";

my $response = HTTP::Tiny->new->get($api_url);
unless ( $response->{success} ) {
    die "[-] CRITICAL ERROR: Feed ingestion failed: $response->{status} $response->{reason}\n";
}
print "[+] API response successfully retrieved ("
    . length( $response->{content} )
    . " bytes)\n";

my $cves = eval { decode_json( $response->{content} ) };
if ($@) {
    die "[-] FATAL ERROR: JSON payload evaluation failure: $@\n";
}

my $total_ingested = scalar(@$cves);
print "[+] Processing $total_ingested raw vulnerability entries from stream...\n";
print "-" x 95 . "\n";

my $critical_count = 0;
my @processed_alerts;

foreach my $item (@$cves) {
    # 1. Normalize the CVE / Advisory ID across multiple payload variations
    my $cve_id = $item->{id}
              // $item->{cveMetadata}{cveId}
              // 'UNKNOWN-CVE';

    # 2. Normalize the text summary / description field (handles OSV and CVE v5 formats)
    my $summary = $item->{summary}
               // $item->{details}
               // (defined $item->{containers}{cna}{descriptions} ? $item->{containers}{cna}{descriptions}[0]{value} : undef)
               // '';

    if ( $summary eq '' ) {
        print "    [-] [$cve_id] SKIPPED: Entry lacks an identifiable summary or description field.\n";
        next;
    }

    # 3. Identify technology alignment
    my $matched_lang = "";
    foreach my $lang ( keys %TECH_FILTERS ) {
        if ( $summary =~ $TECH_FILTERS{$lang} ) {
            $matched_lang = $lang;
            last;
        }
    }
    if (!$matched_lang) {
        next;
    }

    print "[?] Match Triggered: $cve_id aligns with tracked language stack -> [" . uc($matched_lang) . "]\n";

    # 4. Normalize and calculate CVSS scores from multiple possible sources
    my $cvss = 0;
    if ( defined $item->{cvss} ) {
        $cvss = $item->{cvss};
    }
    elsif ( defined $item->{containers}{cna}{metrics} ) {
        foreach my $m ( @{ $item->{containers}{cna}{metrics} } ) {
            $cvss = $m->{cvssV4_0}{baseScore}
                 // $m->{cvssV3_1}{baseScore}
                 // $m->{cvssV3_0}{baseScore}
                 // 0;
            last if $cvss > 0;
        }
    }
    elsif ( defined $item->{severity} ) {
        foreach my $s ( @{ $item->{severity} } ) {
            if ( $s->{score} =~ /^CVSS:[^:]+:([\d\.]+)/ || $s->{score} =~ /^([\d\.]+)$/ ) {
                $cvss = $1;
                last if $cvss > 0;
            }
        }
    }

    if ( $cvss < $CVSS_CRITICAL_THRESHOLD ) {
        printf( "    [-] [$cve_id] SKIPPED: Severity score (CVSS: %.1f) is below CRITICAL threshold (%.1f)\n",
            $cvss, $CVSS_CRITICAL_THRESHOLD );
        next;
    }

    # 5. Temporal Triage: Enforce 24-hour baseline rule across variations
    my $raw_pub_time = $item->{Published}
                    // $item->{published}
                    // $item->{cveMetadata}{datePublished};

    my $pub_time = parse_publication_time( $raw_pub_time );
    unless ($pub_time) {
        print "    [-] [$cve_id] SKIPPED: Invalid or missing publication timestamp format: "
            . ( $raw_pub_time // 'NULL' ) . "\n";
        next;
    }

    my $age_seconds = $CURRENT_TIME - $pub_time;
    my $age_hours   = $age_seconds / 3600;

    if ( $age_seconds > $SECONDS_IN_24H ) {
        printf( "    [-] [$cve_id] SKIPPED: Published %.1f hours ago (exceeds maximum 24-hour analysis window)\n",
            $age_hours );
        next;
    }

    # Valid critical element confirmed
    $critical_count++;
    printf( "    [+] [$cve_id] PASSED: Severe threat found! CVSS: %.1f | Age: %.1f hours\n",
        $cvss, $age_hours );

    # 6. Target Directory Resolution
    my $lang_dir  = CVE::Folder->$matched_lang;

    # Ensure directory path exists before trying to write into it
    make_path($lang_dir) unless -d $lang_dir;

    my $file_path = "$lang_dir/$cve_id.json";
    my $status    = "NEW";

    # 7. Old vs New dynamic classification via the specific language folder
    if ( -e $file_path ) {
        $status = "OLD";
        print "    [*] Record Check: $cve_id tracking file already exists. Classifying as OLD.\n";
    }
    else {
        print "    [!] Record Check: $cve_id is completely unseen! Classifying as NEW.\n";
        if ( open my $fh, '>', $file_path ) {
            print $fh encode_json($item);
            close $fh;
            print "    [+] State Synchronized: Persistent cache written to $file_path\n";
        }
        else {
            warn "    [-] SYSTEM ERROR: Failed writing state mapping payload to $file_path: $!\n";
        }
    }

    push @processed_alerts,
        {
        id     => $cve_id,
        lang   => $matched_lang,
        cvss   => $cvss,
        status => $status,
        age    => sprintf( "%.1f hrs", $age_hours ),
        desc   => substr( $summary, 0, 75 ) . "..."
        };
}

print "-" x 95 . "\n";
print "[*] Evaluation phase complete. Parsing results summary matrix...\n";

# 8. Clean operational exit fallback if zero entries are found
if ( $critical_count == 0 ) {
    print "[+] Summary: 0 critical vulnerabilities matching your specifications hit the radar in the last 24h.\n";
    print "[+] Operational Sweep Complete. Exiting cleanly with status 0.\n";
    exit 0;
}

# Actionable stdout pipeline summary
print "\n" . "!" x 36 . " ACTIONABLE THREAT REPORT " . "!" x 33 . "\n";
print "=" x 95 . "\n";
foreach my $alert (@processed_alerts) {
    printf( "[%s] [%-5s] %s (CVSS: %.1f | %-9s) - %s\n",
        $alert->{status}, uc( $alert->{lang} ), $alert->{id},
        $alert->{cvss},   $alert->{age},        $alert->{desc}
    );
}
print "=" x 95 . "\n";
print "[!] Actionable threats identified. Exiting with alert status 1.\n";

exit 1;

# Context Helper: standardises ISO timestamps (including timezones) into Unix Epoch metrics
sub parse_publication_time {
    my ($time_str) = @_;
    return undef unless $time_str;

    $time_str =~ s/\.\d+//;      # Strip milliseconds if present
    $time_str =~ s/Z$//;         # Strip literal UTC trailing indicator
    $time_str =~ s/([\+\-]\d{2}):(\d{2})$/$1$2/; # Format numeric offsets from (+00:00) to (+0000) for Time::Piece

    my $t;
    if ($time_str =~ /[\+\-]\d{4}$/) {
        $t = eval { Time::Piece->strptime( substr( $time_str, 0, 24 ), "%Y-%m-%dT%H:%M:%S%z" ) };
    } else {
        $t = eval { Time::Piece->strptime( substr( $time_str, 0, 19 ), "%Y-%m-%dT%H:%M:%S" ) };
    }
    return $t ? $t->epoch : undef;
}
