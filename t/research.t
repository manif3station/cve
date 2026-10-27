use strict;
use warnings;
use Test::More;
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use JSON qw(encode_json decode_json);
use lib 'lib';
use CVE::Research;
use CVE::Folder;

for my $help_arg ('--help', '-h', '/?') {
    my $help = `$^X -Ilib cli/__init__.pl $help_arg`;
    is($? >> 8, 0, "research command accepts $help_arg");
    like($help, qr/Usage: d2 cve/, "research command documents $help_arg");
}

my $now = CVE::Research::parse_publication_time('2026-10-27T15:00:00Z');
ok($now, 'parses a UTC timestamp');
is(CVE::Research::parse_publication_time(undef), undef, 'rejects a missing timestamp');
is(CVE::Research::parse_publication_time('not a date'), undef, 'rejects an invalid timestamp');
ok(CVE::Research::parse_publication_time('2026-10-27T12:00:00.123+01:00'),
    'parses a fractional timestamp with a timezone offset');

is(CVE::Research::_score({ cvss => 8.1 }), 8.1, 'uses the direct CVSS score');
is(CVE::Research::_score({ containers => { cna => { metrics => [
    { cvssV4_0 => { baseScore => 9.2 } },
] } } }), 9.2, 'uses a CVSS v4 metric');
is(CVE::Research::_score({ containers => { cna => { metrics => [
    { cvssV4_0 => { baseScore => 0 }, cvssV3_1 => { baseScore => 7.1 } },
] } } }), 0, 'uses a defined zero metric score');
is(CVE::Research::_score({ containers => { cna => { metrics => [
    { cvssV3_1 => { baseScore => 7.2 } },
] } } }), 7.2, 'uses a CVSS v3.1 metric');
is(CVE::Research::_score({ containers => { cna => { metrics => [
    { cvssV3_0 => { baseScore => 6.2 } },
] } } }), 6.2, 'uses a CVSS v3.0 metric');
is(CVE::Research::_score({ severity => [ { score => '8.1' } ] }), 8.1,
    'uses a numeric severity score');
is(CVE::Research::_score({ severity => [
    { score => 'invalid' }, { score => undef },
    { score => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
] }), 9.8, 'calculates a CVSS 3.1 vector after invalid values');
is(CVE::Research::_score({ severity => [ { score => '0' }, { score => '6.6' } ] }), 0,
    'uses the first numeric severity score');
is(CVE::Research::_score({ containers => { cna => { metrics => [
    { cvssV3_0 => { baseScore => 6.2 } },
] } } }), 6.2, 'uses a CVSS v3.0 metric');
is(CVE::Research::_score({ containers => { cna => { metrics => [
    {}, { cvssV4_0 => { baseScore => 7.0 } },
] } } }), 7.0, 'continues to a later positive metric');
is(CVE::Research::_score({ containers => { cna => { metrics => [] } } }), undef,
    'returns no score for an empty metric list');
is(CVE::Research::_score({}), undef, 'does not invent a score when none is available');
is(CVE::Research::_severity_level(9.0), 'CRITICAL', 'labels critical scores');
is(CVE::Research::_severity_level(7.0), 'HIGH', 'labels high scores');
is(CVE::Research::_severity_level(4.0), 'MEDIUM', 'labels medium scores');
is(CVE::Research::_severity_level(0.1), 'LOW', 'labels low scores');
is(CVE::Research::_severity_level(0), 'NONE', 'labels zero scores');
is(CVE::Research::_score({ cvss => 'CVSS:4.0/not-a-supported-vector' }), undef,
    'does not guess the score of an unsupported vector');
is(CVE::Research::_score({ cvss => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }), 9.8,
    'calculates a CVSS vector from the top-level score field');
is(CVE::Research::_cvss31_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8,
    'calculates the standard 9.8 CVSS 3.1 vector');
is(CVE::Research::_cvss31_score('CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H'), 6.5,
    'calculates a CVSS 3.0 vector');
is(CVE::Research::_cvss31_score('not-a-vector'), undef, 'rejects a malformed vector');
is(CVE::Research::_cvss31_score(undef), undef, 'rejects an absent vector');
is(CVE::Research::_cvss31_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0,
    'scores zero impact as zero');
is(CVE::Research::_cvss31_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'), 9.1,
    'calculates an unchanged scope vector');
is(CVE::Research::_cvss31_score('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N'), 8.7,
    'calculates a changed scope vector');
is(CVE::Research::_cvss31_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10,
    'caps maximum vector score at 10');
my $valid_vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
for my $metric (qw(AV AC PR UI S C I A)) {
    my $incomplete = $valid_vector;
    $incomplete =~ s{/$metric:[^/]+}{};
    is(CVE::Research::_cvss31_score($incomplete), undef,
        "rejects a vector missing $metric");
}
for my $bad_metric (
    'AV:X', 'AC:X', 'PR:X', 'UI:X', 'S:X', 'C:X', 'I:X', 'A:X',
) {
    my $invalid = $valid_vector;
    my ($key) = split /:/, $bad_metric;
    $invalid =~ s{/$key:[^/]+}{/$bad_metric};
    is(CVE::Research::_cvss31_score($invalid), undef,
        "rejects invalid $key metric value");
}

my $filters = CVE::Folder->filters;
is(CVE::Research::_identify_language(
    { affected => [{ package => { ecosystem => 'PyPI', purl => 'pkg:pypi/picklescan' } }] },
    'picklescan vulnerability', $filters,
), 'python', 'identifies Python from an OSV PyPI ecosystem');
is(CVE::Research::_identify_language(
    { affected => [{ package => { ecosystem => 'Maven', name => 'org.example:lib' } }] },
    'dependency issue', $filters,
), 'java', 'identifies Java from a Maven ecosystem');
is(CVE::Research::_identify_language(
    { affected => [{ package => { purl => 'pkg:golang/example.org/lib' } }] },
    'dependency issue', $filters,
), 'go', 'identifies Go from a package URL');
is(CVE::Research::_identify_language(
    { affected => [{ package => { ecosystem => 'CPAN', name => 'Example' } }] },
    'dependency issue', $filters,
), 'perl', 'identifies Perl from a CPAN ecosystem');
is(CVE::Research::_identify_language(
    { affected => [{ package => { ecosystem => 'Packagist', name => 'vendor/package' } }] },
    'dependency issue', $filters,
), 'php', 'identifies PHP from a Packagist ecosystem');
is(CVE::Research::_identify_language(
    { affected => [{ package => { ecosystem => 'Unknown', purl => 'pkg:pypi/picklescan' } }] },
    'dependency issue', $filters,
), 'python', 'uses a PyPI package URL when its ecosystem is unknown');
is(CVE::Research::_identify_language(
    { affected => [{ package => { purl => 'pkg:maven/org.example/lib' } }] },
    'dependency issue', $filters,
), 'java', 'identifies Java from a Maven package URL');
is(CVE::Research::_identify_language(
    { affected => [{ package => { purl => 'pkg:cpan/Example' } }] },
    'dependency issue', $filters,
), 'perl', 'identifies Perl from a CPAN package URL');
is(CVE::Research::_identify_language(
    { affected => [{ package => { purl => 'pkg:composer/vendor/package' } }] },
    'dependency issue', $filters,
), 'php', 'identifies PHP from a Composer package URL');
is(CVE::Research::_identify_language(
    { affected => [{ package => { purl => 'pkg:unknown/vendor/package' } }] },
    'dependency issue', $filters,
), '', 'ignores unrecognised package URLs');
is(CVE::Research::_identify_language(
    { affected => [{ ecosystem => 'Go Modules', package => 'example' }] },
    'dependency issue', $filters,
), 'go', 'identifies Go from an affected ecosystem');
is(CVE::Research::_identify_language(
    { containers => { cna => { affected => [{ vendor => 'python-pillow', product => 'Pillow' }] } } },
    'image library issue', $filters,
), 'python', 'identifies Python from CVE affected vendor metadata');
is(CVE::Research::_identify_language({}, 'C++ compiler flaw', $filters),
    'cc', 'falls back to the description language filter');
is(CVE::Research::_identify_language({}, 'unrelated application issue', $filters),
    '', 'ignores unsupported language records');
is(CVE::Research::_identify_language({}, 'Go 1.27 builds reject malformed requests', $filters),
    'go', 'identifies Go from a versioned language description');
is(CVE::Research::_identify_language({}, 'WordPress plugin security issue', $filters),
    'php', 'identifies WordPress plugin issues as PHP');
is(CVE::Research::_identify_language(
    { affected => ['invalid', { package => { name => ['not scalar'] } }] },
    'unrelated issue', $filters,
), '', 'ignores malformed affected entries');
is(CVE::Research::_score({ containers => { cna => { metrics => [
    { cvssV4_0 => {} },
] } } }), undef, 'ignores metrics without a base score');
is(CVE::Research::_score({ containers => { cna => { metrics => [
    { cvssV4_0 => { baseScore => 'unknown' } },
] } } }), undef, 'ignores non-numeric metric scores');

my $home = tempdir(CLEANUP => 1);
local $ENV{HOME} = $home;
my $php_dir = "$home/.cve/php";
make_path($php_dir);
open my $old_record, '>', "$php_dir/CVE-OLD.json" or die $!;
print {$old_record} '{}';
close $old_record;

my $items = [
    { id => 'NO-SUMMARY' },
    { id => 'UNMATCHED', summary => 'A library for an unrelated platform' },
    { id => 'LOW-SCORE', summary => 'PHP package', cvss => 4.9,
      published => '2026-10-27T11:00:00Z' },
    { id => 'BAD-DATE', summary => 'Python package', cvss => 9.0 },
    { id => 'INVALID-DATE', summary => 'Java library', cvss => 9.0,
      published => 'not a date' },
    { id => 'TOO-OLD', summary => 'Java library', cvss => 9.0,
      published => '2026-10-25T11:00:00Z' },
    { id => 'CVE-NEW', summary => 'Python package with a severe flaw', cvss => 9.8,
      published => '2026-10-27T11:00:00.123Z' },
    { id => 'CVE-OLD', details => 'PHP extension vulnerability', cvss => 8.0,
      Published => '2026-10-27T11:00:00Z' },
    { cveMetadata => { cveId => 'CVE-METRIC', datePublished => '2026-10-27T11:00:00Z' },
      containers => { cna => { descriptions => [ { value => 'Golang module vulnerability' } ],
        metrics => [ { cvssV4_0 => { baseScore => 8.5 } } ] } } },
    { id => 'CVE-SEVERITY', summary => 'Perl package flaw',
      severity => [ { score => '6.5' } ], published => '2026-10-27T11:00:00Z' },
    { summary => 'Go-lang service vulnerability', cvss => 6.0,
      published => '2026-10-27T11:00:00Z' },
    { id => 'GHSA-PYTHON', details => 'picklescan before 0.0.22 is vulnerable',
      affected => [{ package => { ecosystem => 'PyPI', name => 'picklescan',
        purl => 'pkg:pypi/picklescan' } }],
      severity => [{ type => 'CVSS_V3',
        score => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      published => '2026-10-27T11:00:00Z', modified => '2026-10-27T11:30:00Z' },
    { cveMetadata => { cveId => 'CVE-2026-96636',
        datePublished => '2026-10-21T21:05:20.850Z',
        dateUpdated => '2026-10-27T11:40:00Z' },
      containers => { cna => {
        descriptions => [{ lang => 'en', value => 'Pillow is an imaging library.' }],
        affected => [{ vendor => 'python-pillow', product => 'Pillow' }],
        metrics => [{ cvssV3_1 => { baseScore => 6.5, baseSeverity => 'MEDIUM' } }],
      } } },
    { cveMetadata => { cveId => 'CVE-2026-92885',
        datePublished => '2026-10-27T08:28:43.933Z',
        dateUpdated => '2026-10-27T14:13:43.451Z' },
      containers => { cna => {
        descriptions => [{ lang => 'en',
          value => 'The Qode Membership plugin for WordPress is vulnerable to authentication bypass.' }],
        affected => [{ vendor => 'Qode Themes', product => 'Qode Membership' }],
        metrics => [{ cvssV3_1 => { baseScore => 9.8, baseSeverity => 'CRITICAL' } }],
      } } },
    { id => 'NO-SCORE', details => 'Go module has a defect',
      affected => [{ package => { ecosystem => 'Go' } }],
      published => '2026-10-27T11:00:00Z' },
    { id => 'FUTURE', summary => 'Java package issue', cvss => 9.0,
      published => '2026-10-27T11:00:00Z', modified => '2026-10-28T11:00:00Z' },
];

my $captured_url;
my $output = '';
open my $out, '>', \$output or die $!;
my $status = CVE::Research->run(
    now => $now,
    threshold => 5,
    window => 24 * 60 * 60,
    fetch => sub {
        $captured_url = shift;
        return { success => 1, content => encode_json($items) };
    },
    out => $out,
);
close $out;
is($status, 1, 'returns alert status when reports meet the severity threshold');
is($captured_url,
    'https://vulnerability.circl.lu/api/vulnerability/?since=2026-10-26&per_page=100&date_sort=updated&sort_order=desc&page=1',
    'requests the first recent, updated-sorted feed page');
like($output, qr/\[NEW\].*CVE-NEW/s, 'includes a new report in the action report');
like($output, qr/\[OLD\].*CVE-OLD/s, 'classifies an existing report as old');
like($output, qr/CVE-METRIC/, 'normalises CVE v5 identifiers and descriptions');
like($output, qr/CVE-SEVERITY/, 'accepts a severity score');
like($output, qr/UNKNOWN-CVE/, 'uses a fallback identifier when no CVE ID exists');
like($output, qr/\[CRITICAL\].*GHSA-PYTHON/s,
    'scores OSV vectors and reports their severity level');
like($output, qr/\[MEDIUM\s*\].*\[PYTHON\s*\].*CVE-2026-96636/s,
    'uses CVE affected metadata, numeric CVSS metrics and update time');
like($output, qr/\[CRITICAL\s*\].*\[PHP\s*\].*CVE-2026-92885/s,
    'identifies and scores a real WordPress plugin CVE payload');
like($output, qr/No supported numeric CVSS base score/, 'skips records without a usable score');
like($output, qr/FUTURE.*future/s, 'rejects update times later than the current time');
like($output, qr/Last updated .*exceeds maximum/, 'uses update time for feed recency');
ok(-f "$home/.cve/python/CVE-NEW.json", 'persists the new report in its language folder');
is(decode_json(do { local $/; open my $fh, '<', "$home/.cve/python/CVE-NEW.json" or die $!; <$fh> })->{id},
    'CVE-NEW', 'stores the original JSON record');

my $empty_output = '';
open my $empty_out, '>', \$empty_output or die $!;
is(CVE::Research->run(
    now => $now,
    threshold => 5,
    fetch => sub { return { success => 1, content => '[]' } },
    out => $empty_out,
), 0, 'returns success when there are no matching reports');
close $empty_out;

my $error_output = '';
open my $error_out, '>', \$error_output or die $!;
eval {
    CVE::Research->run(
        fetch => sub { return { success => 0, status => 503, reason => 'Unavailable' } },
        out => $error_out,
    );
};
like($@, qr/Feed ingestion failed: 503 Unavailable/, 'reports feed request failures');

eval {
    CVE::Research->run(
        fetch => sub { return { success => 1, content => '{invalid' } },
        out => $error_out,
    );
};
like($@, qr/JSON payload evaluation failure/, 'reports invalid feed JSON');

my $write_error_output = '';
open my $write_out, '>', \$write_error_output or die $!;
my $write_error = '';
{
    local *STDERR;
    open STDERR, '>', \$write_error or die $!;
    my $error_items = [{ id => 'BROKEN/RECORD', summary => 'PHP flaw', cvss => 7,
        published => '2026-10-27T11:00:00Z' }];
    is(CVE::Research->run(
        now => $now,
        threshold => 5,
        fetch => sub { return { success => 1, content => encode_json($error_items) } },
        out => $write_out,
    ), 1, 'returns alert status after a failed record write');
}
like($write_error, qr/Failed writing state mapping payload/, 'reports record write failures');
close $write_out;

my $explicit_error = '';
open my $explicit_err, '>', \$explicit_error or die $!;
my $explicit_out_text = '';
open my $explicit_out, '>', \$explicit_out_text or die $!;
my $broken_item = [{ id => 'BROKEN2/RECORD', summary => 'PHP flaw', cvss => 7,
    published => '2026-10-27T11:00:00Z' }];
is(CVE::Research->run(
    now => $now,
    threshold => 5,
    fetch => sub { return { success => 1, content => encode_json($broken_item) } },
    out => $explicit_out,
    err => $explicit_err,
), 1, 'accepts a separate error output handle');
close $explicit_err;
like($explicit_error, qr/Failed writing state mapping payload/,
    'writes storage errors to the supplied error handle');
close $explicit_out;

my $default_output = '';
{
    local *STDOUT;
    open STDOUT, '>', \$default_output or die $!;
    local $CVE::Research::CVSS_SEVERITY_THRESHOLD = undef;
    local $CVE::Research::SECONDS_IN_24H = undef;
    no warnings 'redefine';
    local *HTTP::Tiny::new = sub { bless {}, 'HTTP::Tiny' };
    local *HTTP::Tiny::get = sub { return { success => 1, content => '[]' } };
    is(CVE::Research->run, 0, 'uses the default HTTP client and environment settings');
}
like($default_output, qr/Operational Sweep Complete/, 'writes to standard output by default');

my $csaf = {
    document => {
        tracking => {
            id => 'RHSA-2026:99999',
            initial_release_date => '2026-10-27T13:00:00Z',
            current_release_date => '2026-10-27T14:00:00Z',
        },
        notes => [{ category => 'summary', text => 'CSAF advisory fallback summary' }],
    },
    vulnerabilities => [
        {
            cve => 'CVE-CSAF-GO',
            notes => [{ category => 'description', text => 'Golang crypto module issue' }],
            scores => [{ cvss_v3 => { baseScore => 7.5,
                vectorString => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' } }],
        },
        {
            ids => [{ text => 'CVE-CSAF-PYTHON' }],
            notes => [{ category => 'summary', text => 'Python library issue' }],
            scores => [{ cvss_v3 => { vectorString =>
                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }],
        },
        {},
    ],
};
my $csaf_records = CVE::Research::_normalise_records([$csaf]);
is(scalar @$csaf_records, 3, 'expands each CSAF vulnerability into its own record');
is($csaf_records->[0]{id}, 'CVE-CSAF-GO', 'uses a CSAF vulnerability CVE ID');
is($csaf_records->[1]{id}, 'CVE-CSAF-PYTHON', 'uses a CSAF external CVE ID');
is($csaf_records->[2]{id}, 'RHSA-2026:99999-003', 'creates a unique CSAF advisory fallback ID');
is($csaf_records->[0]{cvss}, 7.5, 'reads numeric scores from CSAF score objects');
is(CVE::Research::_score($csaf_records->[1]), 9.8,
    'scores a CVSS vector from a CSAF score object');
is($csaf_records->[2]{summary}, 'CSAF advisory fallback summary',
    'uses the CSAF document summary as a fallback');
is(CVE::Research::_csaf_score({ scores => [
    { cvss_v3 => { baseScore => 5.0 } }, { cvss_v4 => { baseScore => 8.0 } },
] }), 8.0, 'selects the highest numeric CSAF score');
is(CVE::Research::_csaf_score({}), undef, 'leaves absent CSAF scores unknown');
is(CVE::Research::_csaf_summary({ notes => [ 'bad note',
    { category => 'other', text => 'ignored' }, { category => 'description', text => '' } ] },
    { notes => [ 'bad note', { category => 'other', text => 'ignored' },
        { category => 'summary', text => '' }, { category => 'general', text => 'Document fallback' } ] }),
    'Document fallback', 'ignores invalid CSAF notes and uses general document notes');
is(CVE::Research::_csaf_summary({ title => 'Vulnerability title' }, {}),
    'Vulnerability title', 'uses the CSAF vulnerability title as a fallback');
is(CVE::Research::_csaf_summary({}, { notes => 'not a list' }), '',
    'returns an empty CSAF summary when no notes are available');
is(CVE::Research::_raw_event_time({ document => { tracking => {
    current_release_date => '2026-10-27T14:00:00Z' } } }), '2026-10-27T14:00:00Z',
    'uses a CSAF current release date');
is(CVE::Research::_raw_event_time({ document => { tracking => {
    initial_release_date => '2026-10-27T13:00:00Z' } } }), '2026-10-27T13:00:00Z',
    'uses a CSAF initial release date when no current date exists');
is(CVE::Research::_raw_event_time({}), undef,
    'returns no event time when the record has no timestamps');
is(CVE::Research::_normalise_records([{ vulnerabilities => [] }])->[0]{vulnerabilities}[0], undef,
    'passes through items without CSAF document metadata');
is(scalar @{ CVE::Research::_normalise_records([{ document => {}, vulnerabilities => [
    'bad', { ids => ['bad', {}, { text => 'GHSA-not-cve' }] },
] }]) }, 1, 'skips malformed vulnerabilities and creates a fallback CSAF ID');
is(CVE::Research::_csaf_score({ scores => [ 'bad',
    { cvss_v4 => { baseScore => 'unknown', vectorString => '' } },
] }), undef, 'ignores malformed CSAF scores and empty vectors');
is(CVE::Research::_csaf_summary({ notes => [
    { category => undef, text => 'ignored' },
    { category => 'description' },
], title => '' }, { notes => [
    { category => undef, text => 'ignored' },
    { category => 'summary' },
] }), '', 'ignores CSAF notes without categories or text and empty titles');
my $csaf_fallback_dates = CVE::Research::_normalise_records([{ document => { tracking => {
    initial_release_date => '2026-10-27T13:00:00Z' } }, vulnerabilities => [
        { release_date => '2026-10-27T12:00:00Z' }, {},
    ] }]);
is($csaf_fallback_dates->[0]{published}, '2026-10-27T12:00:00Z',
    'prefers a CSAF vulnerability release date');
is($csaf_fallback_dates->[1]{published}, '2026-10-27T13:00:00Z',
    'uses the CSAF initial release date as a publication fallback');
my $csaf_item_fallback_dates = CVE::Research::_normalise_records([
    { modified => '2026-10-27T14:00:00Z', published => '2026-10-27T13:00:00Z',
      document => { tracking => {} }, vulnerabilities => [{}] },
]);
is($csaf_item_fallback_dates->[0]{modified}, '2026-10-27T14:00:00Z',
    'falls back to the advisory modified date');
is($csaf_item_fallback_dates->[0]{published}, '2026-10-27T13:00:00Z',
    'falls back to the advisory published date');

my @fetch_urls;
my $page_one = [ map {{
    id => "PAGE-$_",
    published => '2026-10-27T14:30:00Z',
}} 1 .. 100 ];
my $page_two = [{ id => 'PAGE-TWO', summary => 'Go module issue', cvss => 7.5,
    published => '2026-10-27T14:30:00Z' }];
my $page_output = '';
open my $page_out, '>', \$page_output or die $!;
is(CVE::Research->run(
    now => $now,
    threshold => 5,
    window => 24 * 60 * 60,
    out => $page_out,
    fetch => sub {
        my ($url) = @_;
        push @fetch_urls, $url;
        return { success => 1,
            content => encode_json(@fetch_urls == 1 ? $page_one : $page_two) };
    },
), 1, 'collects a matching record from a later API page');
close $page_out;
is(scalar @fetch_urls, 2, 'fetches the next page while current records remain recent');
like($page_output, qr/PAGE-TWO/, 'includes records from subsequent API pages');

my @stale_urls;
my $stale_page = [ map {{
    id => "OLD-$_",
    published => '2026-10-25T10:00:00Z',
}} 1 .. 100 ];
my $stale_output = '';
open my $stale_out, '>', \$stale_output or die $!;
is(CVE::Research->run(
    now => $now,
    out => $stale_out,
    fetch => sub {
        push @stale_urls, shift;
        return { success => 1,
            content => encode_json(@stale_urls == 1 ? $stale_page : []) };
    },
), 0, 'finishes cleanly when a page contains only old records');
close $stale_out;
is(scalar @stale_urls, 2, 'reads all incremental pages before applying the age filter');

my $limit_warning = '';
open my $limit_err, '>', \$limit_warning or die $!;
my $limit_out_text = '';
open my $limit_out, '>', \$limit_out_text or die $!;
CVE::Research->run(
    now => $now,
    max_pages => 1,
    out => $limit_out,
    err => $limit_err,
    fetch => sub { return { success => 1, content => encode_json($page_one) } },
);
close $limit_out;
close $limit_err;
like($limit_warning, qr/page limit \(1\)/, 'warns if the pagination safety limit is reached');

my $bad_shape = '';
open my $shape_out, '>', \$bad_shape or die $!;
eval {
    CVE::Research->run(
        out => $shape_out,
        fetch => sub { return { success => 1, content => '{"items":[]}' } },
    );
};
like($@, qr/API payload must be a JSON array/, 'rejects non-array API payloads');
close $shape_out;

done_testing;
