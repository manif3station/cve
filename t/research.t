use strict;
use warnings;
use Test::More;
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use JSON qw(encode_json decode_json);
use lib 'lib';
use CVE::Research;

for my $help_arg ('--help', '-h', '/?') {
    my $help = `$^X -Ilib cli/__init__.pl $help_arg`;
    is($? >> 8, 0, "research command accepts $help_arg");
    like($help, qr/Usage: d2 cve/, "research command documents $help_arg");
}

my $now = CVE::Research::parse_publication_time('2026-10-27T12:00:00Z');
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
    { score => 'invalid' }, { score => undef }, { score => 'CVSS:3.1:8.8' },
] }), 8.8, 'accepts a CVSS vector score after invalid values');
is(CVE::Research::_score({ severity => [ { score => '0' }, { score => '6.6' } ] }), 6.6,
    'continues past a zero severity score');
is(CVE::Research::_score({ containers => { cna => { metrics => [
    { cvssV3_0 => { baseScore => 6.2 } },
] } } }), 6.2, 'uses a CVSS v3.0 metric');
is(CVE::Research::_score({ containers => { cna => { metrics => [
    {}, { cvssV4_0 => { baseScore => 7.0 } },
] } } }), 7.0, 'continues to a later positive metric');
is(CVE::Research::_score({ containers => { cna => { metrics => [] } } }), 0,
    'returns zero for an empty metric list');
is(CVE::Research::_score({}), 0, 'defaults an absent score to zero');

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
is($captured_url, 'https://vulnerability.circl.lu/api/last', 'fetches the public feed URL');
like($output, qr/\[NEW\].*CVE-NEW/s, 'includes a new report in the action report');
like($output, qr/\[OLD\].*CVE-OLD/s, 'classifies an existing report as old');
like($output, qr/CVE-METRIC/, 'normalises CVE v5 identifiers and descriptions');
like($output, qr/CVE-SEVERITY/, 'accepts a severity score');
like($output, qr/UNKNOWN-CVE/, 'uses a fallback identifier when no CVE ID exists');
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

done_testing;
