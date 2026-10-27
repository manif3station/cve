use strict;
use warnings;
use Test::More;
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use lib 'lib';
use CVE::Folder;

my $home = tempdir(CLEANUP => 1);
local $ENV{HOME} = $home;
local $ENV{CVE_TARGET} = undef;

my $base = CVE::Folder->base;
ok(-d $base, 'base directory is created');
is(CVE::Folder->base, $base, 'existing base directory is reused');

my $existing = "$home/existing";
make_path($existing);
is(CVE::Folder::_dir($existing), $existing, 'existing directory is returned');

my $not_created = "$home/not-created";
is(CVE::Folder::_dir($not_created, 0), $not_created,
    'directory creation can be disabled');
ok(!-e $not_created, 'disabled directory creation leaves no directory');

my $filters = CVE::Folder->filters;
my %examples = (
    php    => 'PHP application',
    python => 'Python package',
    perl   => 'Perl module',
    java   => 'Java library',
    go     => 'Golang project',
    rust   => 'Rust crate',
    cc     => 'C++ compiler',
);
for my $language (sort keys %examples) {
    like($examples{$language}, $filters->{$language}, "$language filter matches");
}
like('WordPress plugin vulnerability', $filters->{php},
    'recognises WordPress plugin issues as PHP');
unlike('Python', $filters->{php}, 'language filters remain distinct');

my $directories = CVE::Folder->list;
is_deeply([sort keys %$directories], [sort keys %examples],
    'list returns every supported language');
is($directories->{cc}, "$home/.cve/c/c++",
    'stores C and C++ reports in the documented directory');
for my $language (keys %examples) {
    ok(-d $directories->{$language}, "$language directory is created");
}

is_deeply(CVE::Folder->targets(' PHP '), ['php'],
    'parses a single target and trims surrounding whitespace');
is_deeply(CVE::Folder->targets('php,,rust'), ['php', 'rust'],
    'ignores empty CSV entries');
is_deeply(CVE::Folder->targets(' rUsT, GO '), ['go', 'rust'],
    'parses multiple case-insensitive targets and trims each value');
is_deeply(CVE::Folder->targets('Rust, rust, Cargo'), ['rust'],
    'canonicalises aliases and removes duplicate targets');
is_deeply(CVE::Folder->targets('C/C++'), ['cc'],
    'accepts the documented C and C++ target name');
is_deeply(CVE::Folder->targets(' CPAN '), ['perl'],
    'accepts CPAN as an alias for Perl');
is_deeply(CVE::Folder->targets('  '), [sort keys %examples],
    'treats a blank target setting as all supported languages');
eval { CVE::Folder->targets('php,unknown'); };
like($@, qr/Unsupported CVE_TARGET value\(s\): unknown/,
    'rejects unsupported target names');

{
    local $ENV{CVE_TARGET} = ' php, RuSt ';
    is_deeply([sort keys %{ CVE::Folder->list }], [qw(php rust)],
        'limits storage directories to configured targets');
    is_deeply([sort keys %{ CVE::Folder->target_filters }], [qw(php rust)],
        'limits research filters to configured targets');
}

done_testing;
