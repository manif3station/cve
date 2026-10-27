use strict;
use warnings;
use Test::More;
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use lib 'lib';
use CVE::Folder;

my $home = tempdir(CLEANUP => 1);
local $ENV{HOME} = $home;

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
    cc     => 'C++ compiler',
);
for my $language (sort keys %examples) {
    like($examples{$language}, $filters->{$language}, "$language filter matches");
}
unlike('Python', $filters->{php}, 'language filters remain distinct');

my $directories = CVE::Folder->list;
is_deeply([sort keys %$directories], [sort keys %examples],
    'list returns every supported language');
for my $language (keys %examples) {
    ok(-d $directories->{$language}, "$language directory is created");
}

done_testing;
