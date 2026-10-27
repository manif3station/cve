use strict;
use warnings;
use Test::More;
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use lib 'lib';
use CVE::Count;

my $home = tempdir(CLEANUP => 1);
my $php = "$home/.cve/php";
make_path($php);
open my $json, '>', "$php/CVE-2026-0001.json" or die $!;
print {$json} '{}';
close $json;
open my $text, '>', "$php/notes.txt" or die $!;
print {$text} 'ignore';
close $text;
mkdir "$php/fake.json" or die $!;

local $ENV{HOME} = $home;
my $module_output = '';
open my $module_out, '>', \$module_output or die $!;
is(CVE::Count->run(out => $module_out), 0, 'count module succeeds');
close $module_out;
is($module_output, '{"count":1}', 'count module reports saved JSON files');

my $output = `$^X -Ilib cli/count.pl`;
is($? >> 8, 0, 'count command exits successfully');
is($output, '{"count":1}', 'counts JSON reports and ignores other files');

my $empty_output = '';
open my $empty_out, '>', \$empty_output or die $!;
is(CVE::Count->run(out => $empty_out, directories => {}), 0,
    'count module handles an empty directory list');
close $empty_out;
is($empty_output, '{"count":0}', 'empty directory list returns zero');

my $count_error = '';
eval { CVE::Count->run(directories => { missing => "$home/missing" }); };
like($@, qr/Unable to read/, 'count module reports an unreadable directory');

for my $help_arg ('--help', '-h', '/?') {
    my $help = `$^X -Ilib cli/count.pl $help_arg`;
    is($? >> 8, 0, "count command accepts $help_arg");
    like($help, qr/Usage: d2 cve\.count/, "count command documents $help_arg");
}

done_testing;
