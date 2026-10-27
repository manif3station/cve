use strict;
use warnings;
use Test::More;
use File::Path qw(make_path);
use File::Temp qw(tempdir);

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
my $output = `$^X -Ilib cli/count.pl`;
is($? >> 8, 0, 'count command exits successfully');
is($output, '{"count":1}', 'counts JSON reports and ignores other files');

my $failed = `$^X -It/fixtures cli/count.pl 2>/dev/null`;
is($? >> 8, 2, 'count command reports an unreadable language directory');

done_testing;
