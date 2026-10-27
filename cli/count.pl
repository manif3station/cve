#!/usr/bin/env perl
#
use strict;
use warnings;
use utf8;
use CVE::Folder;

my $count = 0;
while (my ($lang, $dir) = each CVE::Folder->list->%*) {
    opendir(my $dh, $dir) or die "Unable to read $dir";
    $count += grep { -f "$DIR_CVSS_RECORD/$_" } readdir($dh);
}

print qq{{"count":$count}};
