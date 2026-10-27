#!/usr/bin/env perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use CVE::Count;

if ( grep { $_ eq '--help' || $_ eq '-h' || $_ eq '/?' } @ARGV ) {
    print "Usage: d2 cve.count [--help|-h|/?]\nCount saved CVE JSON reports by language.\n";
    exit 0;
}

exit CVE::Count->run;

=head1 NAME

cve.count - count stored CVE reports

=head1 SYNOPSIS

  d2 cve.count [--help|-h|/?]

=head1 DESCRIPTION

Prints a JSON object containing the number of saved CVE report files.
The C<--help>, C<-h> and C</?> options display a short usage message.

=cut
