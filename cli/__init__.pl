#!/usr/bin/env perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use CVE::Research;

if ( grep { $_ eq '--help' || $_ eq '-h' || $_ eq '/?' } @ARGV ) {
    print "Usage: d2 cve [--help|-h|/?]\nCollect recent vulnerability reports by severity.\n";
    exit 0;
}

exit CVE::Research->run;

=head1 NAME

cve - collect recent vulnerability reports by severity

=head1 SYNOPSIS

  d2 cve [--help|-h|/?]

=head1 DESCRIPTION

Runs the CVE research collector. The C<--help>, C<-h> and C</?> options
display a short usage message.

=cut
