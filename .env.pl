use strict;
use warnings;
use Env qw(
    CVSS_SEVERITY_THRESHOLD
    SECONDS_IN_24H
);
$CVSS_SEVERITY_THRESHOLD = 7.0;
$SECONDS_IN_24H          = 24 * 60 * 60;
1;

=head1 NAME

.env.pl - CVE collector defaults

=head1 DESCRIPTION

Sets the research collector defaults: a minimum CVSS score of 7.0, which
includes HIGH and CRITICAL reports, and a maximum report age of 24 hours. The
Developer Dashboard loads these values into the C<d2 env> environment.

=cut
