use strict;
use warnings;
use Env qw(
    CVSS_CRITICAL_THRESHOLD
    SECONDS_IN_24H
);
$CVSS_CRITICAL_THRESHOLD = 5.0;
$SECONDS_IN_24H          = 24 * 60 * 60;
1;
