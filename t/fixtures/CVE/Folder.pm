package CVE::Folder;

use strict;
use warnings;

sub list {
    return { missing => '/cve-test-directory-that-does-not-exist' };
}

1;
