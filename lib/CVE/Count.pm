package CVE::Count;

use strict;
use warnings;
use CVE::Folder;

sub run {
    my ( $class, %options ) = @_;
    my $out = $options{out} // \*STDOUT;
    my $directories = defined $options{directories}
        ? $options{directories}
        : CVE::Folder->list;
    my $count = 0;

    foreach my $dir ( values %$directories ) {
        opendir( my $dh, $dir ) or die "Unable to read $dir";
        $count += grep { /\.json\z/ && -f "$dir/$_" } readdir($dh);
        closedir($dh);
    }

    print {$out} qq{{"count":$count}};
    return 0;
}

1;

=head1 NAME

CVE::Count - count saved CVE reports

=head1 SYNOPSIS

  CVE::Count->run;

=head1 DESCRIPTION

Counts JSON report files in the language directories returned by
C<CVE::Folder> and writes the count as a JSON object. The C<directories>
and C<out> options can be supplied to C<run> for testing.

=cut
