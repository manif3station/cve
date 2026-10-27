package CVE::Folder;

use strict;
use warnings;

sub _dir {
    my ( $path, $chmod ) = @_;
    $chmod //= 0700;
    mkdir $path, $chmod if !-d $path && $chmod;
    return $path;
}

sub filters {{
    'php'   => qr/\b(php|wordpress)\b/i,
    'python' => qr/\bpython\b/i,
    'perl'  => qr/\bperl\b/i,
    'java'  => qr/\bjava\b/i,
    'go'    => qr/\b(golang|go-lang|go (?:v?\d+(?:\.\d+)+|module|package|library|project|application|service))\b/i,
    'rust'  => qr/\b(rust|rustlang|rust-lang|rustc|cargo)\b/i,
    'cc'    => qr/\b(c\+\+|gcc|clang|\bc\b\s+compiler|\blibc\b)/i,
}}

my @list = keys filters->%*;

sub base { _dir "$ENV{HOME}/.cve" }

foreach my $lang (@list) {
    if ( $lang eq 'cc' ) {
        eval "sub cc { _dir base; _dir base . '/c'; _dir base . '/c/c++' }";
    }
    else {
        eval "sub $lang { _dir base . '/$lang' }";
    }
}

sub list {return {
    map { ( $_ => __PACKAGE__->$_ ) } @list
}}

1;

=head1 NAME

CVE::Folder - language filters and CVE storage directories

=head1 SYNOPSIS

  use CVE::Folder;
  my $directories = CVE::Folder->list;

=head1 DESCRIPTION

Defines the supported textual language filters and creates the corresponding
directories beneath C<~/.cve/> when requested. C and C++ reports are stored in
C<~/.cve/c/c++/>. C<CVE::Research> also identifies languages from package
ecosystems, package URLs and affected product metadata. WordPress advisories are
treated as PHP.

=cut
