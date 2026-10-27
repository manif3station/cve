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
    'php'   => qr/\bphp\b/i,
    'python' => qr/\bpython\b/i,
    'perl'  => qr/\bperl\b/i,
    'java'  => qr/\bjava\b/i,
    'go'    => qr/\b(golang|go-lang)\b/i,
    'cc'    => qr/\b(c\+\+|gcc|clang|\bc\b\s+compiler|\blibc\b)/i,
}}

my @list = keys filters->%*;

sub base { _dir "$ENV{HOME}/.cve" }

foreach my $lang (@list) {
    eval "sub $lang { _dir base . '/$lang' }";
}

sub list {return {
    map { ( $_ => __PACKAGE__->$_ ) } @list
}}

1;
