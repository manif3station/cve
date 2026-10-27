package CVE::Folder;

use strict;
use warnings;
use Env qw(CVE_TARGET);

my %TARGET_ALIASES = (
    cc          => 'cc',
    c           => 'cc',
    'c++'       => 'cc',
    'c/c++'     => 'cc',
    java        => 'java',
    go          => 'go',
    golang      => 'go',
    perl        => 'perl',
    cpan        => 'perl',
    php         => 'php',
    wordpress   => 'php',
    python      => 'python',
    rust        => 'rust',
    rustlang    => 'rust',
    'rust-lang' => 'rust',
    rustc       => 'rust',
    cargo       => 'rust',
);

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

sub targets {
    my ( $class, $value ) = @_;
    $value = $CVE_TARGET unless @_ > 1;
    return [ sort keys filters->%* ] unless defined $value && $value =~ /\S/;

    my ( %selected, @unsupported );
    for my $target ( split /,/, $value ) {
        $target =~ s/^\s+|\s+$//g;
        next unless length $target;
        my $language = $TARGET_ALIASES{ lc $target };
        if ( !defined $language ) {
            push @unsupported, $target;
            next;
        }
        $selected{$language} = 1;
    }
    die 'Unsupported CVE_TARGET value(s): ' . join( ', ', @unsupported ) . "\n"
        if @unsupported;
    return [ sort keys %selected ];
}

sub target_filters {
    my $all_filters = filters;
    my $targets = __PACKAGE__->targets;
    return { map { $_ => $all_filters->{$_} } @$targets };
}

sub base { _dir "$ENV{HOME}/.cve" }

foreach my $lang (@list) {
    if ( $lang eq 'cc' ) {
        eval "sub cc { _dir base; _dir base . '/c'; _dir base . '/c/c++' }";
    }
    else {
        eval "sub $lang { _dir base . '/$lang' }";
    }
}

sub list {
    my $targets = __PACKAGE__->targets;
    return { map { ( $_ => __PACKAGE__->$_ ) } @$targets };
}

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
treated as PHP. The optional C<CVE_TARGET> environment variable accepts a
comma-separated, case-insensitive list of language names and aliases. Leading
and trailing whitespace is ignored. If C<CVE_TARGET> is unset or blank, every
supported language is enabled. C<targets> returns the selected canonical names,
C<target_filters> returns only their matching filters, and C<list> returns only
their storage directories. C, C++, C/C++ and CC select the C<cc> target; CPAN
selects Perl; and Cargo, RustLang and Rust select Rust. Perl affected packages
in CVE records are identified using their C<pkg:cpan/> package URLs.

=cut
