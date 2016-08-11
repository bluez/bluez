#!/usr/bin/perl

# parse companies from
# https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers

use strict;
# use URI::Encode qw(uri_decode);

my %known_entities = (
    'nbsp' => ' ',
    'aacute' => 'á',
    'eacute' => 'é',
    'iacute' => 'í',
    'oacute' => 'ó',
    'uacute' => 'ú',
    'auml' => 'ä',
    'uuml' => 'ü',
    'Uuml' => 'Ü',
);

# better to use URI::Encode if you have it
sub uri_decode {
    my $name = $_[0];
    foreach my $entity (keys %known_entities) {
        my $to = $known_entities{$entity};
        $name =~ s/&$entity;/$to/g;
    }
    foreach my $entity (map { lc $_ } $name =~ /&([^;]+);/g) {
        if ($entity ne 'amp') {
            die "\nparse_companies.pl: Unable to convert &$entity; giving up\n";
        }
    }
    $name =~ s/&amp;/&/ig;
    $name =~ s/&nbsp;/ /ig;
    return $name;
}

# never parse HTML with regex!
# except when you should

my $identifier;
my $next_is_name = 0;

while (<>) {
    s/\xe2\x80\x8b//g; # kill zero width space

    # grab identifier (in hex)
    if (/\<td.*(0x[0-9A-F]{4})/i) {
        $identifier = $1;
        $next_is_name = 1;

    # next <td> should be company name
    } elsif ($next_is_name && m|\<td.*\>(.*)\<|) {
        my $name = uri_decode($1);
        $name =~ s/^\s+//g; # kill leading
        $name =~ s/\s+$//g; # and trailing space
        $name =~ s/"/\\"/g; # escape double quotes
        my $id = hex($identifier);
        if ($id != 65535) {
            print "\tcase $id:\n";
            print "\t\treturn \"$name\";\n";
        }
        $next_is_name = 0;
    }
}
