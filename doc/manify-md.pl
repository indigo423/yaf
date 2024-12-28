#! /usr/bin/perl

##  Copyright 2022-2023 Carnegie Mellon University
##  See license information in LICENSE.txt.

##  This script takes as an argument the Markdown source file used to
##  create the application labeling web page and outputs Markdown
##  designed to be converted to a manual page.
##
##  The script adds NAME and SYNOPSIS sections at the top and SEE ALSO
##  section at the end.

use warnings;
use strict;
use Getopt::Long qw(GetOptions);
use Pod::Usage qw(pod2usage);

our $VERSION = "3.0.0";
our $PKGLIB_DIR = "/usr/local/lib/yaf";
our $SYSCONF_DIR = "/usr/local/etc";

our $KEY;


our $APP = $0;
$APP =~ s,.+/,,;

my ($help, $man);
GetOptions('help|h|?'   => \$help,
           'man'        => \$man,
           'key=s'      => \$KEY,
    )
    or pod2usage(2);

# help?
if ($help) {
    pod2usage(-exitval => 0);
}
if ($man) {
    pod2usage(-exitval => 0, -verbose => 2);
}

my $headfoot = get_header_footer($KEY);


if (!@ARGV && -t STDIN) {
    warn "$APP: No file on command line and stdin is a terminal\n";
    pod2usage(1);
}


print $headfoot->{header};

my $printing;
while (<>) {
    if (!$printing) {
        if (/^#+\s+\S/) {
            $printing = 1;
        }
        next;
    }
    # ignore comments in the input
    next if m,^\[//\]:\s+#\s+\(,;
    # denote all headers
    s/^#/##/;
    print;
}

print $headfoot->{footer};

exit 0;


sub get_header_footer
{
    my ($key) = @_;

    unless (defined $key) {
        die "$APP: The --key switch is required.\n";
    }

    my $orig = $key;
    $key =~ s,.+/,,;
    $key =~ s,^([^\.]+).*,$1,;

    if ($key eq "applabel") {
        my $header = <<HEADER;
% applabel(1)  YAF Application Labeling | YAF ??PACKAGE_VERSION??

# NAME

applabel - YAF Application Labeling

# SYNOPSIS

    yaf ... --applabel --max-payload=PAYLOAD [--dpi-rules-file=FILE]

# DESCRIPTION

HEADER

        my $footer = <<FOOTER;

# FILES

??sysconfdir??/yafDPIRules.conf

:   Default location of the Application Labeling/Deep Packet
    Inspection rules file.

??pkglibdir??

:   Directory from which **yaf** loads Application Labeling/Deep
    Packet Inspection plug-ins.

# SEE ALSO

**yaf(1)**, **yafdpi(1)**, **pcresyntax(3)**, **pcrepattern(3)**,
https://www.lua.org/, https://www.pcre.org/
FOOTER

        return { header => $header, footer => $footer };
    }



    if ($key eq "yafdpi") {
        my $header = <<HEADER;
% yafdpi(1)  YAF Deep Packet Inspection | YAF ??PACKAGE_VERSION??

# NAME

yafdpi - YAF Deep Packet Inspection

# SYNOPSIS

    yaf ... --dpi --max-payload=PAYLOAD [--dpi-rules-file=FILE]
            [--dpi-select=APPLABEL[,APPLABEL...]]

# DESCRIPTION

HEADER

        my $footer = <<FOOTER;

# FILES

??sysconfdir??/yafDPIRules.conf

:   Default location of the Application Labeling/Deep Packet
    Inspection rules file.

??pkglibdir??

:   Directory from which **yaf** loads Application Labeling/Deep
    Packet Inspection plug-ins.

# SEE ALSO

**yaf(1)**, **appabel(1)**, **super_mediator(1)**, **pcresyntax(3)**,
**pcrepattern(3)**,
https://tools.netsa.cert.org/cert-ipfix-registry/index.html,
https://www.lua.org/, https://www.pcre.org/
FOOTER

        return { header => $header, footer => $footer };
    }

    if ($orig eq $key) {
        die "$APP: Unknown key '$key'\n";
    }
    die "$APP: Unknown key '$key' (derived from '$orig')\n";
}


__END__

=pod

=head1 NAME

applabel-md.pl

=head1 SYNOPSIS

 applabel-md.pl --key=KEY INPUT

 applabel-md.pl --help

 applabel-md.pl --man

=head1 OPTIONS

=over 4

=item B<--key>=I<KEY>

The key to determine which header and footer to apply to the
input. Typically this is the name of the ultimate destination file.

=item B<--help>

Prints the short usage information and exits.

=item B<--man>

Prints the complete manual page and exits.

=back

=head1 DESCRIPTION

This script expects a I<FILE> argument which is the Markdown source
file used to create the application labeling web page.  The script
outputs Markdown designed to be converted to a manual page.

The script writes NAME and SYNOPSIS sections at the beginning of the
output and opens a DESCRIPTION section.  The contents of the input are
then inserted, ignoring everything to the first header.  All headers
in the input are demoted by one section.  Finally, the script adds
FILE and SEE ALSO sections at the end.

Use C<-> as the I<FILE> argument to read from the standard input.

=head1 COPYRIGHT

@DISTRIBUTION_STATEMENT_BEGIN@
YAF 3.0.0

Copyright 2023 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
INFRINGEMENT.

Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

GOVERNMENT PURPOSE RIGHTS – Software and Software Documentation
Contract No.: FA8702-15-D-0002
Contractor Name: Carnegie Mellon University
Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213

The Government's rights to use, modify, reproduce, release, perform,
display, or disclose this software are restricted by paragraph (b)(2) of
the Rights in Noncommercial Computer Software and Noncommercial Computer
Software Documentation clause contained in the above identified
contract. No restrictions apply after the expiration date shown
above. Any reproduction of the software or portions thereof marked with
this legend must also reproduce the markings.

This Software includes and/or makes use of Third-Party Software each
subject to its own license.

DM23-2317
@DISTRIBUTION_STATEMENT_END@

=cut
