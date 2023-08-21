#!/usr/bin/perl

=head1 NAME

pfqueue_check -

=head1 DESCRIPTION

pfqueue_check

=cut

use strict;
use warnings;
use lib qw(/usr/local/pf/lib);
use lib qw(/usr/local/pf/lib_perl/lib/perl5);
use pf::file_paths qw($var_dir);
my $pfqueue_id = do {
    open(my $fh, "$var_dir/run/pfqueue.pid") or exit 0;
    my $f = '';
    {
        local $/ = undef;
        $f = <$fh>;
    }
    chomp($f);
    $f
};

unless ($pfqueue_id) {
    print "Cannot get the pfqueue pid\n";
    exit 0;
}

my $pfqueue_kids = qx/ps --no-headers --ppid ${pfqueue_id} -o pid,pcpu,etimes/;
my @kids = split(/\n/, $pfqueue_kids);
my @pids;
for my $kid (@kids) {
    $kid =~ s/^ *//;
    $kid =~ s/ *$//;
    next if $kid eq '';
    my ($pid, $cpu, $etimes) = split(/ +/, $kid);
    if (defined $etimes && $etimes > 60 && $cpu == 0) {
        push @pids, $pid;
    }
}

unless (@pids) {
    exit 0;
}

my %pids = map { $_ => 1 } @pids;
my $start = time();
while (keys %pids) {
    my $pid_list = join(",", keys %pids);
    my $info_list = qx/ps --no-headers --pid ${pid_list} -o pid,pcpu/;
    $info_list =~ s/^ *//mg;
    $info_list =~ s/ *$//mg;
    next if $info_list eq '';
    for my $info (split(/\n/, $info_list)) {
        my ($pid, $cpu) = split(/ +/, $info);
        if ($cpu != 0) {
            delete $pids{$pid};
        }
    }
} continue {
    last if (time() - $start) >= 2;
}

@pids = keys %pids;
if (@pids) {
    print STDERR "pfqueue children are stuck ", join(" ", @pids), "\n";
    exit 1;

}

=end

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2023 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut

