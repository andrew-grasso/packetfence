package captiveportal::PacketFence::View::JSON;

use strict;
use warnings;
use Moose;

extends 'Catalyst::View::JSON';

__PACKAGE__->config(
    {
        allow_callback  => 0,
        callback_param  => 'callback',
        expose_stash    => 'json_content',
        json_encoder_args => +{ allow_blessed => 1, convert_blessed => 1},
    },
);

=head1 NAME

captiveportal::View::HTML - JSON View for captiveportal

=head1 DESCRIPTION

JSON View for captiveportal.

=head1 SEE ALSO

L<captiveportal>

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2022 Inverse inc.

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

1;
