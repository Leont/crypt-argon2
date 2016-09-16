package Crypt::Argon2;

use strict;
use warnings;

use Exporter 5.57 'import';
our @EXPORT_OK = qw/argon2i_raw argon2i_pass argon2i_verify argon2d_raw/;
use XSLoader;
XSLoader::load(__PACKAGE__, __PACKAGE__->VERSION || 0);

1;

# ABSTRACT: Perl interface to the Argon2 key derivation functions

=head1 SYNOPSIS

 use Crypt::Argon2 qw/argon2i_pass argon2i_verify/;

 sub add_pass {
   my ($user, $password) = @_;
   my $salt = get_random(16);
   my $encoded = argon2i_pass($password, $salt, 3, 12, 1, 16):
   store_password($user, $encoded);
 }

 sub check_password {
   my ($user, $password) = @_;
   my $encoded = fetch_encoded($user);
   return argon2i_verify($encoded, $password);
 }

=head1 DESCRIPTION

This module implements the Argon2 key derivation function, which is suitable to convert any password into a cryptographic key. This is most often used to for secure storage of passwords but can also be used to derive a encryption key from a password. It offers variable time and memory costs as well as output size.

=head1 RECOMMENDED SETTINGS

The L<Argon2 paper|https://password-hashing.net/argon2-specs.pdf> recommends the following procedure to find settings.

=over 4

=item 1. Select the type C<y>. If you do not know the difference between them or you consider side-channel attacks as viable threat, choose Argon2i.

=item 2. Figure out the maximum number of threads C<h> that can be initiated by each call to Argon2. This is the C<parallelism> argument.

=item 3. Figure out the maximum amount of memory  C<m> that each call can a afford.

=item 4. Figure out the maximum amount C<x> of time (in seconds) that each call can a afford.

=item 5. Select the salt length. 16 bytes is suffient for all applications, but can be reduced to 8 bytes in the case of space constraints.

=item 6. Select the tag (output) size. 16 bytes is suffient for most applications, including key derivation.

=item 7. Run the scheme of type C<y>, memory C<m> and C<h> lanes and threads, using different number of passes C<t>. Figure out the maximum C<t> such that the running time does not exceed C<x>. If it exceeds C<x> even for C<t = 1>, reduce C<m> accordingly.

=item 8. Hash all the passwords with the just determined values C<m>, C<h>, and C<t>.

=back

=func argon2i_pass($password, $salt, $t_cost, $m_factor, $parallelism, $tag_size)

This function processes the C<$password> with the given C<$salt> and parameters. It encodes the resulting tag and the parameters as a password string (e.g. C<$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA>).

=over 4

=item * C<$password>

This is the password that is to be turned into a cryptographic key.

=item * C<$salt>

This is the salt that is used. It must be long enough to be unique.

=item * C<$t_cost>

This is the time-cost factor, typically a small integer that can be derived as explained above.

=item * C<$m_factor>

This is the memory costs factor. It is given as a logarithm of the memory size in kiB, so a value of 12 means 4MiB.

=item * C<$parallelism>

This is the number of threads that are used in computing it.

=item * C<$tag_size>

This is the size of the raw result in bytes. Typical values are 16 or 32.

=back

=func argon2i_verify($encoded, $password)

This verifies that the C<$password> matches C<$encoded>. All parameters and the tag value are extracted from C<$encoded>, so no further arguments are necessary.

=func argon2i_raw($password, $salt, $t_cost, $m_factor, $parallelism, $tag_size)

This function processes the C<$password> with the given C<$salt> and parameters much like C<argon2i_pass>, but returns the binary tag instead of a formatted string.

=func argon2d_raw($password, $salt, $t_cost, $m_factor, $parallelism, $tag_size)

This function processes the C<$password> with the given C<$salt> and parameters much like C<argon2i_pass>, but returns a binary tag for argon2d instead of a formatted string for argon2i.

=head2 ACKNOWLEDGEMENTS

This module is based on the reference implementation as can be found at L<https://github.com/P-H-C/phc-winner-argon2>.

=head2 SEE ALSO

You will also need a good source of randomness to generate good salts. Some possible solutions include:

=over 4

=item * L<Bytes::Random::Secure|Bytes::Random::Secure>

=item * L<Crypt::URandom|Crypt::URandom>

=back

Implementations of other similar algorithms include:

=over 4

=item * L<Crypt::ScryptKDF|Crypt::ScryptKDF>

=item * L<Crypt::Eksblowfish::Bcrypt|Crypt::Eksblowfish::Bcrypt>

=back

=cut
