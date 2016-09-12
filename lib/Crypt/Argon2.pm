package Crypt::Argon2;

use strict;
use warnings;

use Exporter 5.57 'import';
our @EXPORT_OK = qw/argon2i_raw argon2i_pass argon2i_hex argon2i_b64 argon2i_verify/;
use XSLoader;
XSLoader::load(__PACKAGE__, __PACKAGE__->VERSION || 0);

sub argon2i_hex {
	return unpack "H*", argon2i_raw(@_);
}
sub argon2i_b64 {
	return encode_base64(argon2i_raw(@_), '');
}

1;

# ABSTRACT: Perl interface to the Argon2 key derivation functions
