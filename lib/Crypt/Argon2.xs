#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include <argon2.h>

const int output_length = 32;
const int encoded_length = 108;

MODULE = Crypt::Argon2	PACKAGE = Crypt::Argon2

SV*
argon2i_pass(t_cost, m_cost, parallelism, password, salt)
	int t_cost
	int m_cost
	int parallelism
	SV* password
	SV* salt
	PREINIT:
	char *password_raw, *salt_raw;
	STRLEN password_len, salt_len;
	int rc;
	char encoded[encoded_length];
	CODE:
	password_raw = SvPV(password, password_len);
	salt_raw = SvPV(salt, salt_len);
	rc = argon2_hash(t_cost, m_cost, parallelism,
		(char*)password_raw, password_len,
		salt_raw, salt_len,
		NULL, 32,
		encoded, encoded_length,
		Argon2_i, ARGON2_VERSION_NUMBER
	);
	if (rc != ARGON2_OK) {
		SvREFCNT_dec(RETVAL);
		Perl_croak(aTHX_ "Couldn't compute argon2i hash: %s", argon2_error_message(rc));
	}
	RETVAL = newSVpv(encoded, 0);
	OUTPUT:
	RETVAL

SV*
argon2i_raw(t_cost, m_cost, parallelism, password, salt)
	int t_cost
	int m_cost
	int parallelism
	SV* password
	SV* salt
	PREINIT:
	char *password_raw, *salt_raw;
	STRLEN password_len, salt_len;
	int rc;
	char output[output_length];
	CODE:
	password_raw = SvPV(password, password_len);
	salt_raw = SvPV(salt, salt_len);
	rc = argon2_hash(t_cost, m_cost, parallelism,
		(char*)password_raw, password_len,
		salt_raw, salt_len,
		output, output_length,
		NULL, 0,
		Argon2_i, ARGON2_VERSION_NUMBER
	);
	if (rc != ARGON2_OK) {
		SvREFCNT_dec(RETVAL);
		Perl_croak(aTHX_ "Couldn't compute argon2i hash: %s", argon2_error_message(rc));
	}
	RETVAL = newSVpvn(output, 32);
	OUTPUT:
	RETVAL

