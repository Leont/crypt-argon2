#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include <argon2.h>

MODULE = Crypt::Argon2	PACKAGE = Crypt::Argon2

SV*
argon2i_pass(password, salt, t_cost, m_cost, parallelism, output_length)
	int t_cost
	int m_cost
	int parallelism
	SV* password
	SV* salt
	size_t output_length;
	PREINIT:
	char *password_raw, *salt_raw;
	STRLEN password_len, salt_len;
	int rc;
	int encoded_length;
	CODE:
	encoded_length = 65 + ceil(output_length / 3.0) * 4;
	password_raw = SvPV(password, password_len);
	salt_raw = SvPV(salt, salt_len);
	RETVAL = newSVpv("", 0);
	SvGROW(RETVAL, encoded_length);
	rc = argon2_hash(t_cost, m_cost, parallelism,
		(char*)password_raw, password_len,
		salt_raw, salt_len,
		NULL, output_length,
		SvPVX(RETVAL), encoded_length,
		Argon2_i, ARGON2_VERSION_NUMBER
	);
	if (rc != ARGON2_OK) {
		SvREFCNT_dec(RETVAL);
		Perl_croak(aTHX_ "Couldn't compute argon2i hash: %s", argon2_error_message(rc));
	}
	SvCUR(RETVAL) = strlen(SvPV_nolen(RETVAL));
	OUTPUT:
	RETVAL

SV*
argon2i_raw(password, salt, t_cost, m_cost, parallelism, output_length)
	int t_cost
	int m_cost
	int parallelism
	SV* password
	SV* salt
	size_t output_length;
	PREINIT:
	char *password_raw, *salt_raw;
	STRLEN password_len, salt_len;
	int rc;
	CODE:
	password_raw = SvPV(password, password_len);
	salt_raw = SvPV(salt, salt_len);
	RETVAL = newSVpv("", 0);
	SvGROW(RETVAL, output_length);
	rc = argon2_hash(t_cost, m_cost, parallelism,
		(char*)password_raw, password_len,
		salt_raw, salt_len,
		SvPV_nolen(RETVAL), output_length,
		NULL, 0,
		Argon2_i, ARGON2_VERSION_NUMBER
	);
	if (rc != ARGON2_OK) {
		SvREFCNT_dec(RETVAL);
		Perl_croak(aTHX_ "Couldn't compute argon2i hash: %s", argon2_error_message(rc));
	}
	SvCUR(RETVAL) = 32;
	OUTPUT:
	RETVAL

int
argon2i_verify(encoded, password)
	SV* encoded;
	SV* password;
	PREINIT:
	char* password_raw;
	STRLEN password_len;
	int status;
	CODE:
	password_raw = SvPV(password, password_len);
	status = argon2i_verify(SvPV_nolen(encoded), password_raw, password_len);
	RETVAL = status == ARGON2_OK;
	OUTPUT:
	RETVAL
