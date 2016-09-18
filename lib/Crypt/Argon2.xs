#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include <argon2.h>

MODULE = Crypt::Argon2	PACKAGE = Crypt::Argon2

SV*
argon2i_pass(password, salt, t_cost, m_factor, parallelism, output_length)
	int t_cost
	int m_factor
	int parallelism
	SV* password
	SV* salt
	size_t output_length;
	PREINIT:
	char *password_raw, *salt_raw;
	STRLEN password_len, salt_len;
	int rc;
	int encoded_length;
	int m_cost;
	CODE:
	m_cost = 1 << m_factor;
	password_raw = SvPV(password, password_len);
	salt_raw = SvPV(salt, salt_len);
	encoded_length = argon2_encodedlen(t_cost, m_cost, parallelism, salt_len, output_length);
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
argon2i_raw(password, salt, t_cost, m_factor, parallelism, output_length)
	int t_cost
	int m_factor
	int parallelism
	SV* password
	SV* salt
	size_t output_length;
	PREINIT:
	char *password_raw, *salt_raw;
	STRLEN password_len, salt_len;
	int rc;
	int m_cost;
	CODE:
	m_cost = 1 << m_factor;
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


SV*
argon2d_raw(password, salt, t_cost, m_factor, parallelism, output_length)
	int t_cost
	int m_factor
	int parallelism
	SV* password
	SV* salt
	size_t output_length;
	PREINIT:
	char *password_raw, *salt_raw;
	STRLEN password_len, salt_len;
	int rc;
	int m_cost;
	CODE:
	m_cost = 1 << m_factor;
	password_raw = SvPV(password, password_len);
	salt_raw = SvPV(salt, salt_len);
	RETVAL = newSVpv("", 0);
	SvGROW(RETVAL, output_length);
	rc = argon2_hash(t_cost, m_cost, parallelism,
		(char*)password_raw, password_len,
		salt_raw, salt_len,
		SvPV_nolen(RETVAL), output_length,
		NULL, 0,
		Argon2_d, ARGON2_VERSION_NUMBER
	);
	if (rc != ARGON2_OK) {
		SvREFCNT_dec(RETVAL);
		Perl_croak(aTHX_ "Couldn't compute argon2d hash: %s", argon2_error_message(rc));
	}
	SvCUR(RETVAL) = 32;
	OUTPUT:
	RETVAL

