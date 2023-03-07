#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include <argon2.h>
#include "encoding.h"

static size_t S_parse_size(pTHX_ SV* value, int type) {
	STRLEN len;
	const char* string = SvPVbyte(value, len);
	char* end = NULL;
	int base = strtoul(string, &end, 0);
	if (end == string)
		Perl_croak(aTHX_ "Couldn't compute %s tag: memory cost doesn't contain anything numeric", argon2_type2string(type, 0));
	switch(*end) {
		case '\0':
			if (base > 1024)
				return base / 1024;
			else
				Perl_croak(aTHX_ "Couldn't compute %s tag: Memory size much be at least a kilobyte", argon2_type2string(type, 0));
		case 'k':
			return base;
		case 'M':
			return base * 1024;
		case 'G':
			return base * 1024 * 1024;
		default:
			Perl_croak(aTHX_ "Couldn't compute %s tag: Can't parse '%c' as an order of magnitude", argon2_type2string(type, 0), *end);
	}
}
#define parse_size(value, type) S_parse_size(aTHX_ value, type)

#define undef &PL_sv_undef

MODULE = Crypt::Argon2	PACKAGE = Crypt::Argon2

SV* argon2d_pass(SV* password, SV* salt, int t_cost, SV* m_factor, int parallelism, size_t output_length, SV* additional = undef)
	ALIAS:
	argon2d_pass = Argon2_d
	argon2i_pass = Argon2_i
	argon2id_pass = Argon2_id
	PREINIT:
	char *password_raw, *salt_raw, *additional_raw, *output;
	STRLEN password_len, salt_len, additional_len = 0;
	int rc, encoded_length, m_cost;
	CODE:
	m_cost = parse_size(m_factor, ix);
	password_raw = SvPVbyte(password, password_len);
	salt_raw = SvPVbyte(salt, salt_len);
	additional_raw = SvOK(additional) ? SvPVbyte(additional, additional_len) : NULL;
	encoded_length = argon2_encodedlen(t_cost, m_cost, parallelism, salt_len, output_length, ix);
	RETVAL = newSV(encoded_length - 1);
	SvPOK_only(RETVAL);
	Newx(output, output_length, char);
	SAVEFREEPV(output);
	argon2_context context = {
		output, output_length,
		password_raw, password_len,
		salt_raw, salt_len,
		NULL, 0,
		additional_raw, additional_len,
		t_cost, m_cost, parallelism, parallelism,
		ARGON2_VERSION_NUMBER,
		NULL, NULL,
		ARGON2_DEFAULT_FLAGS
	};

	rc = argon2_ctx(&context, ix);

	if (rc != ARGON2_OK) {
		SvREFCNT_dec(RETVAL);
		Perl_croak(aTHX_ "Couldn't compute %s tag: %s", argon2_type2string(ix, FALSE), argon2_error_message(rc));
	}

	if (encode_string(SvPVX(RETVAL), encoded_length, &context, ix) != ARGON2_OK) {
		SvREFCNT_dec(RETVAL);
		Perl_croak(aTHX_ "Couldn't encode %s hash: %s", argon2_type2string(ix, FALSE), argon2_error_message(rc));
	}

	SvCUR(RETVAL) = encoded_length - 1;
	OUTPUT:
	RETVAL

SV* argon2d_raw(SV* password, SV* salt, int t_cost, SV* m_factor, int parallelism, size_t output_length, SV* additional = undef)
	ALIAS:
	argon2d_raw = Argon2_d
	argon2i_raw = Argon2_i
	argon2id_raw = Argon2_id
	PREINIT:
	char *password_raw, *salt_raw, *additional_raw;
	STRLEN password_len, salt_len, additional_len = 0;
	int rc, m_cost;
	CODE:
	m_cost = parse_size(m_factor, ix);
	password_raw = SvPVbyte(password, password_len);
	salt_raw = SvPVbyte(salt, salt_len);
	additional_raw = SvOK(additional) ? SvPVbyte(additional, additional_len) : NULL;
	RETVAL = newSV(output_length);
	SvPOK_only(RETVAL);
	argon2_context context = {
		SvPVX(RETVAL), output_length,
		password_raw, password_len,
		salt_raw, salt_len,
		NULL, 0,
		additional_raw, additional_len,
		t_cost, m_cost, parallelism, parallelism,
		ARGON2_VERSION_NUMBER,
		NULL, NULL,
		ARGON2_DEFAULT_FLAGS
	};

	rc = argon2_ctx(&context, ix);

	if (rc != ARGON2_OK) {
		SvREFCNT_dec(RETVAL);
		Perl_croak(aTHX_ "Couldn't compute %s tag: %s", argon2_type2string(ix, FALSE), argon2_error_message(rc));
	}
	SvCUR(RETVAL) = output_length;
	OUTPUT:
	RETVAL

SV* argon2d_verify(SV* encoded, SV* password)
	ALIAS:
	argon2d_verify = Argon2_d
	argon2i_verify = Argon2_i
	argon2id_verify = Argon2_id
	PREINIT:
	char *password_raw, *encoded_raw;
	STRLEN password_len, encoded_len;
	int status;
	CODE:
	password_raw = SvPVbyte(password, password_len);
	encoded_raw = SvPVbyte(encoded, encoded_len);

    argon2_context ctx = {
		NULL, encoded_len,
		password_raw, password_len,
		NULL, encoded_len,
		NULL, 0,
		NULL, encoded_len,
		0, 0, 0, 0,
		ARGON2_VERSION_NUMBER,
		NULL, NULL,
		ARGON2_DEFAULT_FLAGS
	};
	Newx(ctx.out, encoded_len, char);
	SAVEFREEPV(ctx.out);
	Newx(ctx.salt, encoded_len, char);
	SAVEFREEPV(ctx.salt);
	Newx(ctx.ad, encoded_len, char);
	SAVEFREEPV(ctx.ad);

	status = decode_string(&ctx, encoded_raw, ix);

	if (status == ARGON2_OK) {
		char* desired_result = ctx.out;

		Newx(ctx.out, ctx.outlen, char);
		SAVEFREEPV(ctx.out);

		status = argon2_verify_ctx(&ctx, (char *)desired_result, ix);
	}

	switch(status) {
		case ARGON2_OK:
			RETVAL = &PL_sv_yes;
			break;
		case ARGON2_VERIFY_MISMATCH:
			RETVAL = &PL_sv_no;
			break;
		default:
			Perl_croak(aTHX_ "Could not verify %s tag: %s", argon2_type2string(ix, FALSE), argon2_error_message(status));
	}
	OUTPUT:
	RETVAL
