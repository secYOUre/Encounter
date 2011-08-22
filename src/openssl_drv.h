#ifndef _ENCOUNTER_CRYPTO_OPENSSL_DRV_H_
#define _ENCOUNTER_CRYPTO_OPENSSL_DRV_H_

#include <unistd.h>
#include <sys/time.h>

#include <openssl/bn.h>

#include "encounter_priv.h"


/* Paillier Public-Key */
struct paillier_publickey {
	BIGNUM	*n; 
	BIGNUM	*g;
	BIGNUM	*nsquared;
};

/* Paillier Private-Key */
struct paillier_privatekey {
	BIGNUM *p, *q, *psquared, *qsquared;
	BIGNUM *pinvmod2tow;
	BIGNUM *qinvmod2tow;
	BIGNUM *hsubp;
	BIGNUM *hsubq;
	BIGNUM *qInv;
};

/* Encounter Key Context */
struct ec_keyctx_s {
	encounter_key_t	type;

	union ec_key_u {
		struct paillier_publickey	paillier_pubK;
		struct paillier_privatekey	paillier_privK;
	}k;
};



/* Encounter cryptographic counter */
struct ec_count_s {
	encounter_count_t version;     /* ECOUNTER_COUNT_PAILLIER_V1 */
	time_t		  lastUpdated; /* UTC time for the last update */

	BIGNUM *c;			/* the crypto counter */
};

#define	OPENSSL_ERROR(l)	do { \
		encounter_set_error(ctx, ENCOUNTER_ERR_CRYPTO, \
			"openssl error: %s", \
			ERR_error_string(ERR_get_error(), NULL)); \
		goto l; \
		} while(0)

/* TODO use __BEGIN_DECLS */

encounter_err_t encounter_crypto_openssl_init(encounter_t *);

encounter_err_t encounter_crypto_openssl_term(encounter_t *);

encounter_err_t encounter_crypto_openssl_keygen(encounter_t *, \
	encounter_key_t, unsigned int, ec_keyctx_t **, ec_keyctx_t **);

encounter_err_t encounter_crypto_openssl_new_counter(encounter_t *, \
			ec_keyctx_t *pubK, ec_count_t **);

encounter_err_t encounter_crypto_openssl_free_counter(encounter_t *, \
			ec_count_t *);

encounter_err_t encounter_crypto_openssl_inc(encounter_t *, \
		ec_count_t *, ec_keyctx_t *, const unsigned int );

encounter_err_t encounter_crypto_openssl_dec(encounter_t *, \
		ec_count_t *, ec_keyctx_t *, const unsigned int );

encounter_err_t encounter_crypto_openssl_touch(encounter_t *, \
				ec_count_t *, ec_keyctx_t *);

encounter_err_t encounter_crypto_openssl_add(encounter_t *, \
		ec_count_t *, ec_count_t *, ec_keyctx_t *);

encounter_err_t encounter_crypto_openssl_mul(encounter_t *, \
		ec_count_t *, ec_keyctx_t *, const unsigned int);

encounter_err_t encounter_crypto_openssl_decrypt(encounter_t *, \
		ec_count_t *, ec_keyctx_t *, unsigned long long int *);

encounter_err_t encounter_crypto_openssl_free_keyctx(encounter_t *, \
						ec_keyctx_t *);

encounter_err_t encounter_crypto_openssl_numToString(encounter_t  *, \
		ec_keyctx_t *, ec_keystring_t **);

encounter_err_t encounter_crypto_openssl_stringToNum(encounter_t  *, \
		ec_keystring_t *, ec_keyctx_t **);

encounter_err_t encounter_crypto_openssl_counterToString(encounter_t *,\
					ec_count_t *, char **);

encounter_err_t encounter_crypto_openssl_counterStrDispose(\
					encounter_t *, char *);

encounter_err_t encounter_crypto_openssl_dispose_keystring(\
				encounter_t *, ec_keystring_t *);

encounter_err_t encounter_crypto_openssl_dispose_counterString(\
					encounter_t *, char *);

encounter_err_t encounter_crypto_openssl_stringToCounter(\
			encounter_t *, const char *, ec_count_t **);

#endif  /* _ENCOUNTER_OPENSSL_DRV_H_ */
