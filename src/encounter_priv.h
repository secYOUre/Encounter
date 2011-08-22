#ifndef _ENCOUNTER_PRIV_H_
#define _ENCOUNTER_PRIV_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>

#include <openssl/bn.h>

#include "encounter.h"


/* encounter runtime context */
struct encounter_s
{
	uint32_t	version;     /* Runtime context version number */
	uint32_t	maxcounters; /* Maximum concurrent counters
	                              * for future use */

	/* Last seen error and corresponding human readable message. */
	encounter_err_t rc;
	char estr[256];

#ifdef USE_OPENSSL
	BIGNUM *m;
#endif
};

/* Cryptographic counter scheme enum */
typedef enum {
	ENCOUNTER_COUNT_NONE,
	/* Paillier cryptographic counter */
	ENCOUNTER_COUNT_PAILLIER_V1,
	ENCOUNTER_COUNT_LAST

} encounter_count_t;



/** Crypotgraphic credentials string representation */

/* Paillier Public-Key */
struct paillier_publickey_str {
        char  *n;		/* modulus */
        char  *g;		/* generator */
        char  *nsquared;	/* modulus squared */
};

/* Paillier Private-Key */
struct paillier_privatekey_str {
        char *p, *q, *psquared, *qsquared;	/* primes and their squares */
        char *pinvmod2tow;			/* p^-1 mod 2^w */
        char *qinvmod2tow;			/* q^-1 mod 2^w */
        char *hsubp;				/* h_p */
        char *hsubq;				/* h_q */
        char *qInv;				/* q^-1 */
};

/* Encounter Key Context */
struct ec_keystring_s {
        encounter_key_t type;	

        union ec_key_str_u {
                struct paillier_publickey_str      paillier_pubK;
                struct paillier_privatekey_str     paillier_privK;
        }k;
};

typedef struct ec_keystring_s ec_keystring_t;

/** Keyset struct */
struct ec_keyset_s {
	encounter_keyset_t	type;

	union ec_keyset_u {
		const char	*path;		/* Pathname */
	}s;	
};


#ifdef USE_OPENSSL
# include "openssl_drv.h"
#endif

#ifdef USE_PLAINSTORE
# include "plainstore_drv.h"
#endif

#include "keyset.h"


/** Encounter limits and constants */
#define ENCOUNTER_KEYSIZE_MIN			1024
#define ENCOUNTER_CONCURRENT_COUNTERS_MAX	UINTMAX_MAX


static struct
{
	/* Crypto toolkit */
        encounter_err_t (*init_crypto)(encounter_t *ctx);

	encounter_err_t (*keygen)     (encounter_t *ctx, \
	     encounter_key_t type, unsigned int keysize, \
	     ec_keyctx_t **pubK, ec_keyctx_t **privK);

	encounter_err_t (*new_counter)(encounter_t *ctx, \
	     ec_keyctx_t *keyctx, ec_count_t **encount);

	encounter_err_t (*dispose_counter)(encounter_t *ctx, \
				ec_count_t *encount);

	encounter_err_t (*inc)        (encounter_t *ctx, \
	     ec_count_t *encount, ec_keyctx_t *keyctx, const int);

	encounter_err_t (*touch)      (encounter_t *ctx, \
	     ec_count_t *encount, ec_keyctx_t *keyctx);

	encounter_err_t (*add)      (encounter_t *ctx, \
	     ec_count_t *encountA, ec_count_t *encountB, \
				   ec_keyctx_t *keyctx);

	encounter_err_t	(*decrypt)    (encounter_t *ctx, \
	     ec_count_t *encount, ec_keyctx_t *keyctx, unsigned int *c);

	encounter_err_t (*dispose_key)(encounter_t *ctx, \
				ec_keyctx_t *keyctx);

	encounter_err_t (*dispose_keystring)(encounter_t *ctx, \
				ec_keystring_t *key);

	encounter_err_t (*term_crypto)(encounter_t *ctx);

	encounter_err_t (*numToString)(encounter_t *ctx, \
	     ec_keyctx_t *keyctx, ec_keystring_t **key);

	encounter_err_t (*stringToNum)(encounter_t *ctx, \
	     ec_keystring_t *key, ec_keyctx_t **keyctx);

	encounter_err_t (*counterToString)(encounter_t *ctx, \
		ec_count_t *encount, char **counter);

	encounter_err_t (*dispose_counterString)(encounter_t *ctx, \
				char *counter);

	encounter_err_t (*stringToCounter)(encounter_t *ctx, \
			const char *counter, ec_count_t **encount);


	/* Keystore mechanism */
	encounter_err_t (*init_store) (encounter_t *ctx);

	encounter_err_t (*store_key)  (encounter_t *ctx, \
		ec_keyctx_t *keyctx, const char *keyfile);

        encounter_err_t (*load_pubK)  (encounter_t *ctx, \
		const char *pubkey, ec_keyctx_t **keyctx);

	encounter_err_t (*load_privK) (encounter_t *ctx, 
	  const char *privkey, const char *passphrase, \
				  ec_keyctx_t **keyctx);

	encounter_err_t (*persist_cnt)(encounter_t *ctx, \
			ec_count_t *encount, const char *path);
	
	encounter_err_t (*get_counter)(encounter_t *ctx, \
			const char *path, ec_count_t **encount);

	encounter_err_t (*term_store) (encounter_t *ctx);


	encounter_err_t (*create_keyset)(encounter_t *ctx, \
		encounter_keyset_t type, const char *path, \
		const char *passphrase, ec_keyset_t **keyset);

	encounter_err_t (*dispose_keyset)(encounter_t *ctx, \
					ec_keyset_t *keyset);
	/* Threading mechanism */
	/* TODO */

} D = {
#ifdef USE_OPENSSL
        encounter_crypto_openssl_init,
        encounter_crypto_openssl_keygen,
	encounter_crypto_openssl_new_counter,
	encounter_crypto_openssl_free_counter,
	encounter_crypto_openssl_inc,
	encounter_crypto_openssl_touch,
	encounter_crypto_openssl_add,
	encounter_crypto_openssl_decrypt,
	encounter_crypto_openssl_free_keyctx,
	encounter_crypto_openssl_dispose_keystring,
	encounter_crypto_openssl_term,
	encounter_crypto_openssl_numToString,
	encounter_crypto_openssl_stringToNum,
	encounter_crypto_openssl_counterToString,
	encounter_crypto_openssl_dispose_counterString,
	encounter_crypto_openssl_stringToCounter,
#else
# error "OpenSSL is the only supported crypto toolkit, so far"
#endif

#ifdef USE_PLAINSTORE
	encounter_plain_init_store,
	encounter_plain_storekey,
	encounter_plain_loadPublicKey,
	encounter_plain_loadPrivKey,
	encounter_plain_persist_cnt,
	encounter_plain_get_counter,
	encounter_plain_term_store,
#else
# error "To date, the only supported keystore is 'plain'"
#endif 

	encounter_keyset_create,
	encounter_keyset_dispose
};


/* Macros */
/* Sanity checkes */
#define __ENCOUNTER_SANITYCHECK_STR(s, l, m, e)	\
			do { if (!(s) || ((l) > (m))) return (e); } while(0)

#define __ENCOUNTER_SANITYCHECK_MEM(s, e)	\
			do { if (!(s) ) \
			     return (e); } while(0)

#define __ENCOUNTER_SANITYCHECK_KEYTYPE(type, e) \
			do { if (((type) <= EC_KEYTYPE_NONE)  \
			     ||  ((type) >= EC_KEYTYPE_LAST)) \
					return (e); } while(0)

#define __ENCOUNTER_SANITYCHECK_KEYSET_TYPE(type, e) \
			do { if (((type) <= EC_KEYSET_NONE)  \
			     ||  ((type) >= EC_KEYSET_LAST)) \
					return (e); } while(0)

#define __ENCOUNTER_SANITYCHECK_KEYSIZE(size, e) \
			do { if ((size) < (ENCOUNTER_KEYSIZE_MIN)) \
					return(e); } while(0)

#endif /* !_ENCOUNTER_PRIV_H_ */
