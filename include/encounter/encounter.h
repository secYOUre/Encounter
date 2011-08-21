#ifndef _ENCOUNTER_H_
#define _ENCOUNTER_H_

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

struct encounter_s;   /* Forward decl. */
struct ec_keyctx_s;
struct ec_count_s;
struct ec_keyset_s;


/* These are defined only in encounter.h, and are used for conditional
 * compiles. */
#define	ENCOUNTER_LIB_VER_MAJOR	0
#define ENCOUNTER_LIB_VER_MINOR	1
#define ENCOUNTER_LIB_VER_PATCH	0

/* xxyyzz, where x=major, y=minor, z=patch */
#define	ENCOUNTER_LIB_VERSION	"0.1.0"



/**
 *  \addtogroup encounter
 *  \{
 */

/*
 * Maximum length of various identifiers.
 */ 
#ifndef ENCOUNTER_FILENAME_MAX
  /** Maximum length of the CA filename string. */
  #define ENCOUNTER_FILENAME_MAX	(FILENAME_MAX + 1)
#endif  /* !ENCOUNTER_CAFILE_MAX */

/* Other identifiers to be defined */


/* Error codes. */
typedef enum
{
    ENCOUNTER_OK = 0,
    /**< As expected. */

    ENCOUNTER_ERR_MEM,
    /**< Memory exhaustion. */

    ENCOUNTER_ERR_CRYPTO,
    /**< Error is coming from the crypto toolkit.  */

    ENCOUNTER_ERR_STORE,
    /**< Error is coming from the storage layer.  */

    ENCOUNTER_ERR_PARAM,
    /**< Error is coming from a supplied parameter.  */

    ENCOUNTER_ERR_OS,
    /**< Some syscall has failed (see ::encounter_err() for details.) */

    ENCOUNTER_ERR_DATA,
    /**< Corrupted or unavailable data */

    ENCOUNTER_ERR_IMPL,
    /**< Hit an implementation limit. */

} encounter_err_t;


/** Encounter runtime context.  */
typedef struct encounter_s encounter_t;

/** Encounter key context */
typedef struct ec_keyctx_s ec_keyctx_t;

/** Encounter cryptographic counter */
typedef struct ec_count_s ec_count_t;

/** Encounter keyset */
typedef struct ec_keyset_s ec_keyset_t;


/** Encounter Key Types */
typedef enum {
	EC_KEYTYPE_NONE,		/* No key-type code */
        EC_KEYTYPE_PAILLIER_PUBLIC,	/* Paillier public-key */
        EC_KEYTYPE_PAILLIER_PRIVATE,	/* Paillier private-key */
	EC_KEYTYPE_LAST			/* Last possible key-type code */
} encounter_key_t;


/** Encounter Keyset Types */
typedef enum {
	EC_KEYSET_NONE,			/* No keyset code  */
	EC_KEYSET_PLAIN,		/* Plaintext keyset */
	EC_KEYSET_SOFTTOKEN,		/* ASN.1 softtoken */
	EC_KEYSET_LAST			/* Last possible keyset code */
} encounter_keyset_t;


/** Create and configure a new Encounter context. 
  * This will need to be supplied as the first parameter of each
  * Encounter API */
encounter_err_t encounter_init (const unsigned int, encounter_t **);

/** Return last errno */
encounter_err_t encounter_error (encounter_t *);

/** Generate a keypair according to the scheme and size selected 
 * respectively by the second and third parametes */
encounter_err_t encounter_keygen(encounter_t *, encounter_key_t, \
			unsigned int, ec_keyctx_t **, ec_keyctx_t **);

/** Accepts a key context and returns a new cryptographic counter handle */
encounter_err_t encounter_new_counter(encounter_t *, ec_keyctx_t *, \
							ec_count_t **);

/** Dispose the cryptographic counter referenced by the 2nd parameter */
encounter_err_t encounter_dispose_counter(encounter_t *, ec_count_t *);

/** Increment the cryptographic counter by the amount in a,
  * without first decrypting it. */
encounter_err_t encounter_inc(encounter_t *, ec_keyctx_t *, \
					ec_count_t *, const int);

/** Touch the crypto counter by probabilistically re-rencrypting it.
  * The plaintext counter is not affected */
encounter_err_t encounter_touch(encounter_t *, ec_keyctx_t *, ec_count_t *);

/** Decrypt the cryptographic counter, returning the plaintext 
  * Accepts the handles of the cryptographic counter and private key */
encounter_err_t encounter_decrypt(encounter_t *, ec_count_t *, \
				ec_keyctx_t *, unsigned long long int *);

/** Dispose the cryptographic counter referenced by the handle */
encounter_err_t encounter_dispose_keyctx(encounter_t *, ec_keyctx_t *);


/** Add a public key to keyset */
encounter_err_t encounter_add_publicKey(encounter_t *, ec_keyctx_t *, \
							ec_keyset_t *);

/** Add a private key to keyset */
encounter_err_t encounter_add_privateKey(encounter_t *, ec_keyctx_t *, \
					ec_keyset_t *, const char *);

/** Get a public key from a keyset */
encounter_err_t	encounter_get_publicKey(encounter_t *, \
			ec_keyset_t *, ec_keyctx_t **);

/** Get a private key from a keyset */
encounter_err_t	encounter_get_privateKey(encounter_t *, \
			ec_keyset_t *, const char *, ec_keyctx_t **);

/** Persist a cryptographic counter to a file */
encounter_err_t encounter_persist_counter(encounter_t *, ec_count_t *, \
					const char *);

/** Get a cryptographic counter from a file */
encounter_err_t encounter_get_counter(encounter_t *, const char *, \
				ec_count_t **);

/** Create a keyset handle */
encounter_err_t encounter_create_keyset(encounter_t *,\
       encounter_keyset_t,  const char *, const char *, ec_keyset_t **);

/** Dispose a keyset handle */
encounter_err_t encounter_dispose_keyset(encounter_t *, ec_keyset_t *);

/** Dispose the supplied Encounter context. */
void encounter_term (encounter_t *ctx);

/**
 *  \}
 */ 

#ifdef __cplusplus
}
#endif

#endif  /* !_ENCOUNTER_H_ */
