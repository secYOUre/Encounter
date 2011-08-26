#define	_GNU_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "encounter_priv.h"
#include "utils.h"

encounter_err_t encounter_init(const unsigned int maxc, encounter_t **ctx)
{
	encounter_err_t rc;
	encounter_t *c = NULL;

	/* Sanity check the supplied paramters */
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	if (maxc > ENCOUNTER_CONCURRENT_COUNTERS_MAX) 
			return (ENCOUNTER_ERR_PARAM);


	/* Make room for the context */
	if ((c = calloc(1, sizeof *c)) == NULL)
		return ENCOUNTER_ERR_MEM;

	/* Dup the parameters */
	c->version = ((ENCOUNTER_LIB_VER_MAJOR)<<16) \
                   + ((ENCOUNTER_LIB_VER_MINOR)<<8)  \
                   + (ENCOUNTER_LIB_VER_PATCH);
	c->maxcounters = maxc;

	/* Initialize the crypto toolkit */
	if (D.init_crypto(c) != ENCOUNTER_OK) {
		rc = ENCOUNTER_ERR_CRYPTO;
		goto err;
	}

	/* Initialize the messaging lib */
	if (D.init_store(c) != ENCOUNTER_OK) {
		rc = ENCOUNTER_ERR_STORE;
		goto err;
	}
	
	/* Okay, it worked. Setup error reporting. */
	c->rc = ENCOUNTER_OK;
	c->estr[0] = '\0';

	/* Copy out the pointer to the context */
	*ctx = c;

	/* We are done. */
	return c->rc;

err:
 	if  (c) {
		free(c);
	}
	*ctx = NULL;
	return  rc;
}

encounter_err_t encounter_error(encounter_t *ctx)
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);

	return (ctx->rc);
}

/** Generate a keypair according to the scheme and size selected
 * respectively by the second and third parametes */
encounter_err_t encounter_keygen(encounter_t *ctx, \
		encounter_key_t type, unsigned int size, \
		ec_keyctx_t **pubK, ec_keyctx_t **privK) 
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_KEYTYPE(type, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_KEYSIZE(size, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(pubK, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(privK, ENCOUNTER_ERR_PARAM);

	return D.keygen(ctx, type, size, pubK, privK);
}

/** Accepts a key context and returns a new cryptographic counter handle */
encounter_err_t encounter_new_counter(encounter_t *ctx, \
			ec_keyctx_t *pubK, ec_count_t **encount)
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(pubK, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(encount, ENCOUNTER_ERR_PARAM);

	return D.new_counter(ctx, pubK, encount);

}

/** Dispose the cryptographic counter referenced by the 2nd parameter */
encounter_err_t encounter_dispose_counter(encounter_t *ctx, \
						ec_count_t *encount)
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(encount, ENCOUNTER_ERR_PARAM);

	return D.dispose_counter(ctx, encount);
}

/** Increment the cryptographic counter by the amount in a,
  * without first decrypting it. */
encounter_err_t encounter_inc(encounter_t *ctx, ec_keyctx_t *pubK, \
			ec_count_t *encount,  const unsigned int a) 
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(encount, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(pubK, ENCOUNTER_ERR_PARAM);

	return D.inc(ctx, encount, pubK, a);
}

/** Decrement the cryptographic counter by the amount in a,
  * without first decrypting it. */
encounter_err_t encounter_dec(encounter_t *ctx, ec_keyctx_t *pubK, \
			ec_count_t *encount,  const unsigned int a) 
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(encount, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(pubK, ENCOUNTER_ERR_PARAM);

	return D.dec(ctx, encount, pubK, a);
}

/** Touch the crypto counter by probabilistically re-rencrypting it.
  * The plaintext counter is not affected */
encounter_err_t encounter_touch(encounter_t *ctx, ec_keyctx_t *pubK, \
						ec_count_t *encount)
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(pubK, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(encount, ENCOUNTER_ERR_PARAM);

	return D.touch(ctx, encount, pubK);
}

/** Adds two cryptographic counters placing the result in the first one
  * without first decrypting it. */
encounter_err_t encounter_add(encounter_t *ctx, ec_keyctx_t *pubK, \
			ec_count_t *encountA,  ec_count_t *encountB) 
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(pubK, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(encountA, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(encountB, ENCOUNTER_ERR_PARAM);

	return D.add(ctx, encountA, encountB, pubK );
}

/** Multiply a cryptographic counter by the quantity given in a
  * without first decrypting it. */
encounter_err_t encounter_mul(encounter_t *ctx, ec_keyctx_t *pubK, \
			ec_count_t *encount,  const unsigned int a) 
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(pubK, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(encount, ENCOUNTER_ERR_PARAM);

	return D.mul(ctx, encount, pubK, a);
}

/** Decrypt the cryptographic counter, returning the plaintext
  * Accepts the handles of the cryptographic counter and private key */
encounter_err_t encounter_decrypt(encounter_t *ctx, \
    ec_count_t *encount, ec_keyctx_t *privK, unsigned long long int *c)
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(encount, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(privK, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(c, ENCOUNTER_ERR_PARAM);

	return	D.decrypt(ctx, encount, privK, c);
}

/** Dispose the cryptographic counter referenced by the handle */
encounter_err_t encounter_dispose_keyctx(encounter_t *ctx, \
						ec_keyctx_t *keyctx)
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(keyctx, ENCOUNTER_ERR_PARAM);

	return D.dispose_key(ctx, keyctx);
}

/** Add a public key to keyset */
encounter_err_t encounter_add_publicKey(encounter_t *ctx,\
			 ec_keyctx_t *pubK, ec_keyset_t *keyset)
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(pubK, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(keyset, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_KEYSET_TYPE(keyset->type, ENCOUNTER_ERR_PARAM);

	return D.store_key(ctx, pubK, keyset->s.path);
}

/** Add a private key to keyset */
encounter_err_t encounter_add_privateKey(encounter_t *ctx, \
   ec_keyctx_t *privK, ec_keyset_t *keyset, const char *passphrase)
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(privK, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(keyset, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_KEYSET_TYPE(keyset->type, ENCOUNTER_ERR_PARAM);

	return D.store_key(ctx, privK, keyset->s.path);
}

/** Get a public key from a keyset */
encounter_err_t encounter_get_publicKey(encounter_t *ctx, \
  		ec_keyset_t *keyset, ec_keyctx_t **keyctx) 
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(keyctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(keyset, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_KEYSET_TYPE(keyset->type, ENCOUNTER_ERR_PARAM);

	return D.load_pubK(ctx, keyset->s.path, keyctx);
}

/** Get a private key from a keyset */
encounter_err_t encounter_get_privateKey(encounter_t *ctx, \
  ec_keyset_t *keyset, const char *passphrase, ec_keyctx_t **keyctx)
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(keyctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(keyset, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_KEYSET_TYPE(keyset->type, ENCOUNTER_ERR_PARAM);

	
	return D.load_privK(ctx, keyset->s.path, passphrase, keyctx);
}

/** Persist a cryptographic counter to a file */
encounter_err_t encounter_persist_counter(encounter_t *ctx, \
			ec_count_t *encount, const char *path) 
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(encount, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(path, ENCOUNTER_ERR_PARAM);

	return D.persist_cnt(ctx, encount, path);
}

/** Get a cryptographic counter from a file */
encounter_err_t encounter_get_counter(encounter_t *ctx, \
			const char *path, ec_count_t **encount)
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(path, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(encount, ENCOUNTER_ERR_PARAM);

	return D.get_counter(ctx, path, encount);
}

/** Create a keyset handle */
encounter_err_t encounter_create_keyset(encounter_t *ctx, \
    			encounter_keyset_t type, const char *path, \
			const char *passphrase, ec_keyset_t **keyset) 
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_KEYSET_TYPE(type, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(path, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(keyset, ENCOUNTER_ERR_PARAM);

	return D.create_keyset(ctx, type, path, passphrase, keyset);
}

/** Dispose a keyset handle */
encounter_err_t encounter_dispose_keyset(encounter_t *ctx, \
						ec_keyset_t *keyset)
{
	__ENCOUNTER_SANITYCHECK_MEM(ctx, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_MEM(keyset, ENCOUNTER_ERR_PARAM);

	return D.dispose_keyset(ctx, keyset);
}


/** Dispose the supplied Encounter context. */
void encounter_term(encounter_t *ctx)
{
	if (ctx) {
		D.term_store(ctx);
		D.term_crypto(ctx);
		(void) memset(ctx, 0, sizeof *ctx);
		free(ctx);
	} 
}
