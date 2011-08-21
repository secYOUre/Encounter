#include <sys/time.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/ripemd.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/pkcs12.h>

#include "encounter_priv.h"

#include "openssl_drv.h"

#include "utils.h"

typedef struct seed_ss {
	uint32_t	r[32];	/* 1024-bit */
} seed_t;

#define BN_is_not_one(a)      (!(BN_is_one(a)))
#define BN_are_equal(a,b)     (BN_cmp(a,b) == 0)
#define BN_are_not_equal(a,b) (!(BN_are_equal(a,b)))
#define BN_is_neg(a)          (a->neg == 1)


/* Some static prototypes */
static encounter_err_t rng_init (void);

static encounter_err_t encounter_crypto_openssl_new_keyctx(\
			const encounter_key_t, ec_keyctx_t **);

static encounter_err_t encounter_crypto_openssl_invMod2toW(\
	encounter_t *,	BIGNUM *, const BIGNUM *, BN_CTX *);

static encounter_err_t encounter_crypto_openssl_hConstant (\
	encounter_t *, BIGNUM *, const BIGNUM *, const BIGNUM *, \
			const BIGNUM *, const BIGNUM *, BN_CTX *);

static encounter_err_t encounter_crypto_openssl_fastL(\
	encounter_t *, BIGNUM *, const BIGNUM *, const BIGNUM *, \
      					const BIGNUM *, BN_CTX *);

static encounter_err_t encounter_crypto_openssl_paillierEncrypt(\
	encounter_t *, BIGNUM *, const BIGNUM *, const ec_keyctx_t *);

static encounter_err_t IsInZnstar(encounter_t *, const BIGNUM *, \
				const BIGNUM *, BN_CTX *, bool *);

static encounter_err_t IsInZnSquaredstar(encounter_t *, \
		const BIGNUM *a, const BIGNUM *n, BN_CTX *bnctx, bool *);

static encounter_err_t encounter_crypto_openssl_paillierInc(\
	encounter_t *, BIGNUM *, const ec_keyctx_t *, BN_CTX *);

static encounter_err_t encounter_crypto_openssl_fastCRT(\
	BIGNUM *g, const BIGNUM *g1, const BIGNUM *p, const BIGNUM *g2,\
		 const BIGNUM *q, const BIGNUM *qInv, BN_CTX *bnctx);

static encounter_err_t encounter_crypto_openssl_new_paillierGenerator(\
			encounter_t *,	BIGNUM *, const ec_keyctx_t *);

static encounter_err_t encounter_crypto_openssl_qInv(encounter_t *ctx, \
		BIGNUM *,  const BIGNUM *, const BIGNUM *, BN_CTX *);




static encounter_err_t rng_init(void)
{
        seed_t  *seed_p;
        int c;

        seed_p = malloc(sizeof *seed_p);
        if(!seed_p) return (ENCOUNTER_ERR_MEM);

#ifdef HAVE_ARC4RANDOM
        for (int i = 0; i < (sizeof *seed_p/sizeof seed_p->r[0]); ++i)
                seed_p->r[i] = arc4random_uniform(UINT32_MAX);
#else   /* Revert on /dev/urandom */
        do {
                FILE *f = fopen("/dev/urandom", "r");
                if (!f) return (ENCOUNTER_ERR_OS);
                fread(seed_p, sizeof *seed_p, 1, f);
                fclose(f);

        } while(0);

#endif
        RAND_seed(seed_p, sizeof *seed_p);

        c = RAND_status();
        if (seed_p) free(seed_p);
        if (c == 0) return ENCOUNTER_ERR_CRYPTO;

        return (ENCOUNTER_OK);
}

encounter_err_t encounter_crypto_openssl_init(encounter_t *ctx)
{
	EVP_add_cipher(EVP_aes_256_cbc());
	EVP_add_digest(EVP_ripemd160());

	if (rng_init() != ENCOUNTER_OK) {
		ctx->rc = ENCOUNTER_ERR_CRYPTO;
		return ctx->rc;
	}

#ifdef __ENCOUNTER_DEBUG_
	CRYPTO_malloc_debug_init();
	CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	ERR_load_crypto_strings();
#endif /* ! __ENCOUNTER_DEBUG_ */

	/* Set ctx->m to zero. This precomputed quantity will be used
	 * to initialize each crypto counter instance */
	ctx->m = BN_new();
	BN_zero(ctx->m);

	ctx->rc = ENCOUNTER_OK;
	return ctx->rc;
}

encounter_err_t encounter_crypto_openssl_term(encounter_t *ctx)
{
	BN_free(ctx->m); /* Free the crypto counter initializer */
	EVP_cleanup();	 /* Cleanup the OpenSSL environment */

#ifdef __ENCOUNTER_DEBUG_
	printf("--------Memory Leaks displayed below--------\n");
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_state(0);
	CRYPTO_mem_leaks_fp(stdout);
	printf("--------Memory Leaks displayed above--------\n");
#endif /* ! __ENCOUNTER_DEBUG_ */

	ctx->rc = ENCOUNTER_OK;
	return ctx->rc;
}


static encounter_err_t encounter_crypto_openssl_new_keyctx( \
			const encounter_key_t type, ec_keyctx_t **keyctx_pp) 
{
	encounter_err_t rc;
	ec_keyctx_t *key_p = NULL;

	if (keyctx_pp)  {
		key_p = calloc(1, sizeof *key_p);
		if (key_p) {
			key_p->type = type;
			switch (type) {
				case EC_KEYTYPE_PAILLIER_PUBLIC:
					key_p->k.paillier_pubK.n = BN_new();
					key_p->k.paillier_pubK.g = BN_new();
					key_p->k.paillier_pubK.nsquared = \
								BN_new();
					if (    key_p->k.paillier_pubK.n \
					     && key_p->k.paillier_pubK.g \
					     && key_p->k.paillier_pubK.nsquared)
						rc = ENCOUNTER_OK;
					else
						rc = ENCOUNTER_ERR_MEM; 
					break;

				case EC_KEYTYPE_PAILLIER_PRIVATE:
					key_p->k.paillier_privK.p = BN_new();
					key_p->k.paillier_privK.q = BN_new();
					key_p->k.paillier_privK.psquared = BN_new();
					key_p->k.paillier_privK.qsquared = BN_new();
					key_p->k.paillier_privK.pinvmod2tow = BN_new();
					key_p->k.paillier_privK.qinvmod2tow = BN_new();
					key_p->k.paillier_privK.hsubp = BN_new();
					key_p->k.paillier_privK.hsubq = BN_new();
					key_p->k.paillier_privK.qInv = BN_new();

					if (   key_p->k.paillier_privK.p \
					    && key_p->k.paillier_privK.q \
					    && key_p->k.paillier_privK.psquared\
					    && key_p->k.paillier_privK.qsquared\
					    && key_p->k.paillier_privK.pinvmod2tow \
					    && key_p->k.paillier_privK.qinvmod2tow \
					    && key_p->k.paillier_privK.hsubp \
					    && key_p->k.paillier_privK.hsubq \
					    && key_p->k.paillier_privK.qInv )
						rc = ENCOUNTER_OK;
					else
						rc = ENCOUNTER_ERR_MEM;
					break;

				default:
					free(key_p);
					key_p = NULL;
					/* ctx->rc = ENCOUNTER_ERR_MEM; */
					return ENCOUNTER_ERR_PARAM;

			}
			/* Copy out the pointer to the key context */
			*keyctx_pp = key_p;

		} else
			rc = ENCOUNTER_ERR_MEM;

	}	else rc = ENCOUNTER_ERR_PARAM;

	/* We are done */
	return rc;
}

encounter_err_t encounter_crypto_openssl_free_keyctx(encounter_t *ctx, ec_keyctx_t *keyctx) {
	if (keyctx) {
		switch (keyctx->type) {
			case EC_KEYTYPE_PAILLIER_PUBLIC:
				BN_free(keyctx->k.paillier_pubK.n);
				BN_free(keyctx->k.paillier_pubK.g);
				BN_free(keyctx->k.paillier_pubK.nsquared);
				break;

			case EC_KEYTYPE_PAILLIER_PRIVATE:
				BN_free(keyctx->k.paillier_privK.p);
				BN_free(keyctx->k.paillier_privK.q);
				BN_free(keyctx->k.paillier_privK.psquared);
				BN_free(keyctx->k.paillier_privK.qsquared);
				BN_free(keyctx->k.paillier_privK.pinvmod2tow);
				BN_free(keyctx->k.paillier_privK.qinvmod2tow);
				BN_free(keyctx->k.paillier_privK.hsubp);
				BN_free(keyctx->k.paillier_privK.hsubq);
				BN_free(keyctx->k.paillier_privK.qInv);
				break;
			default:
				ctx->rc = ENCOUNTER_ERR_PARAM;
				return ctx->rc;
		}

		free(keyctx);
		ctx->rc = ENCOUNTER_OK;
	} else ctx->rc = ENCOUNTER_ERR_PARAM;

	return ctx->rc;
}

encounter_err_t encounter_crypto_openssl_keygen(encounter_t *ctx, \
	encounter_key_t type, unsigned int keysize, ec_keyctx_t **pubK, ec_keyctx_t **privK) 
{
	encounter_err_t rc;

	__ENCOUNTER_SANITYCHECK_KEYTYPE(type, ENCOUNTER_ERR_PARAM);
	__ENCOUNTER_SANITYCHECK_KEYSIZE(keysize, ENCOUNTER_ERR_PARAM);

	BN_CTX *bnctx = BN_CTX_new();


	rc = encounter_crypto_openssl_new_keyctx(\
				EC_KEYTYPE_PAILLIER_PUBLIC, pubK);
	if (rc != ENCOUNTER_OK) goto err;	

	rc = encounter_crypto_openssl_new_keyctx(\
				EC_KEYTYPE_PAILLIER_PRIVATE, privK);
	if (rc != ENCOUNTER_OK) goto err;	

	/* Generate p and q primes */
	if (!BN_generate_prime((*privK)->k.paillier_privK.p, keysize,0,\
					NULL, NULL, NULL, NULL) )
		OPENSSL_ERROR(err);

	if (!BN_generate_prime((*privK)->k.paillier_privK.q, keysize,0,\
					NULL, NULL, NULL, NULL) )
		OPENSSL_ERROR(err);

	/* p^2 */
	if (!BN_sqr((*privK)->k.paillier_privK.psquared, \
	       (*privK)->k.paillier_privK.p, bnctx) )
		OPENSSL_ERROR(err);

	/* q^2 */
	if (!BN_sqr((*privK)->k.paillier_privK.qsquared, \
	       (*privK)->k.paillier_privK.q, bnctx) )
		OPENSSL_ERROR(err);

	/* n = pq */
	if (!BN_mul((*pubK)->k.paillier_pubK.n,    \
		(*privK)->k.paillier_privK.p, \
		(*privK)->k.paillier_privK.q, bnctx) )
		OPENSSL_ERROR(err);

	/* n^2 */
	if (!BN_sqr(	(*pubK)->k.paillier_pubK.nsquared, \
	        (*pubK)->k.paillier_pubK.n, bnctx) )
		OPENSSL_ERROR(err);

	/* Generate the Paillier generator */
	if (encounter_crypto_openssl_new_paillierGenerator( ctx, \
		(*pubK)->k.paillier_pubK.g, *privK) != ENCOUNTER_OK)
		OPENSSL_ERROR(err);	/* blame OpenSSL... */

	/* _p = p^-1 mod 2^w */
	if (encounter_crypto_openssl_invMod2toW(ctx, \
	  	(*privK)->k.paillier_privK.pinvmod2tow, \
		(*privK)->k.paillier_privK.p, bnctx) != ENCOUNTER_OK)
		OPENSSL_ERROR(err);

	/* _q = q^-1 mod 2^w */
	if (encounter_crypto_openssl_invMod2toW(ctx, \
		(*privK)->k.paillier_privK.qinvmod2tow, \
		(*privK)->k.paillier_privK.q, bnctx) != ENCOUNTER_OK )
		OPENSSL_ERROR(err);

	/* Compute H constants */
	/* h_p */
	if (encounter_crypto_openssl_hConstant(ctx, \
		(*privK)->k.paillier_privK.hsubp, \
		(*pubK)->k.paillier_pubK.g, 	\
		(*privK)->k.paillier_privK.p, 	\
		(*privK)->k.paillier_privK.psquared, \
		(*privK)->k.paillier_privK.pinvmod2tow, bnctx) \
	  != ENCOUNTER_OK)
		OPENSSL_ERROR(err);

	/* h_q */
	if (encounter_crypto_openssl_hConstant( ctx, \
		(*privK)->k.paillier_privK.hsubq, \
		(*pubK)->k.paillier_pubK.g, 	\
		(*privK)->k.paillier_privK.q, 	\
		(*privK)->k.paillier_privK.qsquared, \
		(*privK)->k.paillier_privK.qinvmod2tow, bnctx) \
	  != ENCOUNTER_OK)
		OPENSSL_ERROR(err);
 
	/* Q^-1 */
	if (encounter_crypto_openssl_qInv(ctx,\
		(*privK)->k.paillier_privK.qInv, \
		(*privK)->k.paillier_privK.q, \
		(*privK)->k.paillier_privK.p, bnctx) != ENCOUNTER_OK)
		OPENSSL_ERROR(err);


	if (bnctx) BN_CTX_free(bnctx);

	ctx->rc = ENCOUNTER_OK;
	return ctx->rc;

err:
	ctx->rc = rc;
	if (bnctx) BN_CTX_free(bnctx);
	if (*pubK) encounter_crypto_openssl_free_keyctx(ctx, *pubK);
	if (*privK) encounter_crypto_openssl_free_keyctx(ctx, *privK);

	return  ctx->rc;
}

static encounter_err_t encounter_crypto_openssl_new_paillierGenerator(\
		encounter_t *ctx, BIGNUM *g, const ec_keyctx_t *privK)
{
	if (!ctx | !g || !privK) goto end;

	BIGNUM *tmp, *inv, *pmin1, *qmin1, *gsubp, *gsubq;
	bool in = false;
	BN_CTX *bnctx = BN_CTX_new();
	BN_CTX_start(bnctx);

	tmp = BN_CTX_get(bnctx); inv = BN_CTX_get(bnctx);
	pmin1 = BN_CTX_get(bnctx); qmin1 = BN_CTX_get(bnctx);
	gsubp = BN_CTX_get(bnctx);gsubq = BN_CTX_get(bnctx);

	if (!gsubq) OPENSSL_ERROR(end);

	/* p-1 and q-1 */
	if (!BN_sub(pmin1, privK->k.paillier_privK.p, BN_value_one()))
			OPENSSL_ERROR(end);
	if (!BN_sub(qmin1, privK->k.paillier_privK.q, BN_value_one()))
			OPENSSL_ERROR(end);

	/* g_p */
	for (;;) {
   		if (!BN_rand_range(gsubp, privK->k.paillier_privK.psquared))
			OPENSSL_ERROR(end);
   		if (IsInZnSquaredstar(ctx, gsubp, \
			privK->k.paillier_privK.psquared, bnctx, &in) \
				!= ENCOUNTER_OK )
			OPENSSL_ERROR(end);
		if (in)
      		{
      			if (!BN_mod_exp(tmp, gsubp, pmin1, \
				privK->k.paillier_privK.psquared, bnctx))
				OPENSSL_ERROR(end);
      			if (BN_are_not_equal(tmp, BN_value_one()))
         			break;
      		}
   	}
	/* g_q */
	for (;;) {
   		if (!BN_rand_range(gsubq, privK->k.paillier_privK.qsquared))
			OPENSSL_ERROR(end);
   		if (IsInZnSquaredstar(ctx, gsubq, \
			privK->k.paillier_privK.qsquared, bnctx, &in) \
				!= ENCOUNTER_OK )
			OPENSSL_ERROR(end);
		if (in)
      		{
      			if (!BN_mod_exp(tmp, gsubq, qmin1, \
				privK->k.paillier_privK.qsquared, bnctx))
				OPENSSL_ERROR(end);
      			if (BN_are_not_equal(tmp, BN_value_one()))
         			break;
      		}
   	}
	/* (q^2 mod p^2)^-1 */
	if (!BN_mod(tmp, privK->k.paillier_privK.qsquared, \
		privK->k.paillier_privK.psquared, bnctx))
		OPENSSL_ERROR(end);
	if (!BN_mod_inverse(inv, tmp, privK->k.paillier_privK.psquared, bnctx))
		OPENSSL_ERROR(end);
	if (encounter_crypto_openssl_fastCRT(g, gsubp,  \
		privK->k.paillier_privK.psquared, gsubq, \
		privK->k.paillier_privK.qsquared, inv, bnctx) != ENCOUNTER_OK)
		OPENSSL_ERROR(end);	

	ctx->rc = ENCOUNTER_OK;

end:

	if (tmp) BN_clear(tmp);
	if (inv) BN_clear(inv);
	if (pmin1) BN_clear(pmin1);
	if (qmin1) BN_clear(qmin1);
	if (gsubp) BN_clear(gsubp);
	if (gsubq) BN_clear(gsubq);

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);

	return ctx->rc;
}

static encounter_err_t encounter_crypto_openssl_qInv(encounter_t *ctx, \
	BIGNUM *qInv, const BIGNUM *p, const BIGNUM *q, BN_CTX *bnctx)

{
	if (!BN_mod(qInv, q, p, bnctx)) OPENSSL_ERROR(end);
	if (!BN_mod_inverse(qInv, qInv, p, bnctx)) OPENSSL_ERROR(end);

	ctx->rc = ENCOUNTER_OK;

end:
	return ctx->rc;
}

static encounter_err_t encounter_crypto_openssl_invMod2toW(\
	encounter_t *ctx, BIGNUM *ninvmod2tow, const BIGNUM *n, \
						BN_CTX *bnctx) {
	BN_CTX_start(bnctx);
	BIGNUM *twotow = BN_CTX_get(bnctx);

	if (!BN_set_word(twotow, 1)) OPENSSL_ERROR(end);
	if (!BN_lshift(twotow, twotow, BN_num_bits(n))) 
		OPENSSL_ERROR(end);
	if (!BN_mod_inverse(ninvmod2tow, n, twotow, bnctx)) 
		OPENSSL_ERROR(end);

	ctx->rc = ENCOUNTER_OK;

end:
	if (twotow) BN_clear(twotow);
	BN_CTX_end(bnctx);

	return ctx->rc;
}


static encounter_err_t encounter_crypto_openssl_hConstant (\
	encounter_t *ctx, BIGNUM *hsubp, \
	const BIGNUM *g, const BIGNUM *p,const BIGNUM *psquared, \
	const BIGNUM *pinvmod2tow,BN_CTX *bnctx)
{
	BN_CTX_start(bnctx);
	BIGNUM *tmp = BN_CTX_get(bnctx);
	BIGNUM *pmin1 = BN_CTX_get(bnctx);

	if (!pmin1)  OPENSSL_ERROR(end);

	if (!BN_sub(pmin1,p,BN_value_one())) OPENSSL_ERROR(end);
	if (!BN_mod(tmp,g,psquared,bnctx)) OPENSSL_ERROR(end);
	if (!BN_mod_exp(tmp,tmp,pmin1,psquared,bnctx)) 
		OPENSSL_ERROR(end);

	if (encounter_crypto_openssl_fastL(ctx, \
			hsubp,tmp,p,pinvmod2tow,bnctx) != ENCOUNTER_OK)
		OPENSSL_ERROR(end);
	if (!BN_mod_inverse(hsubp,hsubp,p,bnctx) ) OPENSSL_ERROR(end);
	
	ctx->rc = ENCOUNTER_OK;

end:
	if (tmp) BN_clear(tmp);
	if (pmin1) BN_clear(pmin1);
	BN_CTX_end(bnctx);

	return ctx->rc;
}

static encounter_err_t encounter_crypto_openssl_fastL(encounter_t *ctx, BIGNUM *y, \
	const BIGNUM *u, const BIGNUM *n, const BIGNUM *ninvmod2tow,\
							BN_CTX *bnctx)
{
	BN_CTX_start(bnctx);
	BIGNUM *tmp = BN_CTX_get(bnctx);

	if (!BN_sub(tmp,u,BN_value_one()) ) OPENSSL_ERROR(end);

	int w = BN_num_bits(n);
	if (!BN_mask_bits(tmp,w) ) OPENSSL_ERROR(end);
	if (! BN_mul(y,tmp,ninvmod2tow,bnctx) ) OPENSSL_ERROR(end);
	if (!BN_mask_bits(y,w) ) OPENSSL_ERROR(end);

	ctx->rc = ENCOUNTER_OK;

end:
	if (tmp) BN_clear(tmp);
	BN_CTX_end(bnctx);

	return ctx->rc;
}


encounter_err_t encounter_crypto_openssl_new_counter(encounter_t *ctx, ec_keyctx_t *pubK, ec_count_t **counter) 
{
	if (counter) {
		*counter = calloc(1, sizeof **counter);
		if (*counter) {
			(*counter)->version = ENCOUNTER_COUNT_PAILLIER_V1;
			(*counter)->c = BN_new();

			encounter_crypto_openssl_paillierEncrypt(\
				ctx, (*counter)->c, ctx->m, pubK);

			/* Update the time of last modification */
			time(&((*counter)->lastUpdated));
			ctx->rc = ENCOUNTER_OK;
		} else
			ctx->rc = ENCOUNTER_ERR_MEM;
		
		return ctx->rc;
	}

	ctx->rc = ENCOUNTER_ERR_PARAM;
	return ctx->rc;
}

encounter_err_t encounter_crypto_openssl_free_counter(encounter_t *ctx, ec_count_t *counter_p) 
{
	if (counter_p) {
		BN_free(counter_p->c);
		memset(counter_p, 0, sizeof *counter_p);

	} else ctx->rc = ENCOUNTER_ERR_PARAM;

	return ctx->rc;
}

static encounter_err_t encounter_crypto_openssl_paillierEncrypt(\
  encounter_t *ctx, BIGNUM *c, const BIGNUM *m, const ec_keyctx_t *pubK)
{
	BN_CTX *bnctx = BN_CTX_new();
	bool in = false;
	BN_CTX_start(bnctx);
	BIGNUM *tmp   = BN_CTX_get(bnctx);
	BIGNUM *tmp2  = BN_CTX_get(bnctx);
	BIGNUM *r     = BN_CTX_get(bnctx);


	BN_mod_exp(tmp, pubK->k.paillier_pubK.g, m, \
			pubK->k.paillier_pubK.nsquared, bnctx);

	for (;;)
   	{
   		BN_rand_range(r, pubK->k.paillier_pubK.n);
   		if (IsInZnstar(ctx, r,pubK->k.paillier_pubK.n, \
				bnctx, &in) != ENCOUNTER_OK) {
			OPENSSL_ERROR(end); 
		}
		if (in == true) break;
   	}

	BN_mod_exp(tmp2, r, pubK->k.paillier_pubK.n, \
		pubK->k.paillier_pubK.nsquared, bnctx);
	BN_mod_mul(c, tmp, tmp2, \
			pubK->k.paillier_pubK.nsquared, bnctx);

	ctx->rc = ENCOUNTER_OK;

end:
	if (tmp)  BN_clear(tmp); 
	if (tmp2) BN_clear(tmp2); 
	if (r)    BN_clear(r);
	BN_CTX_end(bnctx);
	if (bnctx) BN_CTX_free(bnctx);

	return ctx->rc;
}

static encounter_err_t IsInZnstar(encounter_t *ctx, const BIGNUM *a,\
		const BIGNUM *n, BN_CTX *bnctx, bool *in)
{
	if (!ctx || !a || !n || !bnctx || !in) 
		return ENCOUNTER_ERR_PARAM;

	*in = true;
	ctx->rc = ENCOUNTER_OK;

	if (BN_cmp(a,n) >= 0) goto end;

	BN_CTX_start(bnctx);
	BIGNUM *tmp = BN_CTX_get(bnctx);

	if (!tmp) OPENSSL_ERROR(end);

	if (!BN_gcd(tmp,a,n,bnctx)) OPENSSL_ERROR(end);
	if (BN_is_not_one(tmp)) *in = false;


end:
	if (tmp) BN_clear(tmp);
	BN_CTX_end(bnctx);

	return ctx->rc;
}

static encounter_err_t IsInZnSquaredstar(encounter_t *ctx, \
    const BIGNUM *a, const BIGNUM *nsquared, BN_CTX *bnctx, bool *in)
{
	if (!ctx || !a || !nsquared || !bnctx || !in) 
		return ENCOUNTER_ERR_PARAM;

	*in = false;
	ctx->rc = ENCOUNTER_OK;

	if (BN_cmp(a,nsquared) >= 0) goto end;

	BN_CTX_start(bnctx);
	BIGNUM *tmp = BN_CTX_get(bnctx);

	if (!tmp) OPENSSL_ERROR(end);

	/* a is in Z*_n^2 iff GCD(a, n^2) = 1 */
	if (!BN_gcd(tmp,a,nsquared,bnctx)) OPENSSL_ERROR(end);
	if (BN_is_one(tmp)) *in = true;

end:
	if (tmp) BN_clear(tmp);
	BN_CTX_end(bnctx);

	return ctx->rc;
}

encounter_err_t encounter_crypto_openssl_inc(encounter_t *ctx, ec_count_t *counter, ec_keyctx_t *pubK, const int a) 
{
	BN_CTX *bnctx = BN_CTX_new();
	int i;

	for (i = 0; i < a; ++i) 
		encounter_crypto_openssl_paillierInc(ctx, counter->c, pubK, bnctx);

	BN_CTX_free(bnctx);
	/* Update the time of last modification */
	time(&(counter->lastUpdated));

	ctx->rc = ENCOUNTER_OK;
	return ctx->rc;
}

static encounter_err_t encounter_crypto_openssl_paillierInc(\
  encounter_t *ctx, BIGNUM *c, const ec_keyctx_t *pubK, BN_CTX *bnctx)
{
	BN_CTX_start(bnctx);
	BIGNUM *tmp = BN_CTX_get(bnctx);
	BIGNUM *r = BN_CTX_get(bnctx);
	bool in = false;

	if (!r || !tmp) goto end;

#if 0
	fprintf(stdout, "paillier inc: before increment: ");
	BN_print_fp(stdout, c);
	fprintf(stdout, "\n");
#endif

	if (!BN_mod_mul(c, c, pubK->k.paillier_pubK.g, \
			pubK->k.paillier_pubK.nsquared, bnctx) )  
		OPENSSL_ERROR(end);
	
	for (;;)
   	{
		if (!BN_rand_range(r, pubK->k.paillier_pubK.n) )
			OPENSSL_ERROR(end);
   		if (IsInZnstar(ctx, r, pubK->k.paillier_pubK.n, \
				bnctx, &in)  != ENCOUNTER_OK)
			OPENSSL_ERROR(end);
		if (in) break;
   	}
	if (!BN_mod_exp(tmp, r, pubK->k.paillier_pubK.n, \
			pubK->k.paillier_pubK.nsquared, bnctx) ) 
		OPENSSL_ERROR(end);
	if (!BN_mod_mul(c, c, tmp, pubK->k.paillier_pubK.nsquared, bnctx))
		OPENSSL_ERROR(end);

#if 0
	fprintf(stdout, "paillier inc: after incrementing: ");
	BN_print_fp(stdout, c);
	fprintf(stdout, "\n");
#endif
	ctx->rc = ENCOUNTER_OK;

end:
	if (tmp) BN_clear(tmp); 
	if (r)   BN_clear(r);
	BN_CTX_end(bnctx);

	return ctx->rc;
}

encounter_err_t encounter_crypto_openssl_touch(encounter_t *ctx, \
			ec_count_t *counter, ec_keyctx_t *pubK) 
{
	BN_CTX *bnctx = BN_CTX_new();
	BN_CTX_start(bnctx);
	BIGNUM *tmp = BN_CTX_get(bnctx);
	BIGNUM *r = BN_CTX_get(bnctx);
	bool	in = false;

	if (!r)	OPENSSL_ERROR(end);

	for (;;)
   	{
   		if (!BN_rand_range(r, pubK->k.paillier_pubK.n))
			OPENSSL_ERROR(end);
   		if (IsInZnstar(ctx, r,pubK->k.paillier_pubK.n, \
				bnctx, &in) != ENCOUNTER_OK)
			OPENSSL_ERROR(end);
		if (in) break; 
   	}
	if (!BN_mod_exp(tmp, r, pubK->k.paillier_pubK.n, \
			pubK->k.paillier_pubK.nsquared, bnctx))
		OPENSSL_ERROR(end);
	if (!BN_mod_mul(counter->c, counter->c, tmp, \
			pubK->k.paillier_pubK.nsquared, bnctx))
		OPENSSL_ERROR(end);

	/* Update the time of last modification */
	time(&(counter->lastUpdated));

	
	ctx->rc = ENCOUNTER_OK;

end:
	if (tmp) BN_clear(tmp);
	if (r)	BN_clear(r);

	BN_CTX_end(bnctx);
	if (bnctx) BN_CTX_free(bnctx);

	return ctx->rc;
}

encounter_err_t encounter_crypto_openssl_decrypt(encounter_t *ctx, \
     ec_count_t *counter, ec_keyctx_t *privK, unsigned long long int *a)
{
	BN_CTX *bnctx = BN_CTX_new();
	BN_CTX_start(bnctx);
	BIGNUM *m = BN_CTX_get(bnctx);

	BIGNUM *tmp, *pmin1, *qmin1, *msubp, *msubq;

	tmp = BN_CTX_get(bnctx); pmin1 = BN_CTX_get(bnctx); 
	qmin1 = BN_CTX_get(bnctx);
	msubp = BN_CTX_get(bnctx); msubq = BN_CTX_get(bnctx);

	/* p-1 and q-1 */
	BN_sub(pmin1, privK->k.paillier_privK.p, BN_value_one());
	BN_sub(qmin1, privK->k.paillier_privK.q, BN_value_one());

	/* c^(p-1) */
	BN_mod(tmp, counter->c, privK->k.paillier_privK.psquared, bnctx);
	BN_mod_exp(tmp, tmp, pmin1, privK->k.paillier_privK.psquared, bnctx);

	/* m_p = L_p ( c^(p-1) mod p^2 ) h_p mod p */
	encounter_crypto_openssl_fastL(ctx, tmp, tmp, \
			privK->k.paillier_privK.p, \
			privK->k.paillier_privK.pinvmod2tow, bnctx);
	BN_mod_mul(msubp, tmp, privK->k.paillier_privK.hsubp, \
			privK->k.paillier_privK.p, bnctx);

	/* c^(q-1) */
	BN_mod(tmp, counter->c, privK->k.paillier_privK.qsquared, bnctx);
	BN_mod_exp(tmp, tmp, qmin1, privK->k.paillier_privK.qsquared,bnctx);

	/* m_q = L_q( c^(q-1) mod q^2 ) h_q mod q */
	encounter_crypto_openssl_fastL(ctx, tmp, tmp, \
			privK->k.paillier_privK.q, \
			privK->k.paillier_privK.qinvmod2tow, bnctx);
	BN_mod_mul(msubq, tmp, privK->k.paillier_privK.hsubq, \
			privK->k.paillier_privK.q, bnctx);

	/* m = CRT(m_p, m_q) mod pq */
	encounter_crypto_openssl_fastCRT(m, msubp, \
			privK->k.paillier_privK.p, msubq, \
			privK->k.paillier_privK.q, \
			privK->k.paillier_privK.qInv, bnctx);

	/* Make the plaintext counter available via a */
	char *plainC = BN_bn2dec(m);
	*a = strtoul(plainC, NULL, 10);
	OPENSSL_free(plainC);

	BN_clear(tmp); BN_clear(pmin1); BN_clear(qmin1);
	BN_clear(msubp); BN_clear(msubq);
	BN_clear(m);

	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);

	ctx->rc = ENCOUNTER_OK;
	return ctx->rc;
}


static encounter_err_t encounter_crypto_openssl_fastCRT(BIGNUM *g, const BIGNUM *g1, const BIGNUM *p, const BIGNUM *g2, const BIGNUM *q, const BIGNUM *qInv, BN_CTX *bnctx)
{
	BN_CTX_start(bnctx);
	BIGNUM *tmp = BN_CTX_get(bnctx);
	BIGNUM *h = BN_CTX_get(bnctx);

	BN_sub(tmp,g1,g2);
	if (BN_is_neg(tmp))
   		BN_add(tmp,tmp,p);

	BN_mod_mul(h,tmp,qInv,p, bnctx);
	BN_mul(tmp,q,h, bnctx);
	BN_add(g,g2,tmp);

	BN_clear(tmp);
	BN_clear(h);
	BN_CTX_end(bnctx);

	return ENCOUNTER_OK;
}

encounter_err_t encounter_crypto_openssl_numToString(encounter_t  *ctx,\
                ec_keyctx_t *keyctx, ec_keystring_t **key) 
{
	if (keyctx && key) {
		*key = calloc(1, sizeof **key);
		if (*key == NULL) {
			ctx->rc = ENCOUNTER_ERR_MEM;
			return ctx->rc;
		}
		/* The keytype maps to itself */
		(*key)->type = keyctx->type;

		/* Set the key components in hex form */
		switch (keyctx->type) {
			case EC_KEYTYPE_PAILLIER_PUBLIC:
				(*key)->k.paillier_pubK.n = \
				BN_bn2hex(keyctx->k.paillier_pubK.n);

				(*key)->k.paillier_pubK.g = \
				BN_bn2hex(keyctx->k.paillier_pubK.g);

				(*key)->k.paillier_pubK.nsquared = \
				BN_bn2hex(keyctx->k.paillier_pubK.nsquared);
				break;

			case EC_KEYTYPE_PAILLIER_PRIVATE:
				(*key)->k.paillier_privK.p = \
				BN_bn2hex(keyctx->k.paillier_privK.p);

				(*key)->k.paillier_privK.q = \
				BN_bn2hex(keyctx->k.paillier_privK.q);

				(*key)->k.paillier_privK.psquared = \
				BN_bn2hex(keyctx->k.paillier_privK.psquared);

				(*key)->k.paillier_privK.qsquared = \
				BN_bn2hex(keyctx->k.paillier_privK.qsquared);

				(*key)->k.paillier_privK.pinvmod2tow = \
				BN_bn2hex(keyctx->k.paillier_privK.pinvmod2tow);

				(*key)->k.paillier_privK.qinvmod2tow = \
				BN_bn2hex(keyctx->k.paillier_privK.qinvmod2tow);

				(*key)->k.paillier_privK.hsubp = \
				BN_bn2hex(keyctx->k.paillier_privK.hsubp);

				(*key)->k.paillier_privK.hsubq = \
				BN_bn2hex(keyctx->k.paillier_privK.hsubq);

				(*key)->k.paillier_privK.qInv = \
				BN_bn2hex(keyctx->k.paillier_privK.qInv);

				break;

			default:
				assert(NOTREACHED);
				break;
		}
		ctx->rc = ENCOUNTER_OK;
	} else ctx->rc = ENCOUNTER_ERR_PARAM;

	return ctx->rc;
}

encounter_err_t encounter_crypto_openssl_stringToNum(encounter_t *ctx,\
                ec_keystring_t *key, ec_keyctx_t **keyctx) 

{
	if (key && keyctx) {
		switch (key->type) {
			case EC_KEYTYPE_PAILLIER_PUBLIC:
				if (encounter_crypto_openssl_new_keyctx(\
				    EC_KEYTYPE_PAILLIER_PUBLIC ,keyctx )\
				 != ENCOUNTER_OK) 
					break;
				
				(*keyctx)->type = key->type;				
				BN_hex2bn(&(*keyctx)->k.paillier_pubK.n, \
					key->k.paillier_pubK.n);

				BN_hex2bn(&(*keyctx)->k.paillier_pubK.g, \
					key->k.paillier_pubK.g);

				BN_hex2bn(\
				&(*keyctx)->k.paillier_pubK.nsquared, \
				key->k.paillier_pubK.nsquared);

				ctx->rc = ENCOUNTER_OK;
				break;

			case EC_KEYTYPE_PAILLIER_PRIVATE:
				if (encounter_crypto_openssl_new_keyctx(\
				    EC_KEYTYPE_PAILLIER_PRIVATE ,keyctx )\
				 != ENCOUNTER_OK) 
					break;

				(*keyctx)->type = key->type;				

				BN_hex2bn(&(*keyctx)->k.paillier_privK.p,\
					key->k.paillier_privK.p);

				BN_hex2bn(&(*keyctx)->k.paillier_privK.q,\
					key->k.paillier_privK.q);

				BN_hex2bn(\
				&(*keyctx)->k.paillier_privK.psquared,
				key->k.paillier_privK.psquared);

				BN_hex2bn(\
				&(*keyctx)->k.paillier_privK.qsquared,
				key->k.paillier_privK.qsquared);

				BN_hex2bn(\
				&(*keyctx)->k.paillier_privK.pinvmod2tow,\
				key->k.paillier_privK.pinvmod2tow);

				BN_hex2bn(\
				&(*keyctx)->k.paillier_privK.qinvmod2tow,
				key->k.paillier_privK.qinvmod2tow);

				BN_hex2bn(\
				&(*keyctx)->k.paillier_privK.hsubp,
				key->k.paillier_privK.hsubp);

				BN_hex2bn(\
				&(*keyctx)->k.paillier_privK.hsubq,
				key->k.paillier_privK.hsubq);

				BN_hex2bn(\
				&(*keyctx)->k.paillier_privK.qInv,
				key->k.paillier_privK.qInv);

				ctx->rc = ENCOUNTER_OK;
				break;

			default:
				ctx->rc = ENCOUNTER_ERR_DATA;
				break;
		}
	} else ctx->rc = ENCOUNTER_ERR_PARAM;

	/* We are done */
	return ctx->rc;
}

encounter_err_t encounter_crypto_openssl_counterToString(\
	encounter_t *ctx, ec_count_t *encount, char **counter) 
{
	if (encount && counter) {
		*counter = BN_bn2hex(encount->c);		
		ctx->rc = ENCOUNTER_OK;

	} else ctx->rc = ENCOUNTER_ERR_PARAM;

	return ctx->rc;
}

encounter_err_t encounter_crypto_openssl_counterStrDispose(\
				encounter_t *ctx, char *counter) 
{
	if (counter) OPENSSL_free(counter);
}


encounter_err_t encounter_crypto_openssl_dispose_keystring(\
		encounter_t *ctx, ec_keystring_t *key) 
{
	if (key) {
		switch(key->type) {
			case EC_KEYTYPE_PAILLIER_PUBLIC:
				OPENSSL_free(key->k.paillier_pubK.n);
				OPENSSL_free(key->k.paillier_pubK.g);
				OPENSSL_free(key->k.paillier_pubK.nsquared);
				memset(key, 0, sizeof *key);
				free(key);
				ctx->rc = ENCOUNTER_OK;
				break;
			case EC_KEYTYPE_PAILLIER_PRIVATE:	
				OPENSSL_free(key->k.paillier_privK.p);	
				OPENSSL_free(key->k.paillier_privK.q);	
				OPENSSL_free(key->k.paillier_privK.psquared);	
				OPENSSL_free(key->k.paillier_privK.qsquared);	
				OPENSSL_free(key->k.paillier_privK.pinvmod2tow);
				OPENSSL_free(key->k.paillier_privK.qinvmod2tow);
				OPENSSL_free(key->k.paillier_privK.hsubp);	
				OPENSSL_free(key->k.paillier_privK.hsubq);	
				OPENSSL_free(key->k.paillier_privK.qInv);
				memset(key, 0, sizeof *key);
				free(key);
				ctx->rc = ENCOUNTER_OK;
				break;
			default:	
				ctx->rc = ENCOUNTER_ERR_PARAM;	
				break;
		}
	} else ctx->rc = ENCOUNTER_ERR_PARAM;

	return ctx->rc;
}

encounter_err_t encounter_crypto_openssl_dispose_counterString(\
			encounter_t *ctx, char *counter)
{
	if (counter) OPENSSL_free(counter);

	ctx->rc = ENCOUNTER_OK;
	return ctx->rc;
}

encounter_err_t encounter_crypto_openssl_stringToCounter(\
         encounter_t *ctx, const char *counter, ec_count_t **encount)
{
	if (!ctx || !counter || !encount) goto err;

	*encount = calloc(1, sizeof **encount);
	if (*encount) {
		(*encount)->version = ENCOUNTER_COUNT_PAILLIER_V1;
		BN_hex2bn(&(*encount)->c, counter);

		/* Update the time of last modification */
		time(&((*encount)->lastUpdated));

		ctx->rc = ENCOUNTER_OK;
	} else  ctx->rc = ENCOUNTER_ERR_MEM;

	/* We are done */
	return ctx->rc;

err:
	if (*encount) {
		free (*encount);
		*encount = NULL;
	}
	return ctx->rc;
}
