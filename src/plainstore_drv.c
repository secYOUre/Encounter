#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plainstore_drv.h"
#include "encounter.h"
#include "encounter_priv.h"
#include "utils.h"

#define ENCOUNTER_STORE_PLAIN_MAXLINE   1024+16384

encounter_err_t encounter_plain_storekey(encounter_t *ctx, \
			ec_keyctx_t *keyctx, const char *path)
{

	FILE *keyfile = NULL;
	ec_keystring_t *key = NULL;

	/* Get an hex representation of the key components */
	if ( D.numToString(ctx, keyctx, &key) != ENCOUNTER_OK) goto end;

	/* Write the key components in the plaintext keyset */
	switch (key->type) {
		case EC_KEYTYPE_PAILLIER_PUBLIC:
			keyfile = fopen(path, "wb");
			if (!keyfile) goto end;

			fprintf(keyfile, "%s\n", key->k.paillier_pubK.n);
			fprintf(keyfile, "%s\n", key->k.paillier_pubK.g);
			fprintf(keyfile, "%s\n", key->k.paillier_pubK.nsquared);

			ctx->rc = ENCOUNTER_OK;
			break;

		case EC_KEYTYPE_PAILLIER_PRIVATE:
			keyfile = fopen(path, "wb");
			if (!keyfile) goto end;

			fprintf(keyfile, "%s\n", key->k.paillier_privK.p);
			fprintf(keyfile, "%s\n", key->k.paillier_privK.q);
			fprintf(keyfile, "%s\n", key->k.paillier_privK.psquared);
			fprintf(keyfile, "%s\n", key->k.paillier_privK.qsquared);
			fprintf(keyfile, "%s\n", key->k.paillier_privK.pinvmod2tow);
			fprintf(keyfile, "%s\n", key->k.paillier_privK.qinvmod2tow);
			fprintf(keyfile, "%s\n", key->k.paillier_privK.hsubp);
			fprintf(keyfile, "%s\n", key->k.paillier_privK.hsubq);
			fprintf(keyfile, "%s\n", key->k.paillier_privK.qInv);


			ctx->rc = ENCOUNTER_OK;
			break;

		default:
			assert(NOTREACHED);
			break;
	}
	

end:
	/* Okay, dispose temp resources, if any */
	if (keyfile) fclose(keyfile);
	if (key) D.dispose_keystring(ctx, key);

	/* We are done */
	return ctx->rc;
}

encounter_err_t encounter_plain_loadPublicKey(encounter_t *ctx, \
			const char *path, ec_keyctx_t **keyctx) 
{
	if (!ctx || !path || !keyctx) goto end;

	FILE *keyfile = fopen(path, "r");
	if (!keyfile) {
		encounter_set_error(ctx, ENCOUNTER_ERR_OS, "fopen: failed");
		goto end;
	}
	char *line = (char *) calloc(1, ENCOUNTER_STORE_PLAIN_MAXLINE);
	ec_keystring_t *key = calloc(1, sizeof *key );
	if (!key || !line) {
		encounter_set_error(ctx, ENCOUNTER_ERR_MEM, "calloc: failed");
		goto end;
	}

	/* Set the key-type */
	key->type = EC_KEYTYPE_PAILLIER_PUBLIC;

	/* Read, in the following order, n, g, and nsquared */
	if (fgets(line, ENCOUNTER_STORE_PLAIN_MAXLINE, keyfile))
		key->k.paillier_pubK.n = strdup(line);
	
	if (fgets(line, ENCOUNTER_STORE_PLAIN_MAXLINE, keyfile))
		key->k.paillier_pubK.g = strdup(line);

	if (fgets(line, ENCOUNTER_STORE_PLAIN_MAXLINE, keyfile))
		key->k.paillier_pubK.nsquared = strdup(line);


	if (    key->k.paillier_pubK.n \
	     && key->k.paillier_pubK.g \
	     && key->k.paillier_pubK.nsquared )
		/* Get a key-context from the text form */
		ctx->rc = D.stringToNum(ctx, key, keyctx);
	else 
		encounter_set_error(ctx, ENCOUNTER_ERR_OS, \
		   "unable to read the required parameters");

end:
	/* Okay, dispose temp resources, if any */
	if (key) D.dispose_keystring(ctx, key);
	if (line) free(line);
	if (keyfile) fclose(keyfile);

	/* We are done */
	return ctx->rc;
}

encounter_err_t encounter_plain_loadPrivKey(encounter_t *ctx, \
	const char *path, const char *passphrase, ec_keyctx_t **keyctx)
{
	if (!ctx || !path || !keyctx) goto end;

	FILE *keyfile = fopen(path, "r");
	if (!keyfile) {
		encounter_set_error(ctx, ENCOUNTER_ERR_OS, "fopen: failed");
		goto end;
	}
	char *line = (char *) calloc(1, ENCOUNTER_STORE_PLAIN_MAXLINE);
	ec_keystring_t *key = calloc(1, sizeof *key );
	if (!key || !line) {
		encounter_set_error(ctx, ENCOUNTER_ERR_MEM, "calloc: failed");
		goto end;
	}

	/* Set the key-type */
	key->type = EC_KEYTYPE_PAILLIER_PRIVATE;

	/* Read, in the following order:
	 * p, q, psquared, qsquared, pinvmod2tow qinvmod2tow,
	 * hsubp, hsubq, qInv */
	if (fgets(line, ENCOUNTER_STORE_PLAIN_MAXLINE, keyfile))
		key->k.paillier_privK.p = strdup(line);
	
	if (fgets(line, ENCOUNTER_STORE_PLAIN_MAXLINE, keyfile))
		key->k.paillier_privK.q = strdup(line);

	if (fgets(line, ENCOUNTER_STORE_PLAIN_MAXLINE, keyfile))
		key->k.paillier_privK.psquared = strdup(line);

	if (fgets(line, ENCOUNTER_STORE_PLAIN_MAXLINE, keyfile))
		key->k.paillier_privK.qsquared = strdup(line);

	if (fgets(line, ENCOUNTER_STORE_PLAIN_MAXLINE, keyfile))
		key->k.paillier_privK.pinvmod2tow = strdup(line);

	if (fgets(line, ENCOUNTER_STORE_PLAIN_MAXLINE, keyfile))
		key->k.paillier_privK.qinvmod2tow = strdup(line);

	if (fgets(line, ENCOUNTER_STORE_PLAIN_MAXLINE, keyfile))
		key->k.paillier_privK.hsubp = strdup(line);

	if (fgets(line, ENCOUNTER_STORE_PLAIN_MAXLINE, keyfile))
		key->k.paillier_privK.hsubq = strdup(line);

	if (fgets(line, ENCOUNTER_STORE_PLAIN_MAXLINE, keyfile))
		key->k.paillier_privK.qInv = strdup(line);


	if (    key->k.paillier_privK.p \
	     && key->k.paillier_privK.q \
	     && key->k.paillier_privK.psquared \
	     && key->k.paillier_privK.qsquared \
	     && key->k.paillier_privK.pinvmod2tow \
	     && key->k.paillier_privK.qinvmod2tow \
	     && key->k.paillier_privK.hsubp \
	     && key->k.paillier_privK.hsubq \
	     && key->k.paillier_privK.qInv)
		/* Get a key-context from the text form */
		ctx->rc = D.stringToNum(ctx, key, keyctx);
	else 
		encounter_set_error(ctx, ENCOUNTER_ERR_OS, \
		   "unable to read the required parameters");

end:
	/* Okay, dispose temp resources, if any */
	if (key) D.dispose_keystring(ctx, key);
	if (line) free(line);
	if (keyfile) fclose(keyfile);

	/* We are done */
	return ctx->rc;
}

encounter_err_t encounter_plain_persist_cnt(encounter_t *ctx, \
                              ec_count_t *encount, const char *path) 
{
	if (!ctx || !encount || !path) goto end;

	FILE *counterFile  = NULL;
	char *counter = NULL;

	/* Get an hex representation of the cryptographic counter */
	ctx->rc = D.counterToString(ctx, encount, &counter);
	if (ctx->rc != ENCOUNTER_OK) goto end;


	counterFile = fopen(path, "wb");
	if (!counterFile) { 
		ctx->rc = ENCOUNTER_ERR_OS; 
		goto end;
	}

	fprintf(counterFile, "%s", counter);
	ctx->rc = ENCOUNTER_OK;

end:
	if (counter) D.dispose_counterString(ctx, counter);
	if (counterFile) fclose(counterFile);

	return ctx->rc;
}

encounter_err_t encounter_plain_get_counter(encounter_t *ctx, \
                         const char *path, ec_count_t **encount) 
{
	if (!ctx || !path || !encount) goto end;

	char *line = (char *) calloc(1, ENCOUNTER_STORE_PLAIN_MAXLINE);
	FILE *counterFile = fopen(path, "r");
	if (!counterFile) {
		encounter_set_error(ctx, ENCOUNTER_ERR_OS, "fopen: failed");
		goto end;
	}

	if (fgets(line, ENCOUNTER_STORE_PLAIN_MAXLINE, counterFile)) {
		ctx->rc = D.stringToCounter(ctx, line, encount);

	} else ctx->rc = ENCOUNTER_ERR_OS;

end:
	if (line) free(line);
	if (counterFile) fclose(counterFile);

	return ctx->rc;
}

encounter_err_t encounter_plain_init_store(encounter_t *ctx) 
{
	ctx->rc = ENCOUNTER_OK;
	return ctx->rc;
}

encounter_err_t encounter_plain_term_store(encounter_t *ctx) 
{
	ctx->rc = ENCOUNTER_OK;
	return ctx->rc;
}
