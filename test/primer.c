#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "encounter.h"


#define COUNTERPATH	"./counter.txt"
#define PUBLICKEYPATH	"./publickey.txt"
#define PRIVATEKEYPATH	"./privatekey.txt"

#define	KEYSIZE	1024

int main(int argc, char *argv[]) 
{
	encounter_err_t rc = ENCOUNTER_OK;
	encounter_t *ctx = NULL;
	ec_keyctx_t *pubK = NULL;
	ec_keyctx_t *privK = NULL;
	ec_count_t  *encounter = NULL;
	ec_keyset_t *keyset = NULL, *keyset2 = NULL;
	unsigned long long int c = 0;
	int a = 0;

start:
	/* Initialize Encounter */
	rc = encounter_init(0, &ctx);
	if (rc != ENCOUNTER_OK) goto end;

	printf("Init: succeeded\n");

#if 1
	if(encounter_keygen(ctx, EC_KEYTYPE_PAILLIER_PUBLIC, \
			KEYSIZE, &pubK, &privK) != ENCOUNTER_OK) goto end;

	printf("Keygen: succeeded\n");

	if(encounter_new_counter(ctx, pubK, &encounter) != ENCOUNTER_OK)
					goto end;

	printf("New counter: succeded\n");
#endif
	if(encounter_create_keyset(ctx, EC_KEYSET_PLAIN, PUBLICKEYPATH,\
				NULL, &keyset) != ENCOUNTER_OK) goto end;

	printf("Create keyset: succeded\n");

#if 1
	if(encounter_add_publicKey(ctx, pubK, keyset) != ENCOUNTER_OK)
			goto end;

	printf("Adding public key to keyset: succeeded\n");

#endif
	if(encounter_create_keyset(ctx, EC_KEYSET_PLAIN, PRIVATEKEYPATH,\
				NULL, &keyset2) != ENCOUNTER_OK) goto end;

	printf("Create keyset2: succeded\n");
#if 1
	if(encounter_add_privateKey(ctx, privK, keyset2, NULL) != ENCOUNTER_OK)
			goto end;

	printf("Adding private key to keyset2: succeeded\n");


	encounter_dispose_counter(ctx, encounter); encounter = NULL;
	encounter_dispose_keyctx(ctx, pubK);   pubK = NULL;
	encounter_dispose_keyctx(ctx, privK); privK = NULL;

#endif
	if(encounter_get_publicKey(ctx, keyset, &pubK) != ENCOUNTER_OK)
			goto end;

	printf("Retriving public key from keyset: succeeded\n");

	if(encounter_get_privateKey(ctx, keyset2, NULL, &privK) !=
			ENCOUNTER_OK) goto end;

	printf("Retrieving private key from keyset2: succeeded\n");

	if(encounter_new_counter(ctx, pubK, &encounter) != ENCOUNTER_OK)
					goto end;

	printf("New counter: succeded\n");

	if (encounter_inc(ctx, pubK, encounter, 1) != ENCOUNTER_OK) goto end;

	printf("Counter increment: succeeded\n");

	if (encounter_inc(ctx, pubK, encounter, 1) != ENCOUNTER_OK) goto end;

	printf("Counter increment: succeeded\n");

	if (encounter_inc(ctx, pubK, encounter, 1) != ENCOUNTER_OK) goto end;

	printf("Counter increment: succeeded\n");

	if (encounter_inc(ctx, pubK, encounter, 8) != ENCOUNTER_OK) goto end;

	printf("Counter increment: succeeded\n");

	if (encounter_touch(ctx, pubK, encounter) != ENCOUNTER_OK) goto end;
	
	printf("Counter re-encryption: succeeded\n");

	if (encounter_touch(ctx, pubK, encounter) != ENCOUNTER_OK) goto end;
	
	printf("Counter re-encryption: succeeded\n");


	if (encounter_persist_counter(ctx, encounter, COUNTERPATH) != \
					ENCOUNTER_OK) goto end;

	printf("Persisting counter: succeeded\n");

	encounter_dispose_counter(ctx, encounter); encounter = NULL;

	if (encounter_get_counter(ctx, COUNTERPATH, &encounter) \
			!= ENCOUNTER_OK) goto end;

	printf("Load counter from file: succeeded\n");

	if (encounter_decrypt(ctx, encounter, privK, &c) != ENCOUNTER_OK)
			goto end;

	printf("Crypto-counter decryption: succeeded\n");
	printf("Plaintext counter: %lld\n", c);

	if (encounter_inc(ctx, pubK, encounter, 8) != ENCOUNTER_OK) goto end;

	printf("Counter increment: succeeded\n");

	if (encounter_decrypt(ctx, encounter, privK, &c) != ENCOUNTER_OK)
			goto end;

	printf("Crypto-counter decryption: succeeded\n");
	printf("Plaintext counter: %lld\n", c);

	if (encounter_persist_counter(ctx, encounter, COUNTERPATH) != \
					ENCOUNTER_OK) goto end;

	printf("Persisting counter: succeeded\n");
#if 0

	encounter_dispose_counter(ctx, encounter); encounter = NULL;
	encounter_dispose_keyctx(ctx, pubK);   pubK = NULL;
	encounter_dispose_keyctx(ctx, privK); privK = NULL;

	if(encounter_keygen(ctx, EC_KEYTYPE_PAILLIER_PUBLIC, \
			KEYSIZE, &pubK, &privK) != ENCOUNTER_OK) goto end;

	printf("Keygen: succeeded\n");

	if(encounter_new_counter(ctx, pubK, &encounter) != ENCOUNTER_OK)
					goto end;

	printf("New counter: succeded\n");

	if(encounter_new_counter(ctx, pubK, &encounter) != ENCOUNTER_OK)
					goto end;

	printf("New counter: succeded\n");
#endif

	a++;

end:
	if (ctx) rc = encounter_error(ctx);
	if (keyset) encounter_dispose_keyset(ctx, keyset);
	if (keyset2) encounter_dispose_keyset(ctx, keyset2);
	if (encounter) encounter_dispose_counter(ctx, encounter);
	if (pubK) encounter_dispose_keyctx(ctx, pubK);
	if (privK) encounter_dispose_keyctx(ctx, privK);
	if (ctx) encounter_term(ctx);

	if (a < 2) goto start;
	return rc;

}
