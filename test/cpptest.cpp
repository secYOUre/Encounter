#include <iostream>

#include "encounter.h"

using namespace std;


#define COUNTERPATH	"./counter.txt"
#define PUBLICKEYPATH	"./publickey.txt"

int main()
{
        /** Testing Encounter from C++ */

	encounter_err_t rc = ENCOUNTER_OK;
	encounter_t *ctx = NULL;
	ec_keyctx_t *pubK = NULL;
	ec_count_t  *encounter = NULL;
	ec_keyset_t *keyset = NULL;

	/* Initialize Encounter */
	rc = encounter_init(0, &ctx);
	if (rc != ENCOUNTER_OK) return rc;

        std::cout << "Init: succeded\n";

        /* Create a keyset */
	rc = encounter_create_keyset(ctx, \
                EC_KEYSET_PLAIN, PUBLICKEYPATH, NULL, &keyset);
        if (rc != ENCOUNTER_OK) goto end;

	std::cout << "Create keyset: succeded\n";

        /* Load the public key */
	rc = encounter_get_publicKey(ctx, keyset, &pubK);
        if (rc != ENCOUNTER_OK) goto end;

	std::cout << "Retriving public key from keyset: succeeded\n";

        /* Load the counter from file */
	rc = encounter_get_counter(ctx, COUNTERPATH, &encounter);
	if (rc != ENCOUNTER_OK) goto end;

	std::cout << "Load counter from file: succeeded\n";

        /* Increment the counter */
	rc = encounter_inc(ctx, pubK, encounter, 8) ;
	if (rc != ENCOUNTER_OK) goto end;

	std::cout << "Counter increment: succeeded\n";

end:
        /* Dispose the resources */
	if (ctx) rc = encounter_error(ctx);
	if (keyset) encounter_dispose_keyset(ctx, keyset);
	if (encounter) encounter_dispose_counter(ctx, encounter);
	if (pubK) encounter_dispose_keyctx(ctx, pubK);
	if (ctx) encounter_term(ctx);

	return rc;
}
