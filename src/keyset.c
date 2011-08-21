#define	_GNU_SOURCE

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>

#include "encounter.h"
#include "encounter_priv.h"
#include "keyset.h"
#include "utils.h"



/** Create a keyset handle */
encounter_err_t encounter_keyset_create(encounter_t *ctx, 
        encounter_keyset_t type, const char *path, \
	const char *passphrase, ec_keyset_t **keyset) 
{
	__ENCOUNTER_SANITYCHECK_KEYSET_TYPE(type, ENCOUNTER_ERR_PARAM);
	if (!path || !keyset || (strlen(path) > (ENCOUNTER_FILENAME_MAX))) {
		encounter_set_error(ctx, ENCOUNTER_ERR_PARAM, "");
		return ctx->rc;
	}
		
	*keyset = calloc(1, sizeof **keyset);
	if (*keyset) {
		(*keyset)->type = type;
		(*keyset)->s.path = strdup(path);

		ctx->rc = ENCOUNTER_OK;
	} else
		encounter_set_error(ctx, ENCOUNTER_ERR_MEM, \
						"calloc failed");

	return ctx->rc;
}

/** Dispose a keyset handle */
encounter_err_t encounter_keyset_dispose(encounter_t *ctx, \
					ec_keyset_t *keyset)
{
	if (keyset) {
		free((void *) keyset->s.path);
		memset(keyset, 0, sizeof *keyset);

		free(keyset);
		ctx->rc = ENCOUNTER_OK;
	} else  encounter_set_error(ctx, ENCOUNTER_ERR_PARAM, "NULL param");

	return ctx->rc;
}

