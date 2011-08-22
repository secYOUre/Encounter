#ifndef _ENCOUNTER_KEYSTORE_PLAIN_DRV_H_
#define _ENCOUNTER_KEYSTORE_PLAIN_DRV_H_

#include <unistd.h>
#include <sys/time.h>

#include "encounter.h"
#include "encounter_priv.h"


/* TODO use __BEGIN_DECLS */

encounter_err_t encounter_plain_init_store(encounter_t *);

encounter_err_t encounter_plain_storekey(encounter_t *, ec_keyctx_t *, \
			 const char *);

encounter_err_t encounter_plain_loadPublicKey(encounter_t *, \
			const char *, ec_keyctx_t **);

encounter_err_t encounter_plain_loadPrivKey(encounter_t *, \
		const char *, const char *, ec_keyctx_t **);

encounter_err_t encounter_plain_persist_cnt(encounter_t *, \
					ec_count_t *, const char *);

encounter_err_t encounter_plain_get_counter(encounter_t *, \
				const char *, ec_count_t **);

encounter_err_t encounter_plain_term_store(encounter_t *);

#endif  /* _ENCOUNTER_KEYSTORE_PLAIN_DRV_H_ */
