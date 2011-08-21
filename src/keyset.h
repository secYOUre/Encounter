#ifndef _ENCOUNTER_KEYSET_H_
#define _ENCOUNTER_KEYSET_H_

#include "encounter.h"
#include "encounter_priv.h"



/* TODO use __BEGIN_DECLS */

/** Create a keyset handle */
encounter_err_t encounter_keyset_create(encounter_t *, \
        encounter_keyset_t, const char *, const char *, ec_keyset_t **);

/** Dispose a keyset handle */
encounter_err_t encounter_keyset_dispose(encounter_t *, ec_keyset_t *);


#endif  /* _ENCOUNTER_KEYSET_H_ */
