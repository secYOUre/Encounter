#ifndef _ENCOUNTER_UTILS_H_
#define _ENCOUNTER_UTILS_H_

#include <assert.h>

#include "encounter.h"
#include "encounter_priv.h"


#define NOTREACHED	1


/* TODO use __BEGIN_DECLS */

int encounter_set_error (encounter_t *ctx, encounter_err_t rc, \
						const char *fmt, ...);
void debug_print_buf (const char *label, const uint8_t *b, size_t b_sz);


#endif  /* _ENCOUNTER_UTILS_H_ */
