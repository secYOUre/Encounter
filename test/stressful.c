#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "encounter.h"


#define COUNTERPATH	"./counter.txt"
#define PUBLICKEYPATH	"./publickey.txt"
#define PRIVATEKEYPATH	"./privatekey.txt"

#define	KEYSIZE	1024

#define CYCLES	300

#define TIMER_SAMPLE_CNT (10)


/************** Timing routine (for performance measurements) ***********/
/* By Doug Whiting */
/* unfortunately, this is generally assembly code and not very portable */
#if defined(_M_IX86) || defined(__i386) || defined(_i386) || defined(__i386__) || defined(i386) || \
    defined(_X86_)   || defined(__x86_64__) || defined(_M_X64) || defined(__x86_64)
#define _Is_X86_    1
#endif

#if  defined(_Is_X86_) && (!defined(__STRICT_ANSI__)) && (defined(__GNUC__) || !  defined(__STDC__)) && \
    (defined(__BORLANDC__) || defined(_MSC_VER) || defined(__MINGW_H) || defined (__GNUC__))
#define HI_RES_CLK_OK         1          /* it's ok to use RDTSC opcode */

#if defined(_MSC_VER) // && defined(_M_X64)
#include <intrin.h>
#pragma intrinsic(__rdtsc)         /* use MSVC rdtsc call where defined */
#endif

#endif

#define HI_RES_CLK_OK	1


uint32_t HiResTime(void)  /* return the current value of time stamp counter */
    {
#if defined(HI_RES_CLK_OK)
    uint32_t x[2];
#if   defined(__BORLANDC__)
#define COMPILER_ID "BCC"
    __emit__(0x0F,0x31);           /* RDTSC instruction */
    _asm { mov x[0],eax };
#elif defined(_MSC_VER)
#define COMPILER_ID "MSC"
#if defined(_MSC_VER) // && defined(_M_X64)
    x[0] = (uint32_t) __rdtsc();
#else
    _asm { _emit 0fh }; _asm { _emit 031h };
    _asm { mov x[0],eax };
#endif
#elif defined(__MINGW_H) || defined(__GNUC__)
#define COMPILER_ID "GCC"
    __asm volatile("rdtsc" : "=a"(x[0]), "=d"(x[1]));
#else
#error  "HI_RES_CLK_OK -- but no assembler code for this platform (?)"
#endif
    return x[0];
#else
    /* avoid annoying MSVC 9.0 compiler warning #4720 in ANSI mode! */
#if (!defined(_MSC_VER)) || (!defined(__STDC__)) || (_MSC_VER < 1300)
#error "No support for RDTSC on this CPU platform\n"
#endif
    return 0;
#endif /* defined(HI_RES_CLK_OK) */
    }


uint32_t calibrate()
{
    uint32_t dtMin = 0xFFFFFFFF;        /* big number to start */
    uint32_t t0,t1,i;

    for (i=0;i < TIMER_SAMPLE_CNT;i++)  /* calibrate the overhead for measuring
time */
        {
        t0 = HiResTime();
        t1 = HiResTime();
        if (dtMin > t1-t0)              /* keep only the minimum time */
            dtMin = t1-t0;
        }
    return dtMin;
}

int main(int argc, char *argv[]) 
{
	encounter_err_t rc = ENCOUNTER_OK;
	encounter_t *ctx = NULL;
	ec_keyctx_t *pubK = NULL;
	ec_keyctx_t *privK = NULL;
	ec_count_t  *encounter = NULL;
	ec_keyset_t *keyset = NULL, *keyset2 = NULL;
	unsigned long long int c = 0;
	uint32_t calibration;
	uint32_t tmin = 0xffffffff;	
	uint32_t t0, t1, i;

	/* Initialize Encounter */
	rc = encounter_init(0, &ctx);
	if (rc != ENCOUNTER_OK) goto end;

	printf("Init: succeeded\n");

	if(encounter_keygen(ctx, EC_KEYTYPE_PAILLIER_PUBLIC, \
			KEYSIZE, &pubK, &privK) != ENCOUNTER_OK) goto end;

	printf("Keygen: succeeded\n");

	if(encounter_new_counter(ctx, pubK, &encounter) != ENCOUNTER_OK)
					goto end;

	calibration = calibrate();

	t0 = HiResTime();	
	encounter_inc(ctx, pubK, encounter, CYCLES);
	t1 = HiResTime();	
	if (tmin > (t1-t0-calibration)) tmin = t1-t0 - calibration;


	printf("Counter increment: succeeded\n");
	printf("Cycles per %d counter increments: %ld\n", CYCLES, tmin);

	tmin = 0xffffffff;

	for (i=0; i < CYCLES; ++i) {
		t0 = HiResTime();	
		encounter_inc(ctx, pubK, encounter, 1);
		t1 = HiResTime();	
		if (tmin > (t1-t0-calibration)) tmin = t1-t0 - calibration;

	}
	printf("Counter increment: succeeded\n");
	printf("Cycles per counter increments: %ld\n", tmin);


	if (encounter_decrypt(ctx, encounter, privK, &c) != ENCOUNTER_OK)
			goto end;

	printf("Crypto-counter decryption: succeeded\n");
	printf("Plaintext counter: %lld\n", c);


end:
	if (ctx) rc = encounter_error(ctx);
	if (keyset) encounter_dispose_keyset(ctx, keyset);
	if (keyset2) encounter_dispose_keyset(ctx, keyset2);
	if (encounter) encounter_dispose_counter(ctx, encounter);
	if (pubK) encounter_dispose_keyctx(ctx, pubK);
	if (privK) encounter_dispose_keyctx(ctx, privK);
	if (ctx) encounter_term(ctx);

	return rc;

}
