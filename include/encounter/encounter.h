#ifndef _ENCOUNTER_H_
#define _ENCOUNTER_H_

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

struct encounter_s;   /* Forward decl. */
struct ec_keyctx_s;
struct ec_count_s;
struct ec_keyset_s;


/* These are defined only in encounter.h, and are used for conditional
 * compiles. */
#define	ENCOUNTER_LIB_VER_MAJOR	0
#define ENCOUNTER_LIB_VER_MINOR	2
#define ENCOUNTER_LIB_VER_PATCH	6

/* x.y.z, where x=major, y=minor, z=patch */
#define	ENCOUNTER_LIB_VERSION	"0.2.6"



/**
 *  \addtogroup encounter
 *  \{
 */

/*
 * Maximum length of various identifiers.
 */ 
#ifndef ENCOUNTER_FILENAME_MAX
  /** Maximum length of the CA filename string. */
  #define ENCOUNTER_FILENAME_MAX	(FILENAME_MAX + 1)
#endif  /* !ENCOUNTER_CAFILE_MAX */

/* Other identifiers to be defined */


/* Error codes. */
typedef enum
{
    ENCOUNTER_OK = 0,
    /**< As expected. */

    ENCOUNTER_ERR_MEM,
    /**< Memory exhaustion. */

    ENCOUNTER_ERR_CRYPTO,
    /**< Error is coming from the crypto toolkit.  */

    ENCOUNTER_ERR_STORE,
    /**< Error is coming from the storage layer.  */

    ENCOUNTER_ERR_PARAM,
    /**< Error is coming from a supplied parameter.  */

    ENCOUNTER_ERR_OS,
    /**< Some syscall has failed (see ::encounter_err() for details.) */

    ENCOUNTER_ERR_DATA,
    /**< Corrupted or unavailable data */

    ENCOUNTER_ERR_IMPL,
    /**< Hit an implementation limit. */

} encounter_err_t;


/** Encounter runtime context.  */
typedef struct encounter_s encounter_t;

/** Encounter key context */
typedef struct ec_keyctx_s ec_keyctx_t;

/** Encounter cryptographic counter */
typedef struct ec_count_s ec_count_t;

/** Encounter keyset */
typedef struct ec_keyset_s ec_keyset_t;


/** Encounter Key Types */
typedef enum {
	EC_KEYTYPE_NONE,		/* No key-type code */
        EC_KEYTYPE_PAILLIER_PUBLIC,	/* Paillier public-key */
        EC_KEYTYPE_PAILLIER_PRIVATE,	/* Paillier private-key */
	EC_KEYTYPE_LAST			/* Last possible key-type code */
} encounter_key_t;


/** Encounter Keyset Types */
typedef enum {
	EC_KEYSET_NONE,			/* No keyset code  */
	EC_KEYSET_PLAIN,		/* Plaintext keyset */
	EC_KEYSET_SOFTTOKEN,		/* ASN.1 softtoken */
	EC_KEYSET_LAST			/* Last possible keyset code */
} encounter_keyset_t;



/* __BEGIN_DECLS should be used at the beginning of your declarations,
   so that C++ compilers don't mangle their names.  Use __END_DECLS at
   the end of C declarations. */
#undef __BEGIN_DECLS
#undef __END_DECLS
#ifdef __cplusplus
# define __BEGIN_DECLS extern "C" {
# define __END_DECLS }
#else
# define __BEGIN_DECLS /* empty */
# define __END_DECLS /* empty */
#endif

/* __P is a macro used to wrap function prototypes, so that compilers
   that don't understand ANSI C prototypes still work, and ANSI C
   compilers can issue warnings about type mismatches. */
#undef __P
#if defined (__STDC__) || defined (_AIX) || (defined (__mips) && defined (_SYSTYPE_SVR4)) || defined(WIN32) || defined(__cplusplus)
 # define __P(protos)    protos
#else
 # define __P(protos)    ()
#endif


/**
 * The following defines are based on cryptlib.h by Peter Gutmann --
 * Define function types depending on whether the code is included via
 * the internal or external headers. This is needed to support DLLs and
 * other library types 
 */

#if ( defined( WIN32 ) || defined( _WIN32 ) || defined( __WIN32__ ) || \
       defined( _WIN32_WCE ) ) && !( defined( STATIC_LIB ) || defined(_SCCTK))
  #define EC_PTR *                          /* General pointer */
  #if defined( _WIN32_WCE )
        #define EC_CHR wchar_t
  #else
        #define EC_CHR char
  #endif /* WinCE vs. Win32 */
  #define EC_STR EC_CHR *

  #if defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x500 )
        #ifdef _ENCOUNTER_PRIV_H_
	  /* BC++ DLL export ret. val */
          #define ENCOUNTER_RET encounter_err_t		_export _stdcall 
        #else
	  /* BC++ DLL import ret. val. */
          #define ENCOUNTER_RET encounter_err_t		_import _stdcall
        #endif /* __ENCOUNTER_PRIV_H_ */
  #else
        #ifdef _ENCOUNTER_PRIV_H_
	  /* DLL export ret. val. */
          #define ENCOUNTER_RET __declspec( dllexport ) encounter_ret_t	 __stdcall
        #else
	  /* DLL import ret. val. */
          #define ENCOUNTER_RET __declspec( dllimport ) encounter_ret_t	__stdcall 
        #endif /* _ENCOUNTER_PRIV_H_ */
  #endif /* BC++ vs.VC++ DLL functions */
#elif defined( _WINDOWS ) && !defined( STATIC_LIB )
  #define EC_PTR FAR *                    /* DLL pointer */
  #define EC_CHR char
  #define EC_STR EC_CHR FAR *      /* DLL string pointer */
  #define ENCOUNTER_RET encounter_err_t FAR PASCAL _export  /* DLL ret. val */
#elif defined( __BEOS__ )
/* #include <BeBuild.h>                         // _EXPORT/_IMPORT defines */
  #define EC_PTR *
  #define EC_CHR char
  #define EC_STR EC_CHR *
  #ifdef _STATIC_LINKING
        #define ENCOUNTER_RET encounter_err_t
  #else
        #ifdef _ENCOUNTER_PRIV_H_
	  /* Shared lib export return value */
          #define ENCOUNTER_RET __declspec( dllexport ) encounter_err_t 
        #else
	  /* Shared lib import return value */
          #define ENCOUNTER_RET __declspec( dllimport ) encounter_err_t
        #endif /* _ENCOUNTER_PRIV_H_ */
  #endif /* Static vs. shared lib */
#elif defined( __SYMBIAN32__ )
  #ifdef _ENCOUNTER_PRIV_H_
	/* DLL export ret. val */
        #define ENCOUNTER_RET   EXPORT_C     
  #else
	/* DLL import ret. val */
        #define ENCOUNTER_RET   IMPORT_C  
  #endif /* _ENCOUNTER_PRIV_H_ */
#else
  #define EC_PTR *
  #define EC_CHR char
  #define EC_STR EC_CHR *
  #define ENCOUNTER_RET encounter_err_t
#endif /* Windows vs.everything else function types */

/* Symbolic defines to make it clearer how the function parameters behave */

#define EC_IN            const      /* Input-only */
#define EC_IN_OPT        const      /* Input-only, may be NULL */
#define EC_OUT                      /* Output-only */
#define EC_OUT_OPT                  /* Output-only, may be NULL */
#define EC_INOUT                    /* Modified in-place */

/* Additional defines for compilers that provide extended function and
   function-parameter checking */

#if defined( __GNUC__ ) && ( __GNUC__ >= 4 )
  #define EC_CHECK_RETVAL     __attribute__(( warn_unused_result ))
  #ifdef _ENCOUNTER_PRIV_H_
   /* Too dangerous to use inside encounter */
   #define EC_NONNULL_ARG( argIndex )
  #else
   #define EC_NONNULL_ARG( argIndex ) __attribute__(( nonnull argIndex))
  #endif /* _ENCOUNTER_PRIV_H */
#elif defined( _MSC_VER ) && defined( _PREFAST_ )
  #define EC_CHECK_RETVAL                __checkReturn
  #define EC_NONNULL_ARG( argIndex )
  #undef EC_IN_OPT
  #define EC_IN_OPT                      __in_opt const
  #undef EC_OUT_OPT
  #define EC_OUT_OPT                     __out_opt
  #undef EC_INOUT
  #define EC_INOUT                       __inout
#else
  #define EC_CHECK_RETVAL
  #define EC_NONNULL_ARG( argIndex )
#endif /* Compiler-specific annotations */



__BEGIN_DECLS

/** Create and configure a new Encounter context. 
  * This will need to be supplied as the first parameter of each
  * Encounter API */
EC_CHECK_RETVAL EC_NONNULL_ARG( (2) ) \
ENCOUNTER_RET encounter_init __P((const unsigned int, encounter_t **));

/** Return last errno */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1) ) \
ENCOUNTER_RET encounter_error __P((encounter_t *));

/** Generate a keypair according to the scheme and size selected 
 * respectively by the second and third parametes */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 4, 5) ) \
ENCOUNTER_RET encounter_keygen __P((encounter_t *, encounter_key_t, \
			unsigned int, ec_keyctx_t **, ec_keyctx_t **));

/** Accepts a key context and returns a new cryptographic cnt handle */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2, 3) ) \
ENCOUNTER_RET encounter_new_counter __P((encounter_t *, \
					ec_keyctx_t *, ec_count_t **));

/** Dispose the cryptographic counter referenced by the 2nd parameter */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2) )\
ENCOUNTER_RET encounter_dispose_counter __P((encounter_t *, \
							ec_count_t *));

/** Increment the cryptographic counter by the amount in a,
  * without first decrypting it. */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2, 3) )\
ENCOUNTER_RET encounter_inc __P((encounter_t *, ec_keyctx_t *, \
				ec_count_t *, const unsigned int));

/** Decrement the cryptographic counter by the amount in a,
  * without first decrypting it. */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2, 3) )\
ENCOUNTER_RET encounter_dec __P((encounter_t *, ec_keyctx_t *, \
				ec_count_t *, const unsigned int));

/** Touch the crypto counter by probabilistically re-rencrypting it.
  * The plaintext counter is not affected */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2, 3) )\
ENCOUNTER_RET encounter_touch __P((encounter_t *, ec_keyctx_t *, \
							ec_count_t *));

/** Adds two cryptographic counters placing the result in the first one
  * without first decrypting them. */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2, 3, 4) )\
ENCOUNTER_RET encounter_add __P((encounter_t *, ec_keyctx_t *, \
					ec_count_t *, ec_count_t *));

/** Subtracts two cryptographic counters placing the result in the first one
  * without first decrypting them. */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2, 3, 4) )\
ENCOUNTER_RET encounter_sub __P((encounter_t *, ec_keyctx_t *, \
					ec_count_t *, ec_count_t *));

/** Multiply a cryptographic counters by a given quantity
  * without first decrypting it. */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2, 3 ) )\
ENCOUNTER_RET encounter_mul __P((encounter_t *, ec_keyctx_t *, \
				ec_count_t *, const unsigned int));

/** Decrypt the cryptographic counter, returning the plaintext 
  * Accepts the handles of the cryptographic counter and private key */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2, 3, 4) )\
ENCOUNTER_RET encounter_decrypt __P((encounter_t *, ec_count_t *, \
			ec_keyctx_t *, unsigned long long int *));

/** Dispose the cryptographic counter referenced by the handle */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2) )\
ENCOUNTER_RET encounter_dispose_keyctx __P((encounter_t *, \
							ec_keyctx_t *));


/** Add a public key to keyset */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2, 3) )\
ENCOUNTER_RET encounter_add_publicKey __P((encounter_t *, \
					ec_keyctx_t *,  ec_keyset_t *));

/** Add a private key to keyset */
/* To date, no keyset encryption mechanism is supported by the current
 * keystore mechanisms. The fourth parameter must be NULL */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2, 3 ) )\
ENCOUNTER_RET encounter_add_privateKey __P((encounter_t *, \
			ec_keyctx_t *,  ec_keyset_t *, const char *));

/** Get a public key from a keyset */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2, 3 ) )\
ENCOUNTER_RET	encounter_get_publicKey __P((encounter_t *, \
			ec_keyset_t *, ec_keyctx_t **));

/** Get a private key from a keyset */
/* To date, no keyset encryption mechanism is supported by the current
 * keystore mechanisms. The third parameter must be NULL */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2, 4 ) )\
ENCOUNTER_RET	encounter_get_privateKey __P((encounter_t *, \
			ec_keyset_t *, const char *, ec_keyctx_t **));

/** Persist a cryptographic counter to a file */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2, 3 ) )\
ENCOUNTER_RET encounter_persist_counter __P((encounter_t *, \
					ec_count_t *, const char *));

/** Get a cryptographic counter from a file */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2, 3 ) )\
ENCOUNTER_RET encounter_get_counter __P((encounter_t *, \
					const char *, ec_count_t **));

/** Create a keyset handle */
/* To date, no keyset encryption mechanism is supported by the current
 * keystore mechanisms. The fourth parameter must be NULL */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 3, 5 ) )\
ENCOUNTER_RET encounter_create_keyset __P((encounter_t *,\
      encounter_keyset_t,  const char *, const char *, ec_keyset_t **));

/** Dispose a keyset handle */
EC_CHECK_RETVAL EC_NONNULL_ARG( (1, 2) )\
ENCOUNTER_RET encounter_dispose_keyset __P((encounter_t *, \
						ec_keyset_t *));

/** Dispose the supplied Encounter context. */
void encounter_term __P((encounter_t *ctx));

/**
 *  \}
 */ 

__END_DECLS

#endif  /* !_ENCOUNTER_H_ */
