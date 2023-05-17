/*
 * This is a simplified version of the pubkey.c unit test
 * that we will use as the victim calling the functions
 * of interest from the libgcrypt library.
 *
 * We run the victim from this test file because it's easier than writing a standalone C file.
 * The test function called above performs one signature of some fixed hashed data, with a "random" key.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../scutil/lotr.h"

#include "../src/gcrypt.h"

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                               } while (0)


/* Sample RSA keys, taken from basic.c.  */

static const char sample_private_key_1[] =
"(private-key\n"
" (openpgp-rsa\n"
"  (n #00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa"
      "2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291"
      "ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7"
      "891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea251#)\n"
"  (e #010001#)\n"
"  (d #046129F2489D71579BE0A75FE029BD6CDB574EBF57EA8A5B0FDA942CAB943B11"
      "7D7BB95E5D28875E0F9FC5FCC06A72F6D502464DABDED78EF6B716177B83D5BD"
      "C543DC5D3FED932E59F5897E92E6F58A0F33424106A3B6FA2CBF877510E4AC21"
      "C3EE47851E97D12996222AC3566D4CCB0B83D164074ABF7DE655FC2446DA1781#)\n"
"  (p #00e861b700e17e8afe6837e7512e35b6ca11d0ae47d8b85161c67baf64377213"
      "fe52d772f2035b3ca830af41d8a4120e1c1c70d12cc22f00d28d31dd48a8d424f1#)\n"
"  (q #00f7a7ca5367c661f8e62df34f0d05c10c88e5492348dd7bddc942c9a8f369f9"
      "35a07785d2db805215ed786e4285df1658eed3ce84f469b81b50d358407b4ad361#)\n"
"  (u #304559a9ead56d2309d203811a641bb1a09626bc8eb36fffa23c968ec5bd891e"
      "ebbafc73ae666e01ba7c8990bae06cc2bbe10b75e69fcacb353a6473079d8e9b#)\n"
" )\n"
")\n";

/* The same key as above but without p, q and u to test the non CRT case. */
static const char sample_private_key_1_1[] =
"(private-key\n"
" (openpgp-rsa\n"
"  (n #00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa"
      "2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291"
      "ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7"
      "891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea251#)\n"
"  (e #010001#)\n"
"  (d #046129F2489D71579BE0A75FE029BD6CDB574EBF57EA8A5B0FDA942CAB943B11"
      "7D7BB95E5D28875E0F9FC5FCC06A72F6D502464DABDED78EF6B716177B83D5BD"
      "C543DC5D3FED932E59F5897E92E6F58A0F33424106A3B6FA2CBF877510E4AC21"
      "C3EE47851E97D12996222AC3566D4CCB0B83D164074ABF7DE655FC2446DA1781#)\n"
" )\n"
")\n";

/* The same key as above but just without q to test the non CRT case.  This
   should fail. */
static const char sample_private_key_1_2[] =
"(private-key\n"
" (openpgp-rsa\n"
"  (n #00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa"
      "2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291"
      "ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7"
      "891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea251#)\n"
"  (e #010001#)\n"
"  (d #046129F2489D71579BE0A75FE029BD6CDB574EBF57EA8A5B0FDA942CAB943B11"
      "7D7BB95E5D28875E0F9FC5FCC06A72F6D502464DABDED78EF6B716177B83D5BD"
      "C543DC5D3FED932E59F5897E92E6F58A0F33424106A3B6FA2CBF877510E4AC21"
      "C3EE47851E97D12996222AC3566D4CCB0B83D164074ABF7DE655FC2446DA1781#)\n"
"  (p #00e861b700e17e8afe6837e7512e35b6ca11d0ae47d8b85161c67baf64377213"
      "fe52d772f2035b3ca830af41d8a4120e1c1c70d12cc22f00d28d31dd48a8d424f1#)\n"
"  (u #304559a9ead56d2309d203811a641bb1a09626bc8eb36fffa23c968ec5bd891e"
      "ebbafc73ae666e01ba7c8990bae06cc2bbe10b75e69fcacb353a6473079d8e9b#)\n"
" )\n"
")\n";

static const char sample_public_key_1[] =
"(public-key\n"
" (rsa\n"
"  (n #00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa"
      "2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291"
      "ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7"
      "891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea251#)\n"
"  (e #010001#)\n"
" )\n"
")\n";


static int verbose;

static void
die (const char *format, ...)
{
  va_list arg_ptr ;

  va_start( arg_ptr, format ) ;
  vfprintf (stderr, format, arg_ptr );
  va_end(arg_ptr);
  exit (1);
}


static void
check_keys_crypt (gcry_sexp_t pkey, gcry_sexp_t skey,
		  gcry_sexp_t plain0, gpg_err_code_t decrypt_fail_code)
{
  gcry_sexp_t plain1, cipher, l;
  gcry_mpi_t x0, x1;
  int rc;
  int have_flags;

  /* Extract data from plaintext.  */
  l = gcry_sexp_find_token (plain0, "value", 0);
  x0 = gcry_sexp_nth_mpi (l, 1, GCRYMPI_FMT_USG);

  /* Encrypt data.  */
  rc = gcry_pk_encrypt (&cipher, plain0, pkey);
  if (rc)
    die ("encryption failed: %s\n", gcry_strerror (rc));

  l = gcry_sexp_find_token (cipher, "flags", 0);
  have_flags = !!l;
  gcry_sexp_release (l);

  /*********************************************************/
  // From here we basically provide an on-demand decryption service
  // to the monitor by repeating the gcry_pk_decrypt operation
  printf("pin cpu in victim\n");
  
  printf("sched_getcpu = %d\n", sched_getcpu());
  //pin_cpu(6);   // 5 for the full flush; 6 for the L1/L2 only
  
  //cpu_set_t my_set;        /* Define your cpu_set bit mask. */
  //CPU_ZERO(&my_set);       /* Initialize it all to 0, i.e. no CPUs selected. */
  //CPU_SET(2, &my_set);     /* set the bit that represents core 7. */
 
  //sched_setaffinity(0, sizeof(cpu_set_t), &my_set); /* Set affinity of tihs process to */
                                                  /* the defined mask, i.e. only 7. */
  //if (sched_setaffinity(0, sizeof(cpu_set_t), &my_set) == -1) /* Set affinity of tihs process to the defined mask, i.e. only 7. */
  //    errExit("sched_setaffinity");
  //printf("sched_getcpu = %d\n", sched_getcpu());
  //printf("pin cpu in victim00\n");
  volatile struct sharestruct *mysharestruct = get_sharestruct();
  mysharestruct->iteration_of_interest_running = 0;
  mysharestruct->sign_requested = 0;
  mysharestruct->cleansing_mechanism = 2;

  fprintf(stderr, "GO\n");

  while(1) {

    // If a sign was requested
    if (mysharestruct->sign_requested) {

      // Wait a moment for the attacker to get ready
      wait_cycles(10000);

      // Start vulnerable RSA decryption code
      rc = gcry_pk_decrypt (&plain1, cipher, skey);
    }
  }

  /*********************************************************/

  gcry_sexp_release (cipher);
  if (rc)
    {
      if (decrypt_fail_code && gpg_err_code (rc) == decrypt_fail_code)
        return; /* This is the expected failure code.  */
      die ("decryption failed: %s\n", gcry_strerror (rc));
    }
}

static void
check_keys (gcry_sexp_t pkey, gcry_sexp_t skey, unsigned int nbits_data,
            gpg_err_code_t decrypt_fail_code)
{
  gcry_sexp_t plain;
  gcry_mpi_t x;
  int rc;

  /* Create plain text.  */
  x = gcry_mpi_new (nbits_data);
  gcry_mpi_randomize (x, nbits_data, GCRY_WEAK_RANDOM);

  rc = gcry_sexp_build (&plain, NULL,
                        "(data (flags raw no-blinding) (value %m))", x);
  if (rc)
    die ("converting data for encryption failed: %s\n",
	 gcry_strerror (rc));

  check_keys_crypt (pkey, skey, plain, decrypt_fail_code);

  gcry_sexp_release (plain);
}

static void
get_keys_sample (gcry_sexp_t *pkey, gcry_sexp_t *skey, int secret_variant)
{
  gcry_sexp_t pub_key, sec_key;
  int rc;
  static const char *secret;


  switch (secret_variant)
    {
    case 0: secret = sample_private_key_1; break;
    case 1: secret = sample_private_key_1_1; break;
    case 2: secret = sample_private_key_1_2; break;
    default: die ("BUG\n");
    }

  rc = gcry_sexp_sscan (&pub_key, NULL, sample_public_key_1,
			strlen (sample_public_key_1));
  if (!rc)
    rc = gcry_sexp_sscan (&sec_key, NULL, secret, strlen (secret));
  if (rc)
    die ("converting sample keys failed: %s\n", gcry_strerror (rc));

  *pkey = pub_key;
  *skey = sec_key;
}


static void
check_run (void)
{
  gpg_error_t err;
  gcry_sexp_t pkey, skey;
  int variant = 1;

  if (verbose)
    fprintf (stderr, "Checking sample key (%d).\n", variant);

  get_keys_sample (&pkey, &skey, variant);

  /* Check gcry_pk_testkey which requires all elements.  */
  err = gcry_pk_testkey (skey);
  if ((variant == 0 && err)
      || (variant > 0 && gpg_err_code (err) != GPG_ERR_NO_OBJ))
      die ("gcry_pk_testkey failed: %s\n", gpg_strerror (err));

  /* Run the usual check but expect an error from variant 2.  */
  check_keys (pkey, skey, 800, variant == 2? GPG_ERR_NO_OBJ : 0);
  gcry_sexp_release (pkey);
  gcry_sexp_release (skey);
}


int
main (int argc, char **argv)
{
  
  int debug = 0;
  printf("start of victim\n");

  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;
  else if (argc > 1 && !strcmp (argv[1], "--debug"))
    {
      verbose = 2;
      debug = 1;
    }

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);
  /* No valuable keys are create, so we can speed up our RNG. */
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

  printf("before check run\n");
  check_run ();
  printf("after check run\n");
  return 0;
}
