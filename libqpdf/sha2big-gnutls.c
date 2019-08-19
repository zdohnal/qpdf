#include <gnutls/crypto.h>
#include <stdio.h>
#include "sph/sph_sha2.h"


/* see sph_sha3.h */
void
sph_sha384_init(void * cc)
{
	int ret;

	ret = gnutls_hash_init(cc, GNUTLS_DIG_SHA384);
	if (ret < 0)
	{
		fprintf(stderr, "GNU TLS: SHA384 error: %s\n", gnutls_strerror(ret));
		cc = NULL;
	}
}

/* see sph_sha3.h */
void
sph_sha384_close(void * cc, void *dst)
{
	if (cc != NULL && dst != NULL)
		gnutls_hash_deinit(*(cc), dst);
}

/* see sph_sha3.h */
void
sph_sha384(void * cc, const void * data, size_t len)
{
	if (cc != NULL && data != NULL && len > 0)
		gnutls_hash(*(cc), data, len);
}

/* see sph_sha3.h */
void
sph_sha512_init(void * cc)
{
	int ret;

	gnutls_hash_init(cc, GNUTLS_DIG_SHA512);
	if (ret < 0)
	{
		fprintf(stderr, "GNU TLS: SHA512 error: %s\n", gnutls_strerror(ret));
		cc = NULL;
	}
}

/* see sph_sha3.h */
void
sph_sha512_close(void * cc, void * dst)
{
	if (cc != NULL && dst != NULL)
		gnutls_hash_deinit(*(cc), dst);
}

/* see sph_sha3.h */
void
sph_sha512(void * cc, const void * data, size_t len)
{
	if (cc != NULL && data != NULL && len > 0)
		gnutls_hash(*(cc), data, len);
}
