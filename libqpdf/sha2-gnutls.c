#include <gnutls/crypto.h>
#include <stdio.h>
#include "sph/sph_sha2_gnutls.h"


/* see sph_sha2.h */
void
sph_sha256_init(void * cc)
{
	int ret;

	ret = gnutls_hash_init(cc, GNUTLS_DIG_SHA256);
	if (ret < 0)
	{
		fprintf(stderr, "GNU TLS: SHA256 error : %s\n", gnutls_strerror(ret));
		cc = NULL;
	}
}

/* see sph_sha2.h */
void
sph_sha256_close(void * cc, void *dst)
{
	if (cc != NULL)
		gnutls_hash_deinit(*(cc), dst);
}

/* see sph_sha2.h */
void sph_sha256(void * cc, const void * data, size_t len)
{
	if (cc != NULL && data != NULL && len > 0)
		gnutls_hash(*(cc), data, len);
}
