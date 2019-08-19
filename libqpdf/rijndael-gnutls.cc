#include <gnutls/crypto.h>
#include <qpdf/QUtil.h>
#include "qpdf/rijndael-gnutls.h"

typedef uint32_t u32;
typedef unsigned char u8;

/**
 * Init cryptographic context
 */
void rijndaelInit(gnutls_cipher_hd_t * ctx, u8 * key, unsigned int keylen,
                  const u8 cbc_block[16], unsigned int buf_size)
{
    int ret;
    gnutls_cipher_algorithm_t alg;
    gnutls_datum_t cipher_key, iv;

    cipher_key.data = key;

    switch(keylen) {
      case 16:
        alg = GNUTLS_CIPHER_AES_128_CBC;
        break;
      case 32:
        alg = GNUTLS_CIPHER_AES_256_CBC;
        break;
      case 24:
        alg = GNUTLS_CIPHER_AES_192_CBC;
        break;
      default:
        alg = GNUTLS_CIPHER_AES_128_CBC;
        break;
    }

    cipher_key.size = gnutls_cipher_get_key_size(alg);

    iv.data = cbc_block;
    iv.size = buf_size;

    ret = gnutls_cipher_init(ctx, alg, &cipher_key, &iv);
    if (ret < 0)
    {
        QUtil::throw_system_error(
            std::string("GNU TLS: AES error: ") + std::string(gnutls_strerror(ret)));
        return;
    }
}

/**
 * Encrypt string by AES by GNU TLS.
 */
void rijndaelEncrypt(gnutls_cipher_hd_t * ctx,
                     const u8 plaintext[16],
                     u8 ciphertext[16],
                     unsigned int buf_size)
{
    gnutls_cipher_encrypt2(*ctx, plaintext, buf_size, ciphertext, buf_size);
}

/**
 * Decrypt string by AES by GNU TLS.
 */
void rijndaelDecrypt(gnutls_cipher_hd_t * ctx,
                     const u8 ciphertext[16],
                     u8 plaintext[16],
                     unsigned int buf_size)
{
    gnutls_cipher_decrypt2(*ctx, ciphertext, buf_size, plaintext, buf_size);
}

/**
 * Finish cryptography context
 */
void rijndaelFinish(gnutls_cipher_hd_t * ctx)
{
    gnutls_cipher_deinit(*ctx);
}
