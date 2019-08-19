#ifndef H__RIJNDAEL
#define H__RIJNDAEL

#include <qpdf/qpdf-config.h>
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

#include <gnutls/crypto.h>

void rijndaelInit(gnutls_cipher_hd_t * context, u8 * key,
  unsigned int keylen, const u8 cbc_block[16], unsigned int buf_size);
int rijndaelSetupEncrypt(uint32_t *rk, const unsigned char *key,
  int keybits);
int rijndaelSetupDecrypt(uint32_t *rk, const unsigned char *key,
  int keybits);
void rijndaelEncrypt(gnutls_cipher_hd_t * context, const u8 plaintext[16],
  u8 ciphertext[16], unsigned int buf_size);
void rijndaelDecrypt(gnutls_cipher_hd_t * context, const u8 ciphertext[16],
  u8 plaintext[16], unsigned int buf_size);
void rijndaelFinish(gnutls_cipher_hd_t * context);

#define KEYLENGTH(keybits) ((keybits)/8)
#define RKLENGTH(keybits)  ((keybits)/8+28)
#define NROUNDS(keybits)   ((keybits)/32+6)

#endif /* H__RIJNDAEL*/
