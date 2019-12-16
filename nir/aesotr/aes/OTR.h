#include "api.h"

typedef unsigned char	uint8;
typedef unsigned int	uint32;

#define BLOCK 16
#define DBLOCK 32
#define	TAG_MATCH	0
#define	TAG_UNMATCH	1

#define KeyLen  (CRYPTO_KEYBYTES*8)

/* Macro for AD processing */
#define Para 0
#define Seri 1
#define ADP (Seri)

/* OTR Core Functions */
extern int Setup(const unsigned char *skey);
extern int AE_Encrypt(
		  const unsigned char *nonce,
		  unsigned int nonce_len,
		  const unsigned char *plaintext,
		  unsigned int pl_len,
		  const unsigned char *header,
		  unsigned int h_len,
		  unsigned int t_len,
		  unsigned char *ciphertext,
		  unsigned char *tag); //output, ciphertext and tag
extern int AE_Decrypt(
		  const unsigned char *nonce,
		  unsigned int nonce_len,
		  const unsigned char *ciphertext,
		  unsigned int ci_len,
		  const unsigned char *header,
		  unsigned int h_len,
		  unsigned int t_len,
  		  const unsigned char *tag,
		  unsigned char *plaintext);
