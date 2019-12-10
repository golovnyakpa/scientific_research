#include <stdint.h>
#define KeyLen  (CRYPTO_KEYBYTES*8)

/* Deoxys high-level operations */
void deoxys_aead_encrypt(const uint8_t *ass_data, size_t ass_data_len, 
			             const uint8_t *message, size_t m_len, 
			             const uint8_t *key, 
			             const uint8_t *nonce, 
			             uint8_t *ciphertext, size_t *c_len);

int  deoxys_aead_decrypt(const uint8_t *ass_data, size_t ass_data_len, 
			             uint8_t *message, size_t *m_len, 
			             const uint8_t *key, 
			             const uint8_t *nonce, 
			             const uint8_t *ciphertext, size_t c_len);
