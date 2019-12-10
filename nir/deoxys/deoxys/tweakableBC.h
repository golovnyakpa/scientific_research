#include <stdint.h>

void aesTweakEncrypt(uint32_t tweakey_size, 
	                 const uint8_t pt[16], 
                     const uint8_t key[], 
                     uint8_t ct[16]);

void aesTweakDecrypt(uint32_t tweakey_size, 
	                 const uint8_t ct[16],
                     const uint8_t key[],
                     uint8_t pt[16]);
