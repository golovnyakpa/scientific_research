#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
//#include "crypto_aead.h"
//#include <openssl/aes.h>
typedef unsigned char u8;
//#include "aes_round_10.h"    
#include "module.h"
#include <time.h>
#include "api.h"
#define KeyLen  (CRYPTO_KEYBYTES*8)

extern void kuz_encrypt_block(void *blk, void *cblk);
extern void kuz_decrypt_block(void *blk, void *cblk);
extern void kuz_set_encrypt_key( const unsigned char *key);

static void process_AD(
	block W, block Delta_1, const block npub, block param, 
	const u8 *ad, u64 adlen) {	

	block Delta_2, blk, result;
	u8 Is_Final = 0, ozs[16];
	int i; for(i=1; i<16; i++){ozs[i]=0x00;} ozs[0] = 0x80; 

	

	/* ===== make the first block blk based on npub and param ===== */
	load_block(blk, npub, param, 8, 8);
	
	while(1){ 
		
		/* ============= Process the current Block ==================== */
		process_block(Delta_1, Delta_2, result, blk, W, 1, Is_Final, ENCRYPT, AD);
				
		/* === Compute the next Block and updating the pointers and counters ===*/
		if(adlen==0) break; 
		
		else if(adlen <= 16) {
			load_block(blk, ad, ozs, adlen, 16-adlen); 
			if(adlen != 16) Is_Final = 1;
			adlen = 0; 
		}

		else {load_block(blk, ad, ozs, 16, 0); ad +=16; adlen -=16;}
	}

}

/* ===================   COLM_0 Authenticated Encryption Function =================== */

int crypto_aead_encrypt(
unsigned char *c,unsigned long long *clen,
const unsigned char *m,unsigned long long mlen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *nsec,
const unsigned char *npub,
const unsigned char *k
)
{
	u8 param[]={0,0,0,0,0,0,0,0};
	block L, W, Delta_0, Delta_1, Delta_2, blk, result, CS;
	int i; u8 zeroes[16], ozs[16], blen = 16, Is_Final = 0, Is_complete =1;
	for(i=0; i<16; i++)	{zeroes[i]=0x00;}   	
	for(i=1; i<16; i++)	{ozs[i]=0x00;} ozs[0] = 0x80; 	

	*clen = mlen + 16; 

	key_schedule(k);
    // KeySchedule(KeyLen, 0, k);
    //kuz_set_encrypt_key(k);
	/* ==========  Generate the Masks =========== */
	//AES(ENCRYPT, L, zeroes, &aes_key1);
    //Encryption(KeyLen, zeroes, L);
    kuz_encrypt_block(zeroes, L);
	mult_3(Delta_0, L);
	mult_inv2(Delta_0, Delta_0);

	copy_block(Delta_1, L);
	//mult_inv2(Delta_1, L); 	

	mult_3(Delta_2, L); 
	mult_3(Delta_2, Delta_2); 
	//mult_inv2(Delta_2, Delta_2);

	/* ======  Process Associated Data ======== */
	for(i=0; i<16; i++)
		W[i]=0x00;
	process_AD(W, Delta_0, npub, param, ad, adlen);
	Is_Final = 0;

	/* ================  Process Successive Message Blocks ==================== */


	/* ====== Process the first Message block ===== */

	if(mlen < 16){ Is_complete = 0; Is_Final = 1; blen = mlen; }
	if(mlen == 16){ Is_Final = 1;}
	// if(mlen <= 16) { blen = 8 + mlen; }
	//load_block(blk, m, ozs, mlen, 16-mlen); copy_block(CS, blk); 
	load_block(blk, m, ozs, blen, 0); copy_block(CS, blk);
	process_block(Delta_1, Delta_2, result, blk, W, Is_complete, Is_Final, ENCRYPT,  MESSAGE);
	store_bytes(c, result, 0, 15); c +=16;
	if(mlen >= 16)  {mlen -= 16; m +=16;}
	else mlen = 0;

	/* ============= Process Message blocks ================== */
	while(mlen > 0){
		if(mlen >= 16){
			load_block(blk, m, ozs, 16, 0); 
			if(mlen == 16){ Is_Final = 1; xor_block(blk, CS, blk); }
			else xor_block(CS, CS, blk);
			blen = 16; mlen -= 16; m+=16; 
		}
		else 	{Is_complete = 0; Is_Final = 1; blen = mlen; mlen = 0; 
			load_block(blk, m, ozs, blen, 0); xor_block(blk, CS, blk);
			
		}	
		process_block(Delta_1, Delta_2, result, blk, W, Is_complete, Is_Final, ENCRYPT, MESSAGE); 
		store_bytes(c, result, 0, 15); c +=16;
	}

	/* ================ Process checksum block ====================== */
	process_block(Delta_1, Delta_2, result, blk, W, 1, 0, ENCRYPT, MESSAGE); 
	store_bytes(c, result, 0, blen-1);

	return 0;
}

/* ===================   COLM_0 Verified Decryption Function =================== */
int crypto_aead_decrypt(
unsigned char *m,unsigned long long *mlen,
const unsigned char *nsec,
const unsigned char *c, unsigned long long clen,
const unsigned char *ad, unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k
)
{
	u8 param[]={0,0,0,0,0,0,0,0}; 
	
	block L, W, Delta_0, Delta_1, Delta_2, blk, result, CS;
	int i; u8 zeroes[16], ozs[16], blen = 16, Is_Final = 0, Is_complete =1;
	unsigned long long tlen, blk_ctr=0, blk_ctr1=0;	
	for(i=0; i<16; i++)	{zeroes[i]=0x00;}   		// all zero.
	for(i=1; i<16; i++)	{ozs[i]=0x00;} ozs[0] = 0x80; 	//useful for padding.
	
	if(clen < 16)
		return -1;

	*mlen = clen - 16; 
	
	key_schedule(k);
	//KeySchedule(KeyLen, 0, k);
	//kuz_set_encrypt_key(k);
	/* ==========  Generate the Masks =========== */
	//AES(ENCRYPT, L, zeroes, &aes_key1);
    //Encryption(KeyLen, zeroes, L);
    kuz_encrypt_block(zeroes, L);
	/* =========== Generate the Masks ========== */
	//AES(ENCRYPT, L, zeroes, &aes_key1);
	//Encryption(KeyLen, zeroes, L);
	mult_3(Delta_0, L); 
	mult_inv2(Delta_0, Delta_0); 

	copy_block(Delta_1, L);
	//mult_inv2(Delta_1, L); 	

	mult_3(Delta_2, L); 
	mult_3(Delta_2, Delta_2); 
	//mult_inv2(Delta_2, Delta_2);

	
	/* =============  Process Associated Data  ================ */
	for(i=0; i<16; i++)
		W[i]=0x00;
	process_AD(W, Delta_0, npub, param, ad, adlen); 
	Is_Final = 0;
	
	 load_block(CS, zeroes, zeroes, 16, 0);

	 /* ================ Process Ciphertext Blocks ============ */
	 load_block(blk, c, zeroes, 16, 0);  

	 /* =================== Process 1st Block =================== */

	 if(clen<32){
	 	process_block(Delta_2, Delta_1, result, blk, W, 0, 1, DECRYPT, CIPHERTEXT); 
		store_bytes(m, result, 0, clen-17); m += clen - 16;
	 }
	 else {
		if(clen == 32) 
			Is_Final = 1;
		process_block(Delta_2, Delta_1, result, blk, W, 1, Is_Final, DECRYPT,  CIPHERTEXT);
		store_bytes(m, result, 0, 15);  m +=16;
	 }
	 xor_block(CS, CS, result); //store_bytes(nsec, result, 0, 7); 
	 clen -= 16; c+=16;

	 if(clen < 16){ 
		if(result[clen] != 0x80) return -1; 
		for(i=clen+1; i<16; i++) {if(result[i]!=0) return -1;} 
	 }

	/* ============= Process Successive Ciphertext Blocks ============== */
	while(clen > 16){
	   
	   load_block(blk, c, zeroes, 16, 0);  
	   if(clen < 32){ 
	   	process_block(Delta_2, Delta_1, result, blk, W, 0, 1, DECRYPT,  CIPHERTEXT); 
		xor_block(result, result, CS);
	   	store_bytes(m, result, 0, clen - 17);  
	   }
	   else{ 
		if(clen == 32)
			Is_Final = 1;
	        process_block(Delta_2, Delta_1, result, blk, W, 1, Is_Final, DECRYPT,  CIPHERTEXT); 
		if(clen == 32) {xor_block(result, result, CS);}
		store_bytes(m, result, 0, 15); 
	   } 

	   xor_block(CS, CS, result);
	   clen -= 16; c+=16;

	   
	   if(clen < 16){ 
		if(result[clen] != 0x80) return -1; 
		for(i=clen+1; i<16; i++) {if(result[i]!=0) return -1;} 
	   }
	   else
		   m +=16; 
	}
	/* ==========  Process checksum block  ============= */
	process_block(Delta_1, Delta_2, result, CS, W, 1, 0, ENCRYPT, MESSAGE); /* 2nd result was CS */
	for(i=0; i<clen; i++) {if(result[i]!=c[i]) { return -1; }} 
	return 0;
}

static double diffclock(clock_t clock1,clock_t clock2)
{
    double diffticks=clock1-clock2;
    double diffms=(diffticks)/(CLOCKS_PER_SEC/1000);
    return diffms;
}

int main()
{
	int i, res;
	clock_t start, end;
    //struct timespec start, stop, duration;
    static char val[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
    unsigned char np[] = {0xBB,0xAA,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00};
    unsigned char *m;
    m = (unsigned char*) malloc(16 * sizeof(char)); //16
    for (i = 0; i < 16; ++i)
    {
        m[i] = val[i % 16];
    }
    unsigned long long mlen = 16; //128
    const unsigned char nsec = '0';
    
    unsigned char *c;
    c = (unsigned char*) malloc(42* sizeof(char)); //24
    unsigned long long clen;
    unsigned char *ad;
    ad = (unsigned char*) malloc(0 * sizeof(char)); //8
    unsigned long long adlen = 0;
    const unsigned char *npub = (unsigned char *)np;
    unsigned char *k;
    k = (unsigned char*) malloc(32 * sizeof(char));
    for (i = 0; i < 32; ++i)
    {
        k[i] = val[i%16];
    }
    //printf("%s\n", npub);
    start =clock();
    crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, &nsec, npub, k);
    //res = crypto_aead_decrypt(m, &mlen, &nsec, c, clen, ad, adlen, npub, k);
    /*for (i = 0; i < 16; ++i)
    {
        printf("%d\n", m[i]);
    }*/
    /*for (i = 0; i < 16; ++i)
    {
        printf("%d\n", m[i]);
    }*/
    end = clock();
    printf("Алгоритм работал %f\n", diffclock(end, start));
    printf("%d\n", res);
    //clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
}
