#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h> 
#include "api.h"
#include <math.h>
//#include "t-aes_enc_only.h"
//#include "t-aes_define.h"
//#include "crypto_aead.h"
//#include "kuznechik.h"
#define KEYBYTES   CRYPTO_KEYBYTES
#define NONCEBYTES CRYPTO_NPUBBYTES
#define TAGBYTES   CRYPTO_ABYTES
#define KeyLen  (CRYPTO_KEYBYTES*8)



extern void kuz_encrypt_block(void *blk, void *cblk);
extern void kuz_decrypt_block(void *blk, void *cblk);
extern void kuz_set_encrypt_key( const unsigned char *key);

typedef unsigned char block[16];

/* ------------------------------------------------------------------------- */

static void xor_block(block d, block s1, block s2) {
    unsigned i;
    for (i=0; i<16; i++)
        d[i] = s1[i] ^ s2[i];
}

/* ------------------------------------------------------------------------- */
void incr_r(block* blk) 
{
	int i = 15;
	do {
	    *blk[i] += 1;
	} while (blk[i] == 0 && i-- > 7);
}

/* ------------------------------------------------------------------------- */

void incr_l(block* blk) 
{
	int i = 7;
	do {
	    *blk[i] += 1;
	} while (blk[i] == 0 && i-- > 0);
}

/* ------------------------------------------------------------------------- */

static inline uint32_t wlan_crypto_get_be32(const uint8_t *a)
{
	return ((uint32_t) a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

/* ------------------------------------------------------------------------- */

static inline void wlan_crypto_put_be32(uint8_t *a, uint32_t val)
{
	a[0] = (val >> 24) & 0xff;
	a[1] = (val >> 16) & 0xff;
	a[2] = (val >> 8) & 0xff;
	a[3] = val & 0xff;
}

/* ------------------------------------------------------------------------- */

static void shift_right_block(uint8_t *v)
{
	uint32_t val;

	val = wlan_crypto_get_be32(v + 12);
	val >>= 1;
	if (v[11] & 0x01)
		val |= 0x80000000;
	wlan_crypto_put_be32(v + 12, val);

	val = wlan_crypto_get_be32(v + 8);
	val >>= 1;
	if (v[7] & 0x01)
		val |= 0x80000000;
	wlan_crypto_put_be32(v + 8, val);

	val = wlan_crypto_get_be32(v + 4);
	val >>= 1;
	if (v[3] & 0x01)
		val |= 0x80000000;
	wlan_crypto_put_be32(v + 4, val);

	val = wlan_crypto_get_be32(v);
	val >>= 1;
	wlan_crypto_put_be32(v, val);
}

/* ------------------------------------------------------------------------- */

uint32_t BIT(int x){
	 uint32_t a = 1;
	 return a << x;
}

/* ------------------------------------------------------------------------- */

/* Multiplication in GF(2^128) */
static void gf_mult(const uint8_t *x, const uint8_t *y, uint8_t *z)
{
	uint8_t v[16];
	int i, j;

	memset(z, 0, 16); /* Z_0 = 0^128 */
	memcpy(v, y, 16); /* V_0 = Y */

	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (x[i] & BIT(7 - j)) {
				/* Z_(i + 1) = Z_i XOR V_i */
				xor_block(z, z, v);
			} else {
				/* Z_(i + 1) = Z_i */
			}

			if (v[15] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				shift_right_block(v);
				/* R = 11100001 || 0^120 */
				v[0] ^= 0xe1;
			} else {
				/* V_(i + 1) = V_i >> 1 */
				shift_right_block(v);
			}
		}
	}
}

/* ------------------------------------------------------------------------- */

static int mgm_crypt(unsigned char *out, unsigned char *k, unsigned char *n,
                     unsigned char *a, unsigned abytes,
                     unsigned char *in, unsigned inbytes, int encrypting) {
    block Y_i, tmp, Z_i, H_i, sum = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, res = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    int i, ib, ab;
    uint8_t *len_a_and_m = malloc(16 * sizeof(uint8_t));
    unsigned char *out_first = out;
    if ( ! encrypting ) {
         if (inbytes < TAGBYTES) return -1;
         inbytes -= TAGBYTES;
         kuz_set_encrypt_key(k);
    }
    kuz_set_encrypt_key(k);
    *n = *n & 0x7F;
    memcpy(tmp, n, 16);
    kuz_encrypt_block(tmp, Y_i);
    for (i = 1; i <= inbytes/16; i++, in=in+16, out=out+16)
    {
		memset(tmp, 0, 16);
		kuz_encrypt_block(Y_i, tmp);
		xor_block(out, in, tmp);
		incr_r(Y_i);
    }
    ib = inbytes % 16;
    if (ib > 0)
    {
		memset(tmp, 0, 16);
		memcpy(tmp, in, ib);
		kuz_encrypt_block(Y_i, tmp);
		xor_block(out, Y_i, tmp);
	}
	
	//tag generation
	*n = *n | 0x80;
	kuz_encrypt_block(n, Z_i);
	for(i = 1; i <= abytes/16; i++, a=a+16)
	{
		memset(tmp, 0, 16);
		kuz_encrypt_block(Z_i, H_i);
		gf_mult(H_i, a, res);
		xor_block(sum, res, sum);
		incr_l(Z_i);
	}
	ab = abytes % 16;
	if (ab > 0)
    {
		memset(tmp, 0, 16);
		memcpy(tmp, a, ab);
		kuz_encrypt_block(Z_i, H_i);
		xor_block(out, Y_i, tmp);
		incr_l(Z_i);
	}
	for(i = 1; i <= inbytes/16; i++, out_first = out_first + 16)
	{
		memset(tmp, 0, 16);
		kuz_encrypt_block(Z_i, H_i);
		gf_mult(H_i, out_first, res);
		xor_block(sum, res, sum);
		incr_l(Z_i);
	}
	kuz_encrypt_block(Z_i, H_i);
	//xor_block(sum, sum, H_i);
	len_a_and_m[15] = abytes + inbytes;
	gf_mult(len_a_and_m, H_i, res);
	xor_block(sum, sum, res);
	kuz_encrypt_block(res, res);
	for (i=0; i<16; i++)
	    printf("%X ", res[i]);
	return 0;
}

/* ------------------------------------------------------------------------- */

#define OCB_ENCRYPT 1
#define OCB_DECRYPT 0

void mgm_encrypt(unsigned char *c, unsigned char *k, unsigned char *n,
                 unsigned char *a, unsigned abytes,
                 unsigned char *p, unsigned pbytes) {
    mgm_crypt(c, k, n, a, abytes, p, pbytes, OCB_ENCRYPT);
}

/* ------------------------------------------------------------------------- */



/* ------------------------------------------------------------------------- */

int crypto_aead_encrypt(
unsigned char *c,unsigned long long *clen,
const unsigned char *m,unsigned long long mlen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *nsec,
const unsigned char *npub,
const unsigned char *k
)
{
    *clen = mlen + TAGBYTES;
    mgm_crypt(c, (unsigned char *)k, (unsigned char *)npub, (unsigned char *)ad,
              adlen, (unsigned char *)m, mlen, OCB_ENCRYPT);
    return 0;
}

int crypto_aead_decrypt(
unsigned char *m,unsigned long long *mlen,
unsigned char *nsec,
const unsigned char *c,unsigned long long clen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k
)
{
    *mlen = clen - TAGBYTES;
    return mgm_crypt(m, (unsigned char *)k, (unsigned char *)npub,
            (unsigned char *)ad, adlen, (unsigned char *)c, clen, OCB_DECRYPT);
}

/*static double diffclock(clock_t clock1,clock_t clock2)
{
    double diffticks=clock1-clock2;
    double diffms=(diffticks)/(CLOCKS_PER_SEC/1000);
    return diffms;
}*/

int main()
{
    int i;
    //clock_t start, end;
    static char p[] = {0xAA, 0xBB, 0xCC, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
		 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00, 0x11, 0x11, 0x22,
		 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 
		 0x0A, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 
		 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 
		 0x77, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88};
    static char val[] = {0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 
		 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 
		 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    unsigned char np[] =  {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 
		 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88};
    unsigned char *ad;
    ad = (unsigned char*) malloc(80 * sizeof(char)); //8
    unsigned char *m;
    m = (unsigned char*) malloc(80 * sizeof(char)); //16
    for (i = 0; i < 77; ++i)
    {
        m[i] = p[i];
        ad[i] = p[i];
    }
    unsigned long long mlen = 77; //128
    const unsigned char nsec = '0';
    unsigned char *c;
    c = (unsigned char*) malloc(100* sizeof(char)); //24
    unsigned long long clen;
    unsigned long long adlen = 80;
    const unsigned char *npub = (unsigned char *)np;
    unsigned char *k;
    k = (unsigned char*) malloc(32 * sizeof(char));
    for (i = 0; i < 32; ++i)
        k[i] = val[i];
    //printf("%s\n", npub);
    //kuz_set_encrypt_key(k);
    //kuz_encrypt_block(p, &tmp);
    crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, &nsec, npub, k);
    //for (i = 0; i < 77; ++i)
    //    printf("%X ", c[i]);
    //res = crypto_aead_decrypt(m, &mlen, &nsec, c, clen, ad, adlen, npub, k);
    /*for (i = 0; i < 16; ++i)
        printf("%X ", m[i]);*/
}
