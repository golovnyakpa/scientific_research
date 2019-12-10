#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include "api.h"
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

static void double_block(block d, block s) {
    unsigned i;
    unsigned char tmp = s[0];
    for (i=0; i<15; i++)
        d[i] = (s[i] << 1) | (s[i+1] >> 7);
    d[15] = (s[15] << 1) ^ ((tmp >> 7) * 135);
}

/* ------------------------------------------------------------------------- */

static void calc_L_i(block l, block ldollar, unsigned i) {
    double_block(l, ldollar);         /* l is now L_0               */
    for ( ; (i&1)==0 ; i>>=1)
        double_block(l,l);            /* double for each trailing 0 */
}

/* ------------------------------------------------------------------------- */

static void hash(block result, unsigned char *k,
                 unsigned char *a, unsigned abytes) {
    //AES_KEY aes_key;
    block lstar, ldollar, offset, sum, tmp;
    unsigned i;
    
    /* Key-dependent variables */
    
    /* L_* = ENCIPHER(K, zeros(128)) */
    //AES_set_encrypt_key(k, KEYBYTES*8, &aes_key);
    //KeySchedule(KeyLen, 0, k);
    kuz_set_encrypt_key(k);
    memset(tmp, 0, 16);
    //AES_encrypt(tmp, lstar, &aes_key);
    //Encryption(KeyLen, tmp, lstar);
    kuz_encrypt_block(tmp, lstar);
    /* L_$ = double(L_*) */
    double_block(ldollar, lstar); 
    
    /* Process any whole blocks */
    
    /* Sum_0 = zeros(128) */
    memset(sum, 0, 16);
    /* Offset_0 = zeros(128) */
    memset(offset, 0, 16);
    for (i=1; i<=abytes/16; i++, a = a + 16) {
        /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
        calc_L_i(tmp, ldollar, i);
        xor_block(offset, offset, tmp);
        /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i) */
        xor_block(tmp, offset, a);
        //AES_encrypt(tmp, tmp, &aes_key);
        //Encryption(KeyLen, tmp, tmp);
        kuz_encrypt_block(tmp, tmp);
        xor_block(sum, sum, tmp);
    }

    /* Process any final partial block; compute final hash value */

    abytes = abytes % 16;  /* Bytes in final block */
    if (abytes > 0) {
        /* Offset_* = Offset_m xor L_* */
        xor_block(offset, offset, lstar);
        /* tmp = (A_* || 1 || zeros(127-bitlen(A_*))) xor Offset_* */
        memset(tmp, 0, 16);
        memcpy(tmp, a, abytes);
        tmp[abytes] = 0x80;
        xor_block(tmp, offset, tmp);
        /* Sum = Sum_m xor ENCIPHER(K, tmp) */
        //(tmp, tmp, &aes_key);
        xor_block(sum, tmp, sum);
    }
    
    memcpy(result, sum, 16);
}

/* ------------------------------------------------------------------------- */

static int ocb_crypt(unsigned char *out, unsigned char *k, unsigned char *n,
                     unsigned char *a, unsigned abytes,
                     unsigned char *in, unsigned inbytes, int encrypting) {
    // AES_KEY aes_encrypt_key, aes_decrypt_key;
    block lstar, ldollar, sum, offset, ktop, pad, nonce, tag, tmp, ad_hash;
    unsigned char stretch[24];
    unsigned bottom, byteshift, bitshift, i;
    
    /* Setup AES and strip ciphertext of its tag */
    if ( ! encrypting ) {
         if (inbytes < TAGBYTES) return -1;
         inbytes -= TAGBYTES;
         //AES_set_decrypt_key(k, KEYBYTES*8, &aes_decrypt_key);
         //KeySchedule(KeyLen, 0, k);
         kuz_set_encrypt_key(k);
    }
    //AES_set_encrypt_key(k, KEYBYTES*8, &aes_encrypt_key);
    //KeySchedule(KeyLen, 0, k);
    kuz_set_encrypt_key(k);
    /* Key-dependent variables */

    /* L_* = ENCIPHER(K, zeros(128)) */
    memset(tmp, 0, 16);
    //AES_encrypt(tmp, lstar, &aes_encrypt_key);
    //Encryption(KeyLen, tmp, lstar);
    kuz_encrypt_block(tmp, lstar);
    /* L_$ = double(L_*) */
    double_block(ldollar, lstar); 

    /* Nonce-dependent and per-encryption variables */

    /* Nonce = zeros(127-bitlen(N)) || 1 || N */
    memset(nonce,0,16);
    memcpy(&nonce[16-NONCEBYTES],n,NONCEBYTES);
    nonce[0] = (unsigned char)(((TAGBYTES * 8) % 128) << 1);
    nonce[16-NONCEBYTES-1] |= 0x01;
    /* bottom = str2num(Nonce[123..128]) */
    bottom = nonce[15] & 0x3F;
    /* Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6)) */
    nonce[15] &= 0xC0;
    //AES_encrypt(nonce, ktop, &aes_encrypt_key);
    //Encryption(KeyLen, nonce, ktop);
    kuz_encrypt_block(nonce, ktop);
    /* Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]) */
    memcpy(stretch, ktop, 16);
    memcpy(tmp, &ktop[1], 8);
    xor_block(tmp, tmp, ktop);
    memcpy(&stretch[16],tmp,8);
    /* Offset_0 = Stretch[1+bottom..128+bottom] */
    byteshift = bottom/8;
    bitshift  = bottom%8;
    if (bitshift != 0)
        for (i=0; i<16; i++)
            offset[i] = (stretch[i+byteshift] << bitshift) |
                        (stretch[i+byteshift+1] >> (8-bitshift));
    else
        for (i=0; i<16; i++)
            offset[i] = stretch[i+byteshift];
    /* Checksum_0 = zeros(128) */
    memset(sum, 0, 16);

    /* Hash associated data */
    hash(ad_hash, k, a, abytes);

    /* Process any whole blocks */

    for (i=1; i<=inbytes/16; i++, in=in+16, out=out+16) {
        /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
        calc_L_i(tmp, ldollar, i);
        xor_block(offset, offset, tmp);
        
        xor_block(tmp, offset, in);
        if (encrypting) {
            /* Checksum_i = Checksum_{i-1} xor P_i */
            xor_block(sum, in, sum);
            /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i) */
            //AES_encrypt(tmp, tmp, &aes_encrypt_key);
            //Encryption(KeyLen, tmp, tmp);
            kuz_encrypt_block(tmp, tmp);
            xor_block(out, offset, tmp);
        } else {
            /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i) */
            //AES_decrypt(tmp, tmp, &aes_decrypt_key);
            kuz_decrypt_block(tmp, tmp);
            xor_block(out, offset, tmp);
            /* Checksum_i = Checksum_{i-1} xor P_i */
            xor_block(sum, out, sum);
        }
    }

    /* Process any final partial block and compute raw tag */

    inbytes = inbytes % 16;  /* Bytes in final block */
    if (inbytes > 0) {
        /* Offset_* = Offset_m xor L_* */
        xor_block(offset, offset, lstar);
        /* Pad = ENCIPHER(K, Offset_*) */
        //AES_encrypt(offset, pad, &aes_encrypt_key);
        //Encryption(KeyLen, offset, pad);
        kuz_encrypt_block(offset, pad);
        if (encrypting) {
            /* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*))) */
            memset(tmp, 0, 16);
            memcpy(tmp, in, inbytes);
            tmp[inbytes] = 0x80;
            xor_block(sum, tmp, sum);
            /* C_* = P_* xor Pad[1..bitlen(P_*)] */
            xor_block(pad, tmp, pad);
            memcpy(out, pad, inbytes);
            out = out + inbytes;
        } else {
            /* P_* = C_* xor Pad[1..bitlen(C_*)] */
            memcpy(tmp, pad, 16);
            memcpy(tmp, in, inbytes);
            xor_block(tmp, pad, tmp);
            tmp[inbytes] = 0x80;     /* tmp == P_* || 1 || zeros(127-bitlen(P_*)) */
            memcpy(out, tmp, inbytes);
            /* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*))) */
            xor_block(sum, tmp, sum);
            in = in + inbytes;
        }
    }
    
    /* Tag = ENCIPHER(K, Checksum xor Offset xor L_$) xor HASH(K,A) */
    xor_block(tmp, sum, offset);
    xor_block(tmp, tmp, ldollar);
    //AES_encrypt(tmp, tag, &aes_encrypt_key);
    //Encryption(KeyLen, tmp, tag);
    kuz_encrypt_block(tmp, tag);
    xor_block(tag, ad_hash, tag);
    
    if (encrypting) {
        memcpy(out, tag, TAGBYTES);
        return 0;
    } else
        return (memcmp(in,tag,TAGBYTES) ? -1 : 0);     /* Check for validity */
}

/* ------------------------------------------------------------------------- */

#define OCB_ENCRYPT 1
#define OCB_DECRYPT 0

void ocb_encrypt(unsigned char *c, unsigned char *k, unsigned char *n,
                 unsigned char *a, unsigned abytes,
                 unsigned char *p, unsigned pbytes) {
    ocb_crypt(c, k, n, a, abytes, p, pbytes, OCB_ENCRYPT);
}

/* ------------------------------------------------------------------------- */

int ocb_decrypt(unsigned char *p, unsigned char *k, unsigned char *n,
                unsigned char *a, unsigned abytes,
                unsigned char *c, unsigned cbytes) {
    return ocb_crypt(p, k, n, a, abytes, c, cbytes, OCB_DECRYPT);
}

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
    ocb_crypt(c, (unsigned char *)k, (unsigned char *)npub, (unsigned char *)ad,
            adlen, (unsigned char *)m, mlen, OCB_ENCRYPT);
    return 0;
}

int crypto_aead_decrypt(
unsigned char *m,unsigned long long *mlen,
const unsigned char *nsec,
const unsigned char *c,unsigned long long clen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k
)
{
    *mlen = clen - TAGBYTES;
    return ocb_crypt(m, (unsigned char *)k, (unsigned char *)npub,
            (unsigned char *)ad, adlen, (unsigned char *)c, clen, OCB_DECRYPT);
}

static double diffclock(clock_t clock1,clock_t clock2)
{
    double diffticks=clock1-clock2;
    double diffms=(diffticks)/(CLOCKS_PER_SEC/1000);
    return diffms;
}

//void kuz_init();

int main()
{
	int i, res;
	clock_t start, end;
    //struct timespec start, stop, duration;
    static char val[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xA, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
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
    c = (unsigned char*) malloc(32* sizeof(char)); //24
    unsigned long long clen;
    unsigned char *ad;
    ad = (unsigned char*) malloc(0 * sizeof(char)); //8
    unsigned long long adlen = 0;
    const unsigned char *npub = (unsigned char *)np;
    unsigned char *k;
    k = (unsigned char*) malloc(32 * sizeof(char));
    for (i = 0; i < 32; ++i)
    {
        k[i] = val[i];
    }
    //printf("%s\n", npub);
    start =clock();
    crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, &nsec, npub, k);
    for (i = 0; i < 16; ++i)
    {
        printf("%d\n", m[i]);
    }
    res = crypto_aead_decrypt(m, &mlen, &nsec, c, clen, ad, adlen, npub, k);
    /*for (i = 0; i < 16; ++i)
    {
        printf("%d\n", c[i]);
    }*/
    end = clock();
    printf("Алгоритм работал %f\n", diffclock(end, start));
    printf("%d\n", res);
    //clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
}
