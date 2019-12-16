//#include "crypto_aead.h"
#include <stdio.h> 
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include <time.h>
#include "kuznechik.h"
#include <openssl/aes.h>

#ifdef _MSC_VER
#define inline __inline
#endif

#include <string.h>

#ifdef _MSC_VER
#define inline __inline
#endif

typedef unsigned int U32;


static inline void jambu_initialization(kuz_key_t *rk, const uint8_t *iv, unsigned int *stateS, unsigned int *stateR)   
{

    stateS[0] = ((unsigned int *)iv)[0]; stateS[1] = ((unsigned int *)iv)[1]; 
    //AESEncrypt(rk, stateS);
    kuz_encrypt_block(rk, stateS);
    stateS[0] ^= 0x5;
    stateR[0] = stateS[2];
    stateR[1] = stateS[3];
    return;

}

static inline void jambu_tag_generation(kuz_key_t *rk, uint64_t msglen, uint8_t *c, unsigned int *stateS, unsigned int *stateR)  
{

    kuz_encrypt_block(rk, stateS);
    stateS[0] ^= stateR[0] ^ 0x03; 
    stateS[1] ^= stateR[1]; 
    stateR[0] ^= stateS[2]; 
    stateR[1] ^= stateS[3]; 

    kuz_encrypt_block(rk, stateS);

    ((unsigned int *)(c+msglen))[0] = stateS[0] ^ stateS[2] ^ stateR[0]; 
    ((unsigned int *)(c+msglen))[1] = stateS[1] ^ stateS[3] ^ stateR[1]; 
} 

static inline int jambu_tag_verification(kuz_key_t *rk, uint64_t msglen, const uint8_t *c, unsigned int *stateS, unsigned int *stateR)  
{
    uint8_t t[8]; 
    int check = 0; 
    int i; 

    kuz_encrypt_block(rk, stateS);
    stateS[0] ^= stateR[0] ^ 0x03; 
    stateS[1] ^= stateR[1]; 

    stateR[0] ^= stateS[2]; 
    stateR[1] ^= stateS[3]; 

    kuz_encrypt_block(rk, stateS);

    ((unsigned int *)t)[0] = stateS[0] ^ stateS[2] ^ stateR[0]; 
    ((unsigned int *)t)[1] = stateS[1] ^ stateS[3] ^ stateR[1]; 
    for (i = 0; i  < 8; i++) check |= (c[msglen+i] ^ t[i]);
    if (0 == check) return 0; else return -1;
} 

static inline void jambu_aut_ad_step(kuz_key_t *rk, const uint8_t *adblock,
                                     unsigned int *stateS, unsigned int *stateR) 
{
    kuz_encrypt_block(rk, stateS);
    stateS[0] ^= stateR[0] ^ 0x01; 
    stateS[1] ^= stateR[1]; 
    stateS[2] ^= ((unsigned int *)adblock)[0]; 
    stateS[3] ^= ((unsigned int *)adblock)[1]; 

    stateR[0] ^= stateS[2]; 
    stateR[1] ^= stateS[3]; 

    return;
}

static inline void jambu_aut_ad_partial(kuz_key_t *rk, const uint8_t *adblock,
                                        unsigned int *stateS, unsigned int *stateR, unsigned int len) 
{
    uint8_t p[8];

    memcpy(p, adblock, len); 

    p[len] = 0x80; // pad '1' 
    memset(p+len+1, 0, 7-len); // pad '0' 

    kuz_encrypt_block(rk, stateS);
    stateS[0] ^= stateR[0] ^ 0x01; 
    stateS[1] ^= stateR[1]; 
    stateS[2] ^= ((unsigned int *)p)[0]; 
    stateS[3] ^= ((unsigned int *)p)[1]; 

    stateR[0] ^= stateS[2]; 
    stateR[1] ^= stateS[3];

    return;
}

static inline void jambu_aut_ad_full(kuz_key_t *rk, unsigned int *stateS, unsigned int *stateR) 
{
    kuz_encrypt_block(rk, stateS);
    stateS[0] ^= stateR[0] ^ 0x01; 
    stateS[1] ^= stateR[1]; 
    stateS[2] ^= 0x80; 

    stateR[0] ^= stateS[2]; 
    stateR[1] ^= stateS[3];
    return;
}

static inline void jambu_enc_aut_msg_step(kuz_key_t *rk, const uint8_t *plaintextblk,
                                          uint8_t *ciphertextblk, unsigned int *stateS, unsigned int *stateR) 
{

    kuz_encrypt_block(rk, stateS);
    stateS[0] ^= stateR[0]; 
    stateS[1] ^= stateR[1]; 
    stateS[2] ^= ((unsigned int *)plaintextblk)[0]; 
    stateS[3] ^= ((unsigned int *)plaintextblk)[1]; 

    stateR[0] ^= stateS[2]; 
    stateR[1] ^= stateS[3]; 
    ((unsigned int *)ciphertextblk)[0] = stateS[0] ^ ((unsigned int *)plaintextblk)[0];
    ((unsigned int *)ciphertextblk)[1] = stateS[1] ^ ((unsigned int *)plaintextblk)[1];

    return; 
}  

/* Deal with partial final block */
static inline void jambu_enc_aut_msg_partial(kuz_key_t *rk, const uint8_t *plaintextblk,
                                             uint8_t *ciphertextblk, unsigned int *stateS, unsigned int *stateR, unsigned int len) 
{   
    uint8_t p[8]; 

    memcpy(p, plaintextblk, len); 

    p[len] = 0x80; // pad '1' 
    memset(p+len+1, 0, 7-len);// pad '0'

    kuz_encrypt_block(rk, stateS);
    stateS[0] ^= stateR[0]; 
    stateS[1] ^= stateR[1]; 
    stateS[2] ^= ((unsigned int *)p)[0]; 
    stateS[3] ^= ((unsigned int *)p)[1]; 

    stateR[0] ^= stateS[2]; 
    stateR[1] ^= stateS[3]; 
    ((unsigned int *)ciphertextblk)[0] = stateS[0] ^ ((unsigned int *)p)[0];
    ((unsigned int *)ciphertextblk)[1] = stateS[1] ^ ((unsigned int *)p)[1];

    return; 
}  

static inline void jambu_enc_aut_msg_full(kuz_key_t *rk, unsigned int *stateS, unsigned int *stateR) 
{   
    kuz_encrypt_block(rk, stateS);
    stateS[0] ^= stateR[0]; 
    stateS[1] ^= stateR[1]; 
    stateS[2] ^= 0x80; 

    stateR[0] ^= stateS[2]; 
    stateR[1] ^= stateS[3]; 

    return;  
} 

static inline void jambu_dec_aut_msg_step(kuz_key_t  *rk, uint8_t *plaintextblk, const uint8_t *ciphertextblk, unsigned int *stateS, unsigned int *stateR) 
{
    kuz_encrypt_block(rk, stateS);
    stateS[0] ^= stateR[0]; 
    stateS[1] ^= stateR[1]; 
    ((unsigned int *)plaintextblk)[0] = stateS[0] ^ ((unsigned int *)ciphertextblk)[0];
    ((unsigned int *)plaintextblk)[1] = stateS[1] ^ ((unsigned int *)ciphertextblk)[1];

    stateS[2] ^= ((unsigned int *)plaintextblk)[0]; 
    stateS[3] ^= ((unsigned int *)plaintextblk)[1]; 

    stateR[0] ^= stateS[2]; 
    stateR[1] ^= stateS[3]; 

}  

static inline void jambu_dec_aut_partial(kuz_key_t  *rk, uint8_t *plaintextblk, const uint8_t *ciphertextblk, unsigned int *stateS, unsigned int *stateR, unsigned int len) 
{
    uint8_t p[8]; 
    kuz_encrypt_block(rk, stateS);
    stateS[0] ^= stateR[0]; 
    stateS[1] ^= stateR[1]; 
    ((unsigned int *)p)[0] = stateS[0] ^ ((unsigned int *)ciphertextblk)[0];
    ((unsigned int *)p)[1] = stateS[1] ^ ((unsigned int *)ciphertextblk)[1];
    p[len] = 0x80; 
    memset(p+len+1, 0, 7-len); 
    memcpy(plaintextblk, p, len); 

    stateS[2] ^= ((unsigned int *)p)[0]; 
    stateS[3] ^= ((unsigned int *)p)[1]; 

    stateR[0] ^= stateS[2]; 
    stateR[1] ^= stateS[3]; 

}  

int crypto_aead_encrypt(
    unsigned char *c,unsigned long long *clen,
    const unsigned char *m,unsigned long long mlen,
    const unsigned char *ad,unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k
    ) 
{   
    unsigned int i;
    unsigned int jambu_state[4];  
    unsigned int stateR[2]; 
    //unsigned int EK[44]; // Nr = 10, 4*(Nr+1) = 44 round keys
    // key expansion
    kuz_key_t key; 
    kuz_set_encrypt_key(&key, k);
    
    // Initialization
    memset(jambu_state, 0, 16); 
    memset(stateR, 0, 8); 
    jambu_initialization(&key, npub, jambu_state, stateR);  

    //process the associated data
    for (i = 0; (i+8) <= adlen; i += 8) {
        jambu_aut_ad_step(&key, ad+i, jambu_state, stateR);
    }
    //deal with the partial block of associated data
    //in this program, we assume that the message length is a multiple of bytes.
    if (  (adlen & 0x7) != 0 )  {
        jambu_aut_ad_partial(&key, ad+i, jambu_state, stateR, adlen & 0x7); 
    }
    else
    {
        jambu_aut_ad_full(&key, jambu_state, stateR); 
    }
 
    // encrypt the plaintext, we assume that the message length is multiple of bytes. 
    for (i = 0; (i+8) <= mlen; i += 8) {    
        jambu_enc_aut_msg_step(&key, m+i, c+i, jambu_state, stateR);  
    }  
    // deal with the final plaintext block
    if ((mlen & 0x7) != 0) {
        jambu_enc_aut_msg_partial(&key, m+i, c+i, jambu_state, stateR, mlen & 0x7);
    }
    else
    {
        jambu_enc_aut_msg_full(&key, jambu_state, stateR);
    }

    // finalization stage, we assume that the tag length is a multiple of bytes
    jambu_tag_generation(&key, mlen, c, jambu_state, stateR);     
    *clen = mlen + 8;
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
    unsigned int i;  
    //uint8_t check = 0;  
    unsigned int jambu_state[4];  
    unsigned int stateR[2]; 
    // key expansion
    kuz_key_t key; 
    kuz_set_decrypt_key(&key, k);
 
    // Initialization
    memset(jambu_state, 0, 16); 
    memset(stateR, 0, 8); 
    jambu_initialization(&key, npub, jambu_state, stateR);   
 
    //process the associated data
    for (i = 0; (i+8) <= adlen; i += 8) {
        jambu_aut_ad_step(&key, ad+i, jambu_state, stateR);
    }
    //deal with the partial block of associated data
    //in this program, we assume that the message length is a multiple of bytes.
    if (  (adlen & 0x7) != 0 )  {
        jambu_aut_ad_partial(&key, ad+i, jambu_state, stateR, adlen & 0x7); 
    }
    else
    {
        jambu_aut_ad_full(&key, jambu_state, stateR); 
    } 
 
    // decrypt the ciphertext
    *mlen = clen - 8; 
    for (i = 0; (i+8)  <= *mlen; i = i+8) { 
        jambu_dec_aut_msg_step(&key, m+i, c+i, jambu_state, stateR);  
    }  
 
    // deal with the final block
    if (((*mlen) & 0x7) != 0) {
        jambu_dec_aut_partial(&key, m+i, c+i, jambu_state, stateR, *mlen & 0x7);
    }
    else
    {
        jambu_enc_aut_msg_full(&key, jambu_state, stateR);
    }
 
    // verification, we assume that the tag length is a multiple of bytes  
    return jambu_tag_verification(&key, *mlen, c, jambu_state, stateR);
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
    static char val[] = {'s', 'e', 'c', 'r', 'e', 't', 'k', 'e', 'y', 'f', 'o', 'r', 'c', 'i', 'p', 'h',
		                 's', 'e', 'c', 'r', 'e', 't', 'k', 'e', 'y', 'f', 'o', 'r', 'c', 'i', 'p', 'h'};
    unsigned char np[] = {'1','1','1','1','1','1','1','1'};
    unsigned char *m;
    m = (unsigned char*) malloc(4096 * sizeof(char)); //16
    for (i = 0; i < 4096; ++i)
    {
        m[i] = val[i % 16];
    }
    unsigned long long mlen = 4096; //128
    const unsigned char nsec = '0';
    unsigned char *c;
    c = (unsigned char*) malloc(5004 * sizeof(char)); //24
    unsigned long long clen;
    unsigned char *ad;
    ad = (unsigned char*) malloc(2 * sizeof(char)); //8
    unsigned long long adlen = 16;
    const unsigned char *npub = (unsigned char *)np;
    unsigned char *k;// = {'s', 'e', 'c', 'r', 'e', 't', 'k', 'e', 'y', 'f', 'o', 'r', 'c', 'i', 'p', 'h'};
    k = (unsigned char*) malloc(32 * sizeof(char));
    for (i = 0; i < 32; ++i)
    {
        k[i] = val[i];
    }
    ad[0] = 'h';
    ad[1] = 'e';
    start =clock();
    crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, &nsec, npub, k);
    res = crypto_aead_decrypt(m, &mlen, &nsec, c, clen, ad, adlen, npub, k);
    end = clock();
    printf("Алгоритм работал %f\n", diffclock(end, start));
    /*for (i = 0; i < 16; ++i)
    {
        printf("%d\n", m[i]);
    }*/
    printf("%d\n", res);
    return 0; 
}
