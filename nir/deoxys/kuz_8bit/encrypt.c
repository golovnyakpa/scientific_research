#include <stdlib.h>
#include "api.h"
#include "deoxys.h"
#include <time.h>
#include <stdio.h> 
#include <stdint.h>
#include <string.h>


/*
 the code for the cipher implementation goes here,
 generating a ciphertext c[0],c[1],...,c[*clen-1]
 from a plaintext m[0],m[1],...,m[mlen-1]
 and associated data ad[0],ad[1],...,ad[adlen-1]
 and secret message number nsec[0],nsec[1],...
 and public message number npub[0],npub[1],...
 and secret key k[0],k[1],...
 */
int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec,
                        const unsigned char *npub,
                        const unsigned char *k
                        )
{
    
    size_t outlen = 0;
    deoxys_aead_encrypt(ad, adlen, m, mlen, k, npub, c, &outlen);
    *clen = outlen;
    (void)nsec;
    return 0;
}

/*
 the code for the cipher implementation goes here,
 generating a plaintext m[0],m[1],...,m[*mlen-1]
 and secret message number nsec[0],nsec[1],...
 from a ciphertext c[0],c[1],...,c[clen-1]
 and associated data ad[0],ad[1],...,ad[adlen-1]
 and public message number npub[0],npub[1],...
 and secret key k[0],k[1],...
 */
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        const unsigned char *nsec,
                        const unsigned char *c, unsigned long long clen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *npub,
                        const unsigned char *k
                        )
{
    int result = deoxys_aead_decrypt(ad, adlen, m, (size_t *)mlen, k, npub, c, clen);
    (void)nsec;
    return result;
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
    static char val[] = {'s', 'e', 'c', 'r', 'e', 't', 'k', 'e', 'y', 'f', 'o', 'r', 'c', 'i', 'p', 'h'};
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
    c = (unsigned char*) malloc(5028 * sizeof(char)); //24
    unsigned long long clen;
    unsigned char *ad;
    ad = (unsigned char*) malloc(2 * sizeof(char)); //8
    unsigned long long adlen = 0;
    const unsigned char *npub = (unsigned char *)np;
    unsigned char *k;// = {'s', 'e', 'c', 'r', 'e', 't', 'k', 'e', 'y', 'f', 'o', 'r', 'c', 'i', 'p', 'h'};
    k = (unsigned char*) malloc(32 * sizeof(char));
    for (i = 0; i < 32; ++i)
    {
        k[i] = val[i%16];
    }
    start =clock();
    crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, &nsec, npub, k);
    //k[3] = 'q';
    //res = crypto_aead_decrypt(m, &mlen, &nsec, c, clen, ad, adlen, npub, k);
    /*for (i = 0; i < 16; ++i)
    {
        printf("%d\n", c[i]);
    }*/
    end = clock();
    printf("Алгоритм работал %f\n", diffclock(end, start));
    //printf("%d\n", res);
    //printf("%d\n", res);
    //res = crypto_aead_decrypt(m, &mlen, &nsec, c, clen, ad, adlen, npub, k);
    //end = clock();
    //printf("Алгоритм работал %f\n", diffclock(end, start));
    /*for (i = 0; i < 256; ++i)
    {
        printf("%d\n", m[i]);
    }*/
    //printf("%d\n", res);
    return 0;
}
