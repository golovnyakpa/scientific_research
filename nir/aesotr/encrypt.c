//#include "crypto_aead.h" /* for SUPERCOP */
#include "api.h"
#include "OTR.h"
#include <stdio.h> 
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


/*
       ... the code for the cipher implementation goes here,
       ... generating a ciphertext c[0],c[1],...,c[*clen-1]
       ... from a plaintext m[0],m[1],...,m[mlen-1]
       ... and associated data ad[0],ad[1],...,ad[adlen-1]
       ... and secret message number nsec[0],nsec[1],...
       ... and public message number npub[0],npub[1],...
       ... and secret key k[0],k[1],...
*/
int crypto_aead_encrypt(
	unsigned char *c,unsigned long long *clen,
	const unsigned char *m,unsigned long long mlen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k
	)
{
	Setup(k);
	AE_Encrypt(npub, CRYPTO_NPUBBYTES, m, (uint32)mlen, ad, (uint32)adlen, CRYPTO_ABYTES, c, c+mlen);

	*clen = mlen + CRYPTO_ABYTES;

	return 0;
}

/*
       ... the code for the cipher implementation goes here,
       ... generating a plaintext m[0],m[1],...,m[*mlen-1]
       ... and secret message number nsec[0],nsec[1],...
       ... from a ciphertext c[0],c[1],...,c[clen-1]
       ... and associated data ad[0],ad[1],...,ad[adlen-1]
       ... and public message number npub[0],npub[1],...
       ... and secret key k[0],k[1],...
*/
int crypto_aead_decrypt(
	unsigned char *m,unsigned long long *mlen,
	const unsigned char *nsec,
	const unsigned char *c,unsigned long long clen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
	)
{
	int		rc;

	*mlen = clen - CRYPTO_ABYTES;

	Setup(k);
	rc = AE_Decrypt(npub, CRYPTO_NPUBBYTES, c, (uint32)*mlen, ad, (uint32)adlen, CRYPTO_ABYTES, c+*mlen, m);

	if(rc == TAG_UNMATCH)
		return -1;
	else
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
    static char val[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    unsigned char np[] = {0,1,2,3,4,5,6,7,8,9,10,11};
    unsigned char *m;
    m = (unsigned char*) malloc(512 * sizeof(char)); //16
    for (i = 0; i < 512; ++i)
    {
        m[i] = val[i % 16];
    }
    unsigned long long mlen = 512; //128
    const unsigned char nsec = '0';
    unsigned char *c;
    c = (unsigned char*) malloc(542* sizeof(char)); //24
    unsigned long long clen;
    unsigned char *ad;
    ad = (unsigned char*) malloc(2 * sizeof(char)); //8
    unsigned long long adlen = 0;
    const unsigned char *npub = (unsigned char *)np;
    unsigned char *k;
    k = (unsigned char*) malloc(16 * sizeof(char));
    for (i = 0; i < 16; ++i)
    {
        k[i] = val[i];
    }
    //printf("%s\n", npub);
    start =clock();
    crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, &nsec, npub, k);
    //res = crypto_aead_decrypt(m, &mlen, &nsec, c, clen, ad, adlen, npub, k);
    end = clock();
    printf("Алгоритм работал %f\n", diffclock(end, start));
    //printf("%d\n", res);
    //clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
}
