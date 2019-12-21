#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>


typedef unsigned long long ull;


ull rdtsc() 
	{
		unsigned int lo, hi;
		asm volatile ( "rdtsc\n" : "=a" (lo), "=d" (hi) );
		return ((ull)hi << 32) | lo;
    }


int main()
{
	int a, i;
	float time;
	ull t1 = rdtsc();
	for (i=0; i < 1000; i++)
	    a = 3 ^ 5;
	ull t2 = rdtsc();
	time = (float)((t2 - t1)/(CLOCKS_PER_SEC/1000));
	printf("%f\n", time / 1000);
	return 0;
}
