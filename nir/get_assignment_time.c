#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h> 

static double diffclock(clock_t clock1,clock_t clock2)
{
    double diffticks=clock1-clock2;
    double diffms=(diffticks)/(CLOCKS_PER_SEC/1000);
    return diffms;
}

int main()
{
	int i, j, a, b = 7, c = 9;
	clock_t start, end;
	double results[100], res, answer, sum = 0;
	for (i=0; i<100; i++)
	{
		start =clock();
		for (j=0; j<100000; j++)
		{
		    a = b*c;
		}
		end = clock();
	    res = diffclock(end, start);
	    results[i] = res;
    }
    for (i=0; i<100; i++)
        sum += results[i];
    answer = sum / 100;
	printf("Алгоритм работал %f\n", answer);
	return 0;
}
