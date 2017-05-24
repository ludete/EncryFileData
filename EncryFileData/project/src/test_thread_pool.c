#include <stdlib.h> 
#include <pthread.h> 
#include <unistd.h> 
#include <assert.h> 
#include <stdio.h> 
#include <string.h> 
#include <signal.h> 
#include <errno.h> 
#include <stdbool.h>

#include "thread_pool.h"
#include "include_sub_function.h"



<<<<<<< HEAD
int process(void *arg)
{
	int *flag = (int*)arg;
	
	printf("thread 0x%x working on task %d\n ",(unsigned int)pthread_self(),*((int*)arg));
	sleep(1);	//小---大写
	myprint("task %d is end", *flag);
	return 0;
=======
void process(void *arg)
{
    int *flag = (int*)arg;

    printf("thread 0x%x working on task %d\n ",(unsigned int)pthread_self(),*((int*)arg));
    sleep(1);	//小---大写
    myprint("task %d is end", *flag);

>>>>>>> b149491b2540937e4e7ff6137efdca1c223bae51
}



int main()
{
<<<<<<< HEAD
	threadpool_t *pool = NULL;

	//1. create 10 sub-thread
	if((pool = threadpool_create(10, 100, 100)) == NULL)
	{
		myprint("Err : func threadpool_create() pool : %p", pool);
	}

	int num[20], i = 0;
	for(i = 0; i < 20; i++)
	{
		num[i] = i;
		threadpool_add(pool, process, (void *)&num[i]);
	}

	sleep(2);
	printf("\n\n");
	myprint(" !!!!!!!!! begin destroy() !!!!!!!!!!");
	threadpool_destroy(pool);	
	myprint(" !!!!!!!!! end destroy() !!!!!!!!!!");


	return 0;
=======
    threadpool_t *pool = NULL;

    //1. create 10 sub-thread
    if((pool = threadpool_create(10, 100, 100)) == NULL)
    {
        myprint("Err : func threadpool_create() pool : %p", pool);
    }

    int num[20], i = 0;
    for(i = 0; i < 20; i++)
    {
        num[i] = i;
        threadpool_add(pool, process, (void *)&num[i]);
    }

    sleep(2);
    printf("\n\n");
    myprint(" !!!!!!!!! begin destroy() !!!!!!!!!!");
    threadpool_destroy(pool);	
    myprint(" !!!!!!!!! end destroy() !!!!!!!!!!");


    return 0;
>>>>>>> b149491b2540937e4e7ff6137efdca1c223bae51
}
