#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

pthread_mutex_t mutex;
pthread_cond_t cond;


// 1 sub-thread working
void *thread1(void *arg) 
{
	
	//pthread_cleanup_push(pthread_mutex_unlock, &mutex);

    //提供函数回调保护
    while (1) {
	
		printf("\n=========== thread1 is running\n");
				
		//1. working 		
		pthread_mutex_lock(&mutex);				
		pthread_cond_wait(&cond, &mutex);				
		printf("=========== thread1 applied the condition\n\n");				
		pthread_mutex_unlock(&mutex);
				
		sleep(4);
	
	}
	
	//pthread_cleanup_pop(0);

}

void *thread2(void *arg) 
{
	
	while (1) {
			
		printf("\n*********** thread2 is running\n");	
					
		//1. working 			
		pthread_mutex_lock(&mutex);				
		pthread_cond_wait(&cond, &mutex);				
		printf("*********** thread2 applied the condition\n\n");				
		pthread_mutex_unlock(&mutex);
				
		sleep(1);
		
	}

}


int main() 
{
	
	pthread_t thid1, thid2;
		
	printf("condition variable study!\n");
		
	//1. init mutex And cond	
	pthread_mutex_init(&mutex, NULL);		
	pthread_cond_init(&cond, NULL);
		
	//2. create two sub-thread 	
	pthread_create(&thid1, NULL, (void *) thread1, NULL);		
	pthread_create(&thid2, NULL, (void *) thread2, NULL);
		
	//3. main-thread work, signal cond to sub-thread	
	do {			
		pthread_cond_signal(&cond);	
		sleep(4);
	} while (1);
		
	sleep(20);
		
	pthread_exit(0);
		
	return 0;

}

