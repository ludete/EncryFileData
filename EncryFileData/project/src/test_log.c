#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>

#include "socklog.h"


Handle g_handle_log;
pthread_mutex_t g_mutex_log = PTHREAD_MUTEX_INITIALIZER;  

#if 0
void socket_log2(int lever, int status, const char *fmt, ... )
{
	va_list args;
	va_start(args, fmt);
	
	Socket_Log(g_handle_log, &g_mutex_log, &g_handle_log, __FILE__, __LINE__, lever, status, fmt, args);
	
	va_end(args);
}
//#define socket_log(level, status, x...)	do {printf(x); printf("\r\n\n");}while (0)
#endif

#define socket_log(lever, status, x...) Socket_Log(g_handle_log, &g_mutex_log, &g_handle_log, __FILE__, __LINE__, lever, status, ##x);

void *test_child_write_log(void *arg)
{
	while(1)
	{
		socket_log(1,0, "func test_child_write_log() OK 1, %d", 1111 );
		//sleep(1);
		usleep(1000000);
	}
}
void *test_child_write_log_two(void *arg)
{
	while(1)
	{
		socket_log(1, 2, "func test_child_write_log_two() OK 2, %d", 2222 );
		//sleep(1);
		usleep(1000000);
	}
}

void *test_child_write_log_three(void *arg)
{
	while(1)
	{
		socket_log(1, 3, "func test_child_write_log_three() OK 3, %d", 3333 );
		usleep(1000000);
	}
}
void *test_child_write_log_four(void *arg)
{
	while(1)
	{
		socket_log(1, 4, "func test_child_write_log_four() OK 4, %d", 4444 );
		usleep(1000000);
	}
}
void *test_child_write_log_five(void *arg)
{
	while(1)
	{
		socket_log(1, 5, "func test_child_write_log_five() OK 5, %d", 5555 );
		//sleep(1);
		usleep(1000000);
	}
}
void *test_child_write_log_six(void *arg)
{
	while(1)
	{
		socket_log(1, 2, "func test_child_write_log_six() OK 6, %d", 6666 );
		//sleep(1);
		usleep(1000000);
	}
}




#define MODIFY(y)	do{ printf("Enter : %d ...\n", *y);\
					*y = 15;\
					printf("Modify : %d ...\n", *y);}while(0)

int main()
{
	int ret = 0;
	int i = 0;
	pthread_t thread[100];

	MODIFY(&ret);


#if 1
	if((init_log(NULL, &g_handle_log)) < 0)
	{
		printf("Err : func init_log() \n");
		return ret;
	}
	
	for(i = 0; i < 100; i++)
	{
		if(i < 20)
		{
			if((ret = pthread_create(&thread[i], NULL, test_child_write_log, NULL)) < 0)
			{
				printf("Err : func pthread_create() \n");
				return ret;
			}	
		}
		else if( 20 <= i && i < 50)
		{
			if((ret = pthread_create(&thread[i], NULL, test_child_write_log_two, NULL)) < 0)
			{
				printf("Err : func pthread_create() \n");
				return ret;
			}	
		}
		else if(50 <= i && i < 60)
		{
			if((ret = pthread_create(&thread[i], NULL, test_child_write_log_three, NULL)) < 0)
			{
				printf("Err : func pthread_create() \n");
				return ret;
			}	

		}
		else if(60 <= i && i < 80)
		{
			if((ret = pthread_create(&thread[i], NULL, test_child_write_log_four, NULL)) < 0)
			{
				printf("Err : func pthread_create() \n");
				return ret;
			}	

		}
		else if(80 <= i && i < 95)
		{
			if((ret = pthread_create(&thread[i], NULL, test_child_write_log_five, NULL)) < 0)
			{
				printf("Err : func pthread_create() \n");
				return ret;
			}	

		}
		else 
		{
			if((ret = pthread_create(&thread[i], NULL, test_child_write_log_six, NULL)) < 0)
			{
				printf("Err : func pthread_create() \n");
				return ret;
			}	

		}
	}

	for(i = 0; i < 100; i++)
	{	
		//	int pthread_join(pthread_t thread, void **retval);
		pthread_join(thread[i], NULL);
	}
#endif
	return 0;
}

