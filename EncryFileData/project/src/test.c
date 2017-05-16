#include <stdio.h>  
#include <stdlib.h>  
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>



void *child_func(void *arg)
{
	//pthread_detach(pthread_self());
#if 1

	int fd = 0;
	if((fd = open("hello", O_WRONLY | O_CREAT, 0777)) < 0)
	{
		printf("Err : open(), [%d],[%s]\n", __LINE__, __FILE__);		
	}
	else
	{
		printf("open() OK!!!!\n");
	}
	if(fd > 0)	close(fd);
#endif

#if 0
	FILE *fp = NULL;
	if((fp = fopen("hello", "a+")) == NULL )
	{
		printf("Err : fopen(), [%d],[%s]\n", __LINE__, __FILE__);
	}
	else
	{
		printf("fopen() OK!!!!\n");
	}

	if(fp)	fclose(fp);	
#endif	
	
	pthread_exit(NULL);
}


int main(int argc, char* argv[])  
{  
    int i =0;
	pthread_t pthid[5];

	for(i =0; i < 5; i++)
	{
		pthread_create(&pthid[i], NULL, child_func, NULL);

	}

	for(i = 0; i < 5; i++)
		pthread_join( pthid[i], NULL);

    return 0;  
} 

