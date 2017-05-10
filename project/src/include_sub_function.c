#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>

#include "include_sub_function.h"


typedef void (*sighandler_t)(int);


//��ʵ�� system ϵͳ����
int pox_system(const char *cmd_line) 
{ 
	int ret = 0; 	
	sighandler_t old_handler; 
	old_handler = signal(SIGCHLD, SIG_DFL); 
	ret = system(cmd_line); 
	signal(SIGCHLD, old_handler); 

	if(ret == 127)
	{
		printf("Err : The cmd is absent, no Find cmd\n");
		ret = -1;
	}
	
	return ret; 
}


//��ȡ�Ӵ���ĸ���е�λ��
char* memstr(char* full_data, int full_data_len, char* substr) 
{ 
     if (full_data == NULL || full_data_len <= 0 || substr == NULL) { 
         return NULL; 
     } 
     if (*substr == '\0') { 
         return NULL; 
     } 
     int sublen = strlen(substr); 
     int i; 
     char* cur = full_data; 
     int last_possible = full_data_len - sublen + 1; 
     for (i = 0; i < last_possible; i++) { 
         if (*cur == *substr) { 
             //assert(full_data_len - i >= sublen);  
             if (memcmp(cur, substr, sublen) == 0) { 
                 //found  
                 return cur; 
             } 
        } 
         cur++; 
     }                                                                                                                                                    

     return NULL;
}

//get The file size
int get_file_size(char* filename)  
{  
	if(!filename)		return -1;
    struct stat statbuf;  
    stat(filename,&statbuf);  
    int size=statbuf.st_size;  
  
    return size;  
}

//juege The specify File exist 
bool if_file_exist(const char *filePath)
{
	if(filePath == NULL)
		assert(0);
	if(access(filePath, F_OK) == 0)
		return true;

	return false;
}


// get The Number of encryption
int get_encryNum_fromFile(char *fileName, int baseSize)
{
	int ret = 0, fileSize = 0;
	if(!fileName || baseSize < 0)
	{
		myprint("Err : filename : %p, baseSize : %d ", fileName, baseSize);
		ret = -1;
		goto End;
	}

	//1. get The file Size
	if((fileSize = get_file_size(fileName)) < 0)
	{
		myprint("Err : func get_file_size() ");
		ret = -1;
		goto End;
	}

	//2. get The Number of encryption
	if( (fileSize % baseSize) > 0 )
		ret = fileSize / baseSize + 1;
	else
		ret = fileSize / baseSize;
	
End:

	return ret;
}

//
int get_workThreadNum(int workRounds, int liveThreadNum)
{
	int ret = 0;
	
	if(workRounds < 0 || liveThreadNum < 0)
	{
		myprint("Err : workRounds : %d, liveThreadNum : %d ", workRounds, liveThreadNum);
		ret = -1;
		goto End;
	}

	//1. get The Number of encryption
	if( (workRounds % liveThreadNum) > 0 )
		ret = workRounds / liveThreadNum + 1;
	else
		ret = workRounds / liveThreadNum;

End:

	return ret;
}

