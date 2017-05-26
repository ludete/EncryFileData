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


//自实现 system 系统命令
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


//获取子串在母串中的位置
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


int get_workSize_thread(char *fileName, int baseSize, int liveThrnum, int *workThreadNum, int *beforeThreadSize, int *behindThreadSize, int *perRound, int *modSize)
{
	int ret = 0, fileSize = 0, totalRound = 0;
	int thrNum = 0;				//work thread Number
	int peerThreadRound = 0;	//peer Thread work Round
	int modFile = 0; 			//The file mod size
	
	if(!fileName || baseSize < 0 || liveThrnum <= 0 || !workThreadNum || !beforeThreadSize || !behindThreadSize)
	{
		myprint("Err : filename : %p, baseSize : %d, liveThrnum : %d, workThreadNum : %p, \
				beforeThreadSize : %p,behindThreadSize : %p ", 
				fileName, baseSize, liveThrnum, workThreadNum, beforeThreadSize, behindThreadSize);
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

	//2. caculate The total roundNum for encry or decry File 
	if((totalRound = fileSize / baseSize) == 0)
	{
		totalRound = 1;
	}

	//3. caculate The work Thread Number
	if(totalRound >= liveThrnum)		thrNum = liveThrnum;
	else								thrNum = totalRound;

	//4. caculate peer Thread work Round
	peerThreadRound = totalRound / thrNum;

	//5. caculate thread work FileSize
	if(baseSize < fileSize)
	{
		*beforeThreadSize = peerThreadRound * baseSize;
		if((modFile = fileSize - *beforeThreadSize * thrNum) > 0)
			*behindThreadSize = *beforeThreadSize + modFile;
	}
	else
	{
		*beforeThreadSize = fileSize;
	}
	
	*workThreadNum = thrNum;
	*perRound = peerThreadRound;
	*modSize = modFile;

End:

	return ret;
}


// get The Number of encryption round
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
	ret = fileSize / baseSize;
	
End:

	return ret;
}


int get_workThreadNum(int workRounds, int liveThreadNum, int *lowRoundNum)
{ 
	int workThreadNum = 0;
	
	if(workRounds < 0 || liveThreadNum < 0 || !lowRoundNum)
	{
		myprint("Err : workRounds : %d, liveThreadNum : %d ", workRounds, liveThreadNum);
		workThreadNum = -1;
		goto End;
	}

	//1. get The Number of encryption 
	if(workRounds > liveThreadNum)					workThreadNum = liveThreadNum;		
	else											workThreadNum = workRounds;		

	//2. get The low round Number for per-thread
	if(workThreadNum == liveThreadNum)
	{
		*lowRoundNum = workRounds / (workThreadNum );		
	}
	else
	{
		*lowRoundNum = 0;
 	}
		
End:

	return workThreadNum;
}

