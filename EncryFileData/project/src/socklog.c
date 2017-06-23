#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>


#include "socklog.h"

#define ITCAST_DEBUG_FILE_	"socketlib.log"
#define ITCAST_DEBUG_DIR_   "LOG"
#define ITCAST_MAX_STRING_LEN 		5120
#define FILE_MAX_LENTH 		1.5 * 1024 * 1024 * 1024


//Levelç±»åˆ«
#define IC_NO_LOG_LEVEL			0
#define IC_DEBUG_LEVEL			1
#define IC_INFO_LEVEL			2
#define IC_WARNING_LEVEL		3
#define IC_ERROR_LEVEL			4

int  SocketLevel[5] = {IC_NO_LOG_LEVEL, IC_DEBUG_LEVEL, IC_INFO_LEVEL, IC_WARNING_LEVEL, IC_ERROR_LEVEL};

//Levelçš„åç§°
char ICLevelName[5][10] = {"NOLOG", "DEBUG", "INFO", "WARNING", "ERROR"};


/*
*@param : pf ÎÄ¼şÃèÊö·û
*@retval: success 0, fail -1;
*/
static int ITCAST_Error_GetCurTime(char* strTime)
{
	struct tm*		tmTime = NULL;
	size_t			timeLen = 0;
	time_t			tTime = 0;	
	
	tTime = time(NULL);
	tmTime = localtime(&tTime);
	timeLen = strftime(strTime, 33, "%Y.%m.%d %H:%M:%S", tmTime);
	
	return timeLen;
}

/*´´½¨²¢´ò¿ªÎÄ¼ş
*@param : pf ÎÄ¼şÃèÊö·û
*@retval: success 0, fail -1;
*/
static int ITCAST_Error_OpenFile(int* pf)
{
	char	fileName[1024];
	struct tm*		tmTime = NULL;
	time_t			tTime = 0;
	char   tmpfile[120] = { 0 };
	char   strTime[15] = { 0 };
	memset(fileName, 0, sizeof(fileName));
	static int index = 0;
	
	//1.»ñÈ¡Ê±¼ä
	tTime = time(NULL);
	tmTime = localtime(&tTime);	
	strftime(strTime, 33, "%Y.%m.%d-", tmTime);

	//2.ÎÄ¼şÃû³Æ
	sprintf(tmpfile, "%s%03d%s",  strTime, index++, ITCAST_DEBUG_FILE_);
	//3.ÎÄ¼ş¾ø¶ÔÂ·¾¶
	sprintf(fileName, "./%s/%s", ITCAST_DEBUG_DIR_ ,tmpfile);
	//4.´´½¨Ä¿Â¼
    mkdir(ITCAST_DEBUG_DIR_, 0755);
	//5.ÒÔ×·¼ÓµÄ·½Ê½´ò¿ªÎÄ¼ş
    *pf = open(fileName, O_WRONLY|O_CREAT|O_APPEND, 0666);
    if(*pf < 0)
    {
        return -1;
    }

	return 0;
}


static int ITCAST_Error_Core(Handle handle, pthread_mutex_t *mutex, Handle *handleSrc, const char *file, int line, int level, int status, const char *fmt, va_list args)
{
    char str[ITCAST_MAX_STRING_LEN];		//LOGÈÕÖ¾ÄÚÈİ
    int	 strLen = 0;						//ÈÕÖ¾ÄÚÈİ³¤¶È
    char tmpStr[64];						//LOGÈÕÖ¾Ê±¼ä
    int	 tmpStrLen = 0;
    int  pf = (int)handle;					//ÎÄ¼ş¾ä±ú
    int  ret = 0, len = 0, nWriteLen = 0;
	
    //1. ³õÊ¼»¯
    memset(str, 0, ITCAST_MAX_STRING_LEN);
    memset(tmpStr, 0, 64);
    
    //2. »ñÈ¡µ±Ç°Ğ´LOGµÄÊ±¼ä
    tmpStrLen = ITCAST_Error_GetCurTime(tmpStr);
    tmpStrLen = sprintf(str, "[%s] ", tmpStr);
    strLen = tmpStrLen;

    //3. ÈÕÖ¾µÈ¼¶
    tmpStrLen = sprintf(str+strLen, "[%s] ", ICLevelName[level]);
    strLen += tmpStrLen;
    
    //4. ÈÕÖ¾×´Ì¬Âë
    if (status != 0) 
    {
        tmpStrLen = sprintf(str+strLen, "[ERRNO is %d] ", status);
    }
    else
    {
    	tmpStrLen = sprintf(str+strLen, "[SUCCESS] ");
    }
    strLen += tmpStrLen;

    //5. LOGÈÕÖ¾ÄÚÈİ(¼´¿É±ä²ÎÊıµÄÊı¾İ)
    tmpStrLen = vsprintf(str+strLen, fmt, args);
    strLen += tmpStrLen;

    //6. LOG ÈÕÖ¾·¢ÉúµÄÎÄ¼ş
    tmpStrLen = sprintf(str+strLen, " [%s]", file);
    strLen += tmpStrLen;

    //7. LOG ÈÕÖ¾·¢ÉúµÄĞĞÊı
    tmpStrLen = sprintf(str+strLen, " [%d]\n", line);
    strLen += tmpStrLen;    

	pthread_mutex_lock(mutex);
    //8. Ğ´ÈëÊı¾İ, ÏÈÅĞ¶Ïµ±Ç°ÎÄ¼ş´óĞ¡
    if(lseek(pf, 0, SEEK_END) + strLen < FILE_MAX_LENTH)
   	{
   		while(nWriteLen < strLen)
		{
			if((len = write(pf, str+nWriteLen, strLen - nWriteLen)) < 0)
			{
				printf("Err : func write(), [%d], [%s]\n", __LINE__, __FILE__);
				ret = -1;
				goto End;
			}
			nWriteLen += len;
		}
    }
	else
	{
		close(pf);	// ÎÄ¼ş¹ı´ó, ¹Ø±Õµ±Ç°ÎÄ¼ş, ĞÂ½¨ÎÄ¼ş
		if((ITCAST_Error_OpenFile(&pf)) < 0)
		{
			printf("The LogFile is MAXSIZE == %f, create a new file Error, [%d], [%s]\n", FILE_MAX_LENTH,__LINE__, __FILE__);
			ret = -1;
			goto End;
		}
		while(nWriteLen < strLen)
		{
			if((len = write(pf, str+nWriteLen, strLen - nWriteLen)) < 0)
			{
				printf("Err : func write(), [%d], [%s]\n", __LINE__, __FILE__);
				ret = -1;
				goto End;
			}
			nWriteLen += len;
		}
		*((int*)handleSrc) = pf;
	}

End:

	pthread_mutex_unlock(mutex);

	return ret;
}

int Socket_Log(Handle handle, pthread_mutex_t *mutex, Handle *handleSrc, const char *file, int line,  int level, int status, const char *fmt, ...)
{
	int ret = 0;
	va_list args;
	
	//1.ÅĞ¶ÏÊÇ·ñĞèÒªĞ´LOG
	if(level == IC_NO_LOG_LEVEL)
	{
		goto End;
	}


	//2.µ÷ÓÃºËĞÄµÄĞ´LOGº¯Êı
	va_start(args, fmt);
	ret = ITCAST_Error_Core(handle, mutex, handleSrc, file,line, level, status, fmt, args);
	va_end(args);

End:
	
	return ret;
}


int Socket_Log02(Handle handle, pthread_mutex_t *mutex, Handle *handleSrc, const char *file, int line,  int level, int status, const char *fmt, va_list args)
{
	int ret = 0;


	//1.ÅĞ¶ÏÊÇ·ñĞèÒªĞ´LOG
	if(level == IC_NO_LOG_LEVEL)
	{
		goto End;
	}

	//2.µ÷ÓÃºËĞÄµÄĞ´LOGº¯Êı
	ret = ITCAST_Error_Core(handle, mutex, handleSrc, file,line, level, status, fmt, args);

End:

	return ret;
}

/*ÈÕÖ¾Ä£¿é³õÊ¼»¯
*@param : fileName ÈÕÖ¾ÎÄ¼ş, ÎªNULLÊ±,°´ÕÕµ±Ç°ÈÕÖ¾×Ô¶¯Éú³É, 
*@param : Handle  ÈÕÖ¾¾ä±ú
*@retval: success 0; fail -1;
*/
int init_log(char *fileName, Handle *handle)
{
	int 	ret = 0;
	int 	pf = 0;
	char 	fileNamePath[1024] = { 0 };
	
	if(!handle)
	{
		printf("Err : func init_log(), Handle : %p, [%d],[%s]", handle, __LINE__, __FILE__);
		ret = -1;
		goto End;
	}

	//1. Ãû³ÆÎªNULL, ²ÉÓÃÄ¬ÈÏÃû³Æ
	if(!fileName)
	{
		if((ret = ITCAST_Error_OpenFile(&pf)) < 0)
		{
			printf("Err : func ITCAST_Error_OpenFile() [%d],[%s]", __LINE__, __FILE__);
			ret = -1;
			goto End;
		}
	}
	else
	{		
		//2.´´½¨Ä¿Â¼
		mkdir(ITCAST_DEBUG_DIR_, 0755);
		sprintf(fileNamePath, "./%s/%s", ITCAST_DEBUG_DIR_, fileName);
		//3.ÒÔ×·¼ÓµÄ·½Ê½´ò¿ªÎÄ¼ş
		if((pf = open(fileNamePath, O_WRONLY|O_CREAT|O_APPEND, 0666)) < 0)
		{
			printf("Err : func open() : %s, [%d],[%s]", fileNamePath, __LINE__, __FILE__);
			ret = -1;
			goto End;
		}
	}

	*((int*)handle) = pf;
End:

	return ret;
}

/*Ïú»ÙÈÕÖ¾ÎÄ¼şÄ£¿é
*@param : Handle ÈÕÖ¾ÎÄ¼ş¾ä±ú
*@retval: success 0; fail -1;
*/
int destroy_log(Handle handle)
{
	int fd = 0;

	if(handle <= 0)
	{
		printf("Err : func destroy_log() handle : %d, [%d],[%s]\n", handle, __LINE__, __FILE__);
		return  -1;		
	}
	fd = (int)handle;
	if((close(fd)) < 0)
	{
		printf("Err : func destroy_log() : %s, [%d],[%s]\n", strerror(errno), __LINE__, __FILE__);
		return	-1;
	}

	return 0;
}

