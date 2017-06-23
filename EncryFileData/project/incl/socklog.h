
//socketlog.h æ—¥å¿—å¤´æ–‡ä»¶
#ifndef _SOCKET_LOG_H_
#define _SOCKET_LOG_H_

#if defined(__cplusplus)
extern "C" {
#endif


/*
#define IC_NO_LOG_LEVEL			0
#define IC_DEBUG_LEVEL			1
#define IC_INFO_LEVEL			2
#define IC_WARNING_LEVEL		3
#define IC_ERROR_LEVEL			4;
*/

/************************************************************************/
/* 
const char *fileï¼šæ–‡ä»¶åç§°
int lineï¼šæ–‡ä»¶è¡Œå·
int levelï¼šé”™è¯¯çº§åˆ«
		0 -- æ²¡æœ‰æ—¥å¿—
		1 -- debugçº§åˆ«
		2 -- infoçº§åˆ«
		3 -- warningçº§åˆ«
		4 -- errçº§åˆ«
int statusï¼šé”™è¯¯ç 
const char *fmtï¼šå¯å˜å‚æ•°
*/
/************************************************************************/
//å®é™…ä½¿ç”¨çš„Level
extern int  SocketLevel[5];
typedef int Handle;



//#define socket_log(handle, mutex, level, status, x...)	Socket_Log(handle, mutex, __FILE__, __LINE__, level, status, ##x)
//#define socket_log(level, status, x...)	do {printf(x); printf("\r\n\n");}while (0)



/*ÈÕÖ¾Ä£¿é³õÊ¼»¯
*@param : fileName ÈÕÖ¾ÎÄ¼ş, ÎªNULLÊ±,°´ÕÕµ±Ç°ÈÕÖ¾×Ô¶¯Éú³É, 
*@param : Handle  ÈÕÖ¾¾ä±ú
*@retval: success 0; fail -1;
*/
int init_log(char *fileName, Handle *handle);

/*Ïú»ÙÈÕÖ¾ÎÄ¼şÄ£¿é
*@param : Handle ÈÕÖ¾ÎÄ¼ş¾ä±ú
*@retval: success 0; fail -1;
*/
int destroy_log(Handle handle);

/*ÏòÈÕÖ¾ÎÄ¼şÖĞÌí¼ÓLOGÄÚÈİ
*@param : handle ÈÕÖ¾¾ä±ú
*@param : file   ³ö´íÎÄ¼ş
*@param : line	 ³ö´íĞĞÊı
*@param : level  ÈÕÖ¾¼¶±ğ
*@param : status ÈÕÖ¾×´Ì¬Âë
*@param : fmt	 ÈÕÖ¾ÄÚÈİ
*@param : mutex  »¥³âËø
*@param : handleSrc µ±ÎÄ¼ş´ïµ½×î´óÖµÊ±, ´«³öĞÂÎÄ¼şµÄ¾ä±ú
*@param : success 0, fail -1;
*/
//int Socket_Log(Handle handle, pthread_mutex_t *mutex, Handle *handleSrc, const char *file, int line,  int level, int status, const char *fmt, va_list args);
int Socket_Log(Handle handle, pthread_mutex_t *mutex, Handle *handleSrc, const char *file, int line,  int level, int status, const char *fmt, ...);




#if defined(__cplusplus)
}
#endif


#endif
