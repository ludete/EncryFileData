
//socketlog.h 日志头文件
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
const char *file：文件名称
int line：文件行号
int level：错误级别
		0 -- 没有日志
		1 -- debug级别
		2 -- info级别
		3 -- warning级别
		4 -- err级别
int status：错误码
const char *fmt：可变参数
*/
/************************************************************************/
//实际使用的Level
extern int  SocketLevel[5];
typedef int Handle;



//#define socket_log(handle, mutex, level, status, x...)	Socket_Log(handle, mutex, __FILE__, __LINE__, level, status, ##x)
//#define socket_log(level, status, x...)	do {printf(x); printf("\r\n\n");}while (0)



/*��־ģ���ʼ��
*@param : fileName ��־�ļ�, ΪNULLʱ,���յ�ǰ��־�Զ�����, 
*@param : Handle  ��־���
*@retval: success 0; fail -1;
*/
int init_log(char *fileName, Handle *handle);

/*������־�ļ�ģ��
*@param : Handle ��־�ļ����
*@retval: success 0; fail -1;
*/
int destroy_log(Handle handle);

/*����־�ļ������LOG����
*@param : handle ��־���
*@param : file   �����ļ�
*@param : line	 ��������
*@param : level  ��־����
*@param : status ��־״̬��
*@param : fmt	 ��־����
*@param : mutex  ������
*@param : handleSrc ���ļ��ﵽ���ֵʱ, �������ļ��ľ��
*@param : success 0, fail -1;
*/
//int Socket_Log(Handle handle, pthread_mutex_t *mutex, Handle *handleSrc, const char *file, int line,  int level, int status, const char *fmt, va_list args);
int Socket_Log(Handle handle, pthread_mutex_t *mutex, Handle *handleSrc, const char *file, int line,  int level, int status, const char *fmt, ...);




#if defined(__cplusplus)
}
#endif


#endif
