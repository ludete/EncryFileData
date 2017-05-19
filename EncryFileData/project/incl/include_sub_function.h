#ifndef _INCLUDE_SUB_FUNCTION_H_
#define _INCLUDE_SUB_FUNCTION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#define myprint( x...) do {char bufMessagePut_Stdout_[1024];\
        sprintf(bufMessagePut_Stdout_, x);\
        fprintf(stdout, "%s [%d], [%s]\n", bufMessagePut_Stdout_,__LINE__, __FILE__ );\
   }while (0)

#define  MY_MIN(x, y)	((x) < (y) ? (x) : (y))

/*��ʵ��system ����
*@param : cmd_line ָ������
*@retval: success The cmd shell return value > 0; fail -1;
*/
int pox_system(const char *cmd_line); 

/*��ȡ�Ӵ���ĸ���е�λ��
*@param : full_data 	  ĸ�����ݵ�ַ
*@param : full_data_len   ĸ�����ݳ���
*@param : substr		  �Ӵ�����
*@retval: success find The location, fail NULL;
*/
char* memstr(char* full_data, int full_data_len, char* substr); 

/*get The file size
*@param : filename The check filePath or fileName
*@retval: fail -1; success The file size >= 0
*/
int get_file_size(char* filename); 

/*�ж�ָ���ļ��Ƿ����
*@param : filePath  ָ���ļ�·��
*@retval: exist true,  absent false;
*/
bool if_file_exist(const char *filePath);

/* get The Number of encryption
*@param : filePath   ָ���ļ�·��
*@retval: baseSize   ����ķָ����
*@retval: success The Number of encryption, fail -1;
*/
int get_encryNum_fromFile(char *fileName, int baseSize);


/*��ȡ�ļ��ܼ��������ִ�,��Ҫ���߳�����
*@param : workRounds   		�ļ����ܵ����ִ�
*@retval: liveThreadNum   	�̳߳ش���߳�����
*@param : lowRoundNum       ÿ���̹߳���������ִ�
*@retval: success The Number of thread, fail -1;
*/
int get_workThreadNum(int workRounds, int liveThreadNum, int *lowRoundNum);

/*�������/���� ���ļ�, ������߳��� �� ÿ���߳�����Ĺ�����
*
*
*/
int get_workSize_thread(char *fileName, int baseSize, int liveThrnum, int *workThreadNum, int *beforeThreadSize, int *behindThreadSize, int *perRound, int *modSize);



#ifdef __cplusplus
}
#endif

#endif
