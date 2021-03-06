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

/*自实现system 命令
*@param : cmd_line 指定命令
*@retval: success The cmd shell return value > 0; fail -1;
*/
int pox_system(const char *cmd_line); 

/*获取子串在母串中的位置
*@param : full_data 	  母串数据地址
*@param : full_data_len   母串数据长度
*@param : substr		  子串数据
*@retval: success find The location, fail NULL;
*/
char* memstr(char* full_data, int full_data_len, char* substr); 

/*get The file size
*@param : filename The check filePath or fileName
*@retval: fail -1; success The file size >= 0
*/
int get_file_size(char* filename); 

/*判断指定文件是否存在
*@param : filePath  指定文件路径
*@retval: exist true,  absent false;
*/
bool if_file_exist(const char *filePath);

/* get The Number of encryption
*@param : filePath   指定文件路径
*@retval: baseSize   计算的分割基数
*@retval: success The Number of encryption, fail -1;
*/
int get_encryNum_fromFile(char *fileName, int baseSize);


/*获取文件总加密任务轮次,需要的线程总数
*@param : workRounds   		文件加密的总轮次
*@retval: liveThreadNum   	线程池存活线程总数
*@param : lowRoundNum       每个线程工作的最低轮次
*@retval: success The Number of thread, fail -1;
*/
int get_workThreadNum(int workRounds, int liveThreadNum, int *lowRoundNum);

/*计算加密/解密 该文件, 所需的线程数 和 每个线程所需的工作量
*
*
*/
int get_workSize_thread(char *fileName, int baseSize, int liveThrnum, int *workThreadNum, int *beforeThreadSize, int *behindThreadSize, int *perRound, int *modSize);



#ifdef __cplusplus
}
#endif

#endif
