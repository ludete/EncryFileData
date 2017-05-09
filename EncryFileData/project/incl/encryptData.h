#ifndef _ENCRYPT_DATA_H_
#define _ENCRYPT_DATA_H_


#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#define FILENAMELENTH  1024

#define myprint( x...) do {char bufMessagePut_Stdout_[1024];\
        sprintf(bufMessagePut_Stdout_, x);\
        fprintf(stdout, "%s [%d], [%s]\n", bufMessagePut_Stdout_,__LINE__, __FILE__ );\
   }while (0)

#define  MY_MIN(x, y)	((x) < (y) ? (x) : (y))

/*加密; 采用公钥
*@param : str 加密数据地址
*@param : len 加密数据长度
*@param : publicPathKey 指定加密数据公钥
*@retval: success encrypt Data address; fail NULL;
*/
char* my_encrypt_publicKey(char *str, int lenth, char *publicPathKey);


/*解密; 采用私钥;
*@param : str 加密数据地址
*@param : len 加密数据长度
*@param : privatePathKey 指定解密数据私钥
*@retval: success encrypt Data address; fail NULL;
*/
char* my_decrypt(char *str, int lenth, int *deDataLenth, char *privatePathKey);


/*加密; 采用证书; 证书与公钥的不同之处在于: 证书中包含 公钥和 其他申请人信息
*@param : str 加密数据地址
*@param : len 加密数据长度
*@param : publicPathKey 指定加密数据公钥
*@retval: success encrypt Data address; fail NULL;
*/
char* my_encrypt_publicCert(char *str, int lenth, int *enDataLenth, char *publicPathKey);

/*加密文件
*@param : filePath 		文件的绝对路径
*@param : publicPathKey 指定加密数据公钥
*@retval: success 0, fail -1;
*/
int encryptFileData(char *filePath, char *publicPathKey);

/*解密文件
*@param : filePath 		 文件的绝对路径
*@param : privatePathKey 指定解密数据私钥
*@retval: success 0, fail -1;
*/
int decryptFileData(char *filePath, char *privatePathKey);

/*判断指定文件是否存在
*@param : filePath  指定文件路径
*@retval: exist true,  absent false;
*/
bool if_file_exist(const char *filePath);


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



#ifdef __cplusplus
}
#endif

#endif