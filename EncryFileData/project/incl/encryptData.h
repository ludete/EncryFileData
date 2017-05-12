#ifndef _ENCRYPT_DATA_H_
#define _ENCRYPT_DATA_H_


#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "thread_pool.h"

#define FILENAMELENTH  1024
typedef struct _encry_handle encryHandle_t;

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

/*get the certficate news 
*@param : publicPathKey : 证书文件名
*@retval: success 0; fail -1;
*/
int get_cert_pubKey( RSA  **pRsa, char *publicPathKey);

/*get The private Key News
*@param : pRsa :  私钥信息
*@param : privatePathKey : 私钥文件名
*@retval: success 0; fail -1;
*/
int get_privateKey_new(RSA  **pRsa, char *privatePathKey);

/*encry data  加密数据
*@param : str 		 	 原始数据
*@param : lenth 		 原始数据长度
*@param : enData 		 加密数据
*@param : pRsa 		 	 加密公钥信息
*@retval: success 加密数据长度; fail -1;
*/ 
int encry_data(char *str, int lenth, char *enData, RSA *pRsa);

/*decry data  解密数据
*@param : str 		 	 原始数据
*@param : lenth 		 原始数据长度
*@param : enData 		 解密数据
*@param : pRsa 		 	 解密私钥信息
*@retval: success 解密数据长度; fail -1;
*/ 
int decry_data(char *str, int lenth, char *deData, RSA *pRsa);

/*获取剩余文件的 加密所需的最小线程数(即剩余文件的最小工作轮次) 以及 (所有线程工作量)最后剩余的文件大小
*@param : filePath 		 	 文件路径
*@param : threadNum 		 该文件所需工作线程的数量
*@param : lowRoundNum 		 所需线程的最小工作轮次
*@param : baseSize 		 	 文件计算的分割基数
*@param : size				 最后剩余文件大小
*@retval: success 解密数据长度; fail -1;
*/
int get_residueSize_needThreadNum(char *filePath, int threadNum, 
	int lowRoundNum, int baseSize, int *size);

/*拼装加密后的文件名
*@param : filePath   		原始文件绝对路径或相对路径(或文件名)
*@param : encFileName   	加密后文件绝对路径或相对路径(或文件名)
*/
void package_encry_file_name(char *filePath, char *encFileName);


/*组装 解密文件名
*@param : filePath   		原始文件绝对路径或相对路径(或文件名)
*@param : decFileName   	加密后文件绝对路径或相对路径(或文件名)
*/
void package_decry_file_name(char *filePath, char *decFileName);

threadpool_t *init_thread_pool();

void decry_process(void *arg);

int multiDecryFile(char *filePath, char *privatePathKey, threadpool_t *pool);

int destroy(threadpool_t *pool );

#ifdef __cplusplus
}
#endif

#endif