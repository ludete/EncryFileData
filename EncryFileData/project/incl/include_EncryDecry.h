#ifndef _INCLUDE_ENCRY_DECRY_H_
#define _INCLUDE_ENCRY_DECRY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "encryDecryFile.h"

int encry_data(char *str, int lenth, char *enData, void *pRsa);

int decry_data(char *str, int lenth, char *deData, void *pRsa);

void package_encry_file_name(char *filePath, char *encFileName);

void package_decry_file_name(char *filePath, char *decFileName);

void package_AES_RSA_encry_file_name(char *filePath, char *encFileName);

void package_AES_RSA_decry_file_name(char *filePath, char *decFileName);

void package_AES_RSA_decry_dirfile_name(char *filePath,char *storeDir, char *decFileName);

void package_AES_RSA_encry_dirfile_name(char *filePath, char *storeDir, char *encFileName);

/*获取证书文件信息
*@param : pRsa : 公钥信息
*@param : publicPathKey : 证书文件路径
*/
retval_t get_cert_pubKey(void  **pRsa, char *publicPathKey);

/*获取公钥信息
*@param : pRsa : 公钥信息
*@param : publicKey : 公钥文件路径
*/
retval_t get_public_key(void **pRsa, char *publicKey);

int get_privateKey_new(void  **pRsa, char *privatePathKey);


#ifdef __cplusplus
}
#endif

#endif

