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

/*��ȡ֤���ļ���Ϣ
*@param : pRsa : ��Կ��Ϣ
*@param : publicPathKey : ֤���ļ�·��
*/
retval_t get_cert_pubKey(void  **pRsa, char *publicPathKey);

/*��ȡ��Կ��Ϣ
*@param : pRsa : ��Կ��Ϣ
*@param : publicKey : ��Կ�ļ�·��
*/
retval_t get_public_key(void **pRsa, char *publicKey);

int get_privateKey_new(void  **pRsa, char *privatePathKey);


#ifdef __cplusplus
}
#endif

#endif

