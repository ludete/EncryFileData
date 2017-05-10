#ifndef _ENCRYPT_DATA_H_
#define _ENCRYPT_DATA_H_


#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define FILENAMELENTH  1024
typedef struct _encry_handle encryHandle_t;

/*����; ���ù�Կ
*@param : str �������ݵ�ַ
*@param : len �������ݳ���
*@param : publicPathKey ָ���������ݹ�Կ
*@retval: success encrypt Data address; fail NULL;
*/
char* my_encrypt_publicKey(char *str, int lenth, char *publicPathKey);


/*����; ����˽Կ;
*@param : str �������ݵ�ַ
*@param : len �������ݳ���
*@param : privatePathKey ָ����������˽Կ
*@retval: success encrypt Data address; fail NULL;
*/
char* my_decrypt(char *str, int lenth, int *deDataLenth, char *privatePathKey);


/*����; ����֤��; ֤���빫Կ�Ĳ�֮ͬ������: ֤���а��� ��Կ�� ������������Ϣ
*@param : str �������ݵ�ַ
*@param : len �������ݳ���
*@param : publicPathKey ָ���������ݹ�Կ
*@retval: success encrypt Data address; fail NULL;
*/
char* my_encrypt_publicCert(char *str, int lenth, int *enDataLenth, char *publicPathKey);

/*�����ļ�
*@param : filePath 		�ļ��ľ���·��
*@param : publicPathKey ָ���������ݹ�Կ
*@retval: success 0, fail -1;
*/
int encryptFileData(char *filePath, char *publicPathKey);

/*�����ļ�
*@param : filePath 		 �ļ��ľ���·��
*@param : privatePathKey ָ����������˽Կ
*@retval: success 0, fail -1;
*/
int decryptFileData(char *filePath, char *privatePathKey);

/*get the certficate news 
*@param : publicPathKey : ֤���ļ���
*@retval: success 0; fail -1;
*/
int get_cert_pubKey( EVP_PKEY **evpKey, BIO  **bioHandle, RSA  **pRsa, char *publicPathKey);

/*get The private Key News
*@param : pRsa :  ˽Կ��Ϣ
*@param : privatePathKey : ˽Կ�ļ���
*@retval: success 0; fail -1;
*/
int get_privateKey_new(RSA  **pRsa, char *privatePathKey);

/*encry data  ��������
*@param : str 		 	 ԭʼ����
*@param : lenth 		 ԭʼ���ݳ���
*@param : enData 		 ��������
*@param : pRsa 		 	 ���ܹ�Կ��Ϣ
*@retval: success �������ݳ���; fail -1;
*/ 
int encry_data(char *str, int lenth, char *enData, RSA *pRsa);

/*decry data  ��������
*@param : str 		 	 ԭʼ����
*@param : lenth 		 ԭʼ���ݳ���
*@param : enData 		 ��������
*@param : pRsa 		 	 ����˽Կ��Ϣ
*@retval: success �������ݳ���; fail -1;
*/ 
int decry_data(char *str, int lenth, char *deData, RSA *pRsa);


#ifdef __cplusplus
}
#endif

#endif