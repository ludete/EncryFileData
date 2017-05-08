#ifndef _ENCRYPT_DATA_H_
#define _ENCRYPT_DATA_H_


#ifdef __cplusplus
extern "C" {
#endif

#define FILENAMELENTH  1024

#define myprint( x...) do {char bufMessagePut_Stdout_[1024];\
        sprintf(bufMessagePut_Stdout_, x);\
        fprintf(stdout, "%s [%d], [%s]\n", bufMessagePut_Stdout_,__LINE__, __FILE__ );\
   }while (0)

#define  MY_MIN(x, y)	((x) < (y) ? (x) : (y))

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

#ifdef __cplusplus
}
#endif

#endif