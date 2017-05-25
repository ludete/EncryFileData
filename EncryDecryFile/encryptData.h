#ifndef _ENCRYPT_DATA_H_
#define _ENCRYPT_DATA_H_


#ifdef __cplusplus
extern "C" {
#endif


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




/*��ȡʣ���ļ��� �����������С�߳���(��ʣ���ļ�����С�����ִ�) �Լ� (�����̹߳�����)���ʣ����ļ���С
*@param : filePath 		 	 �ļ�·��
*@param : threadNum 		 	 ���ļ����蹤���̵߳�����
*@param : lowRoundNum 		 �����̵߳���С�����ִ�
*@param : baseSize 		 	 �ļ�����ķָ����
*@param : size				 ���ʣ���ļ���С
*@retval: success �������ݳ���; fail -1;
*/
int get_residueSize_needThreadNum(char *filePath, int threadNum, 
	int lowRoundNum, int baseSize, int *size);

/*ƴװ���ܺ���ļ���
*@param : filePath   		ԭʼ�ļ�����·�������·��(���ļ���)
*@param : encFileName   	���ܺ��ļ�����·�������·��(���ļ���)
*/
void package_encry_file_name(char *filePath, char *encFileName);

/*��װ �����ļ���
*@param : filePath   		ԭʼ�ļ�����·�������·��(���ļ���)
*@param : decFileName   	���ܺ��ļ�����·�������·��(���ļ���)
*/
void package_decry_file_name(char *filePath, char *decFileName);

/*��ʼ��, ȫ�ֱ���, �����̳߳�
*@retval: success : �����̳߳� ; fail : NULL
*/
void *init();

/* �����ļ��̹߳��� ����
*@param : arg : �������
*/
void decry_process(void *arg);

/* �����ļ��̹߳��� ����
*@param : arg : �������
*/
void encry_process(void *arg);

/*���߳̽����ļ��ӿ�
*@param : filePath 		 �ļ��ľ���·��
*@param : privatePathKey ָ����������˽Կ
*@param : pool 			 �����̳߳�
*@retval: success 0, fail -1;
*/
int multiDecryFile(char *filePath, char *privatePathKey, void *pool);


int multiDecryFile_inFileFp(char *filePath, char *privatePathKey, void *pool);

/*���ٳ���: �����̳߳�, ȫ�ֱ���
*@param : pool 			 �����̳߳�
*@retval: success 0; fail -1;
*/
int destroy(void *pool );

/*�ԳƼ����㷨�����ļ�, AES
*@param : file 		 	 ԭʼ�ļ��ľ���·��
*@param : passwd 		 ָ�������ļ���������Կ
*@retval: success 0, fail -1;
*/
int encry_file_AES(char *file, char *passwd);

/*�ԳƼ����㷨�����ļ�, AES
*@param : file 		 	 ԭʼ�ļ��ľ���·��
*@param : passwd 		 ָ�������ļ���������Կ
*@retval: success 0, fail -1;
*/
int decry_file_AES(char *file, char *passWdSrc);


int mix_RSA_AES_decryFile(char *file, char *privatePathKey);

int mix_RSA_AES_encryFile(char *file, char *passWdSrc, char *publicPathKey);

#ifdef __cplusplus
}
#endif

#endif
