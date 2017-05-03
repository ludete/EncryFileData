#ifndef _ENCRYPT_DATA_H_
#define _ENCRYPT_DATA_H_


#ifdef __cplusplus
extern "C" {
#endif



#define myprint( x...) do {char bufMessagePut_Stdout_[1024];\
        sprintf(bufMessagePut_Stdout_, x);\
        fprintf(stdout, "%s [%d], [%s]\n", bufMessagePut_Stdout_,__LINE__, __FILE__ );\
   }while (0)

/*����
*@param : str �������ݵ�ַ
*@param : len �������ݳ���
*@param : publicPathKey ָ���������ݹ�Կ
*@retval: success encrypt Data address; fail NULL;
*/
char* my_encrypt(char *str, int lenth, char *publicPathKey);


/*����
*@param : str �������ݵ�ַ
*@param : len �������ݳ���
*@param : privatePathKey ָ����������˽Կ
*@retval: success encrypt Data address; fail NULL;
*/
char* my_decrypt(char *str, int lenth, char *privatePathKey);

#ifdef __cplusplus
}
#endif

#endif