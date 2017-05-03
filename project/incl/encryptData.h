#ifndef _ENCRYPT_DATA_H_
#define _ENCRYPT_DATA_H_


#ifdef __cplusplus
extern "C" {
#endif



#define myprint( x...) do {char bufMessagePut_Stdout_[1024];\
        sprintf(bufMessagePut_Stdout_, x);\
        fprintf(stdout, "%s [%d], [%s]\n", bufMessagePut_Stdout_,__LINE__, __FILE__ );\
   }while (0)

/*加密
*@param : str 加密数据地址
*@param : len 加密数据长度
*@param : publicPathKey 指定加密数据公钥
*@retval: success encrypt Data address; fail NULL;
*/
char* my_encrypt(char *str, int lenth, char *publicPathKey);


/*解密
*@param : str 加密数据地址
*@param : len 加密数据长度
*@param : privatePathKey 指定解密数据私钥
*@retval: success encrypt Data address; fail NULL;
*/
char* my_decrypt(char *str, int lenth, char *privatePathKey);

#ifdef __cplusplus
}
#endif

#endif