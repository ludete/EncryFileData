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
char* my_decrypt(char *str, int lenth, char *privatePathKey);


/*加密; 采用证书; 证书与公钥的不同之处在于: 证书中包含 公钥和 其他申请人信息
*@param : str 加密数据地址
*@param : len 加密数据长度
*@param : publicPathKey 指定加密数据公钥
*@retval: success encrypt Data address; fail NULL;
*/
char* my_encrypt_publicCert(char *str, int lenth, int *enDataLenth, char *publicPathKey);


#ifdef __cplusplus
}
#endif

#endif