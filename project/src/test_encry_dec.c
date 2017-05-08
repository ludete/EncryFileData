#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include "encryptData.h"

//#define PRIVATEKEY 	"/home/yyx/MyEncryProject/EncryFileData/hostClientCert/client-key.pem"
//#define PUBLICKEY 	"/home/yyx/MyEncryProject/EncryFileData/hostClientCert/client-cert.pem"
#define PRIVATEKEY 	"/home/yyx/MyEncryProject/EncryFileData/clientCert/client-key.pem"
#define PUBLICKEY 	"/home/yyx/MyEncryProject/EncryFileData/clientCert/client-cert.pem"
int main()
{
	int ret = 0, i =0;
	char *str = "hello world";
	char *encryData = NULL;
	char *decData = NULL;
	int  enDataLenth = 0;
	char *buf = NULL;
	
	buf = malloc(245 + 1);
	memset(buf, 49, 245);
	buf[245] = '\0';
	
	printf("=========== 1 =============\n");
	if((encryData = my_encrypt_publicCert(buf, strlen(buf), &enDataLenth, PUBLICKEY)) == NULL)
	{
		ret = -1;
		myprint("Err : func my_encrypt(),  srcDataLenth : %d",strlen(buf));				 
		goto End;
	}
	printf("=========== 2 =============\n");
	if((decData = my_decrypt(encryData, enDataLenth, PRIVATEKEY)) == NULL)
	{
		ret = -1;
		myprint("Err : func my_encrypt()");
		goto End;
	}
	
	if(strcmp(buf, decData) == 0)		myprint("OK, SrcData : %s, encrypt : %s And decrypt : %s success", str, encryData, decData );
	else								myprint("Err, SrcData : %s, encrypt : %s And decrypt : %s fail", str, encryData, decData);
		
	
	myprint("====================== End ===================");

End:
		
	return ret;
}