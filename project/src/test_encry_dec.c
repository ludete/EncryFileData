#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include "encryptData.h"

#define PRIVATEKEY 	"/home/yyx/MyEncryProject/client2/client-key.pem"
#define PUBLICKEY 	"/home/yyx/MyEncryProject/client2/client-cert.pem"

int main()
{
	int ret = 0;
	char *str = "hello world";
	char *encryData = NULL;
	char *decData = NULL;
	
	
	if((encryData = my_encrypt(str, strlen(str), PUBLICKEY)) == NULL)
	{
		ret = -1;
		myprint("Err : func my_encrypt()");
		goto End;
	}
	
	if((decData = my_decrypt(encryData, strlen(encryData), PRIVATEKEY)) == NULL)
	{
		ret = -1;
		myprint("Err : func my_encrypt()");
		goto End;
	}
	
	if(strcmp(str, decData) == 0)		myprint("OK, encrypt : %s And decrypt : %s success",encryData, decData );
	else								myprint("Err, encrypt : %s And decrypt : %s fail", encryData, decData);
		
	
	myprint("====================== End ===================");

End:
	return ret;
}