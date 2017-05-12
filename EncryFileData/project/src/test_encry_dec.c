#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<assert.h>

#include <unistd.h>
#include "encryptData.h"
#include "include_sub_function.h"

//#define PRIVATEKEY 	"/home/yyx/MyEncryProject/EncryFileData/hostClientCert/client-key.pem"
//#define PUBLICKEY 	"/home/yyx/MyEncryProject/EncryFileData/hostClientCert/client-cert.pem"
#define PRIVATEKEY 	"/home/yyx/MyEncryProject/EncryFileData/clientCert/client-key.pem"
#define PUBLICKEY 	"/home/yyx/MyEncryProject/EncryFileData/clientCert/client-cert.pem"



void test_content()
{
	int decryptDataLenth = 0;
	char *str = "hello world";
	char *encryData = NULL;
	char *decData = NULL;
	int  enDataLenth = 0;
	char *buf = NULL;
	
	buf = malloc(10 + 1);
	memset(buf, 49, 10);
	buf[10] = '\0';
	
	printf("=========== 1 =============\n");
	if((encryData = my_encrypt_publicCert(buf, strlen(buf), &enDataLenth, PUBLICKEY)) == NULL)
	{
		
		myprint("Err : func my_encrypt(),  srcDataLenth : %d",strlen(buf));				 
		goto End;
	}
	printf("=========== 2 enDataLenth : %d =============\n", enDataLenth);
	if((decData = my_decrypt(encryData, enDataLenth, &decryptDataLenth, PRIVATEKEY)) == NULL)
	{
	
		myprint("Err : func my_encrypt()");
		goto End;
	}
	
	if(strcmp(buf, decData) == 0)		myprint("OK, SrcData : %s, encrypt : %s And decrypt : %s,  decryptDataLenth : %d ,success", str, encryData, decData, decryptDataLenth );
	else								myprint("Err, SrcData : %s, encrypt : %s And decrypt : %s fail", str, encryData, decData);
		
	
	myprint("====================== End ===================");
	
End:
	
	return;
}


void test_encryptFile()
{
	int ret = 0;
	if((ret = encryptFileData("C_16_01_04_10_16_10_030_B_L.jpg", PUBLICKEY)) < 0)		assert(0);
//	if((ret = encryptFileData("/home/yyx/MyEncryProject/EncryFileData/project/C_16_01_04_10_16_10_030_B_L.jpg", PUBLICKEY)) < 0)		assert(0);	
}

void test_decryptFile()
{
	int ret = 0;
//	if((ret = decryptFileData("/home/yyx/MyEncryProject/EncryFileData/project/C_16_01_04_10_16_10_030_B_L_ENCRYPT.jpg", PRIVATEKEY)) < 0)		assert(0);
	if((ret = decryptFileData("C_16_01_04_10_16_10_030_B_L_ENCRYPT.jpg", PRIVATEKEY)) < 0)		assert(0);
}

void test_multiDecryFile()
{
	threadpool_t *pool = NULL;
	
	pool = init_thread_pool();
	if((multiDecryFile("C_16_01_04_10_16_10_030_B_L_ENCRYPT.jpg", PRIVATEKEY, pool)) < 0)			assert(0); 

		sleep(20);
	destroy(pool);

}


int main()
{
	int ret = 0;

	test_encryptFile();
//	test_decryptFile();
	test_multiDecryFile();
	//test_content();	
	
	return ret;
}
