#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "encryptData.h"
#include "include_sub_function.h"

//#define PRIVATEKEY 	"/home/yyx/MyEncryProject/EncryFileData/hostClientCert/client-key.pem"
//#define PUBLICKEY 	"/home/yyx/MyEncryProject/EncryFileData/hostClientCert/client-cert.pem"
#define PRIVATEKEY 	"/home/yyx/MyEncryProject/EncryFileData/clientCert/client-key.pem"
#define PUBLICKEY 	"/home/yyx/MyEncryProject/EncryFileData/clientCert/client-cert.pem"

typedef struct _retval_{
	int retval;
	char reason[1024];

}retval_t;


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
	//if((ret = encryptFileData("hello.mp4", PUBLICKEY)) < 0)		assert(0);
	//if((ret = encryptFileData("hello.wmv", PUBLICKEY)) < 0)		assert(0);

	


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
	
	pool = init();
	//if((multiDecryFile("C_16_01_04_10_16_10_030_B_L_ENCRYPT.jpg", PRIVATEKEY, pool)) < 0)			assert(0); 
	if((multiDecryFile("hello_ENCRYPT.wmv", PRIVATEKEY, pool)) < 0)			assert(0); 
	//if((multiDecryFile("hello_ENCRYPT.mp4", PRIVATEKEY, pool)) < 0)			assert(0); 
	

	//sleep(12);
	destroy(pool);

}

void test_lockNum()
{
	threadpool_t *pool = NULL;
	pool = init();

	myprint("The Num : %d", test_pthread_mutex_Num());
	destroy(pool);

}

void test_AES_encryfile()
{
	char *file = "C_16_01_04_10_16_10_030_B_L.jpg";
	char *key = "1254544844020202";
	
	if((encry_file_AES(file, key)) < 0)
	{
		myprint("Err : func encry_file_AES()");
	}

}

void test_AES_decryfile()
{
	char *file = "C_16_01_04_10_16_10_030_B_L_ENCRYPT.jpg";
	char *key = "1254544844020202";
	
	if((decry_file_AES(file, key)) < 0)
	{
		myprint("Err : func decry_file_AES()");
	}	

}

void test_AES_RSA_decryfile()
{
	char *file = "C_16_01_04_10_16_10_030_B_L_ENCRYPT_RSA_AES.jpg";
	
	if((mix_RSA_AES_decryFile(file, PRIVATEKEY)) < 0)
	{
		myprint("Err : func decry_file_AES()");
	}	


}

void test_AES_RSA_encryfile()
{
	char *file = "C_16_01_04_10_16_10_030_B_L.jpg";
	char *key = "1254544844020202";
	
	if((mix_RSA_AES_encryFile(file, key, PUBLICKEY)) < 0)
	{
		myprint("Err : func mix_RSA_AES_encryFile()");
	}

}

void test_muldecry_fileFp()
{
	threadpool_t *pool = NULL;
	
	pool = init();
	if((multiDecryFile_inFileFp("C_16_01_04_10_16_10_030_B_L_ENCRYPT.jpg", PRIVATEKEY, pool)) < 0) 		assert(0); 

	destroy(pool);
}



retval_t test_retval()
{
	retval_t retval;
	memset(&retval, 0, sizeof(retval_t));

	retval.retval = -2;
	strcpy(retval.reason, "Err : func test_retval()");
	return retval;
}
	




int main()
{
	int ret = 0;

	//test_encryptFile();
	//test_decryptFile();
	//test_multiDecryFile();
	//test_muldecry_fileFp();

	//test_content();	
	//test_lockNum();
	//test_AES_encryfile();
	//test_AES_decryfile();
	//test_AES_RSA_encryfile();
	//test_AES_RSA_decryfile();
	retval_t retval;
	retval = test_retval();
	myprint("retval : %d, reason : %s", retval.retval, retval.reason);



	return ret;
}
