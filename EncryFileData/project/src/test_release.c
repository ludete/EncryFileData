#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "encryDecryFile.h"


//#define PRIVATEKEY 	"/home/yyx/MyEncryProject/EncryFileData/hostClientCert/client-key.pem"
//#define PUBLICKEY 	"/home/yyx/MyEncryProject/EncryFileData/hostClientCert/client-cert.pem"
#define PRIVATEKEY 	"/home/yyx/MyEncryProject/EncryFileData/clientCert/client-key.pem"
#define PUBLICKEY 	"/home/yyx/MyEncryProject/EncryFileData/clientCert/client-cert.pem"


void test_encryFile_RSA()
{
	char *file = "C_16_01_04_10_16_10_030_B_L.jpg";
	char encryName[1024] = { 0 };
	retval_t ret;
	
	ret = encryptFile(file, PUBLICKEY, encryName, 1 );
	printf("ret : %d, reason : %s, encryName : %s, [%d],[%s]\n",
			ret.retval, ret.reason, encryName, __LINE__, __FILE__);
	
}

void test_decryFile_RSA()
{
	char *file = "C_16_01_04_10_16_10_030_B_L_ENCRYPT.jpg";
	char decryName[1024] = { 0 };
	retval_t ret;

	ret = decryptFile(file, PRIVATEKEY, decryName);
	printf("ret : %d, reason : %s, decryName : %s, [%d],[%s]\n",
			ret.retval, ret.reason, decryName, __LINE__, __FILE__);

}

void test_encryFile_RSA_AES()
{
	char *file = "C_16_01_04_10_16_10_030_B_L.jpg";
	char encryName[1024] = { 0 };
	char *passwd = "1545adw8751";
	retval_t ret;
	
	ret = mix_RSA_AES_encryFile(file, passwd, PUBLICKEY, encryName, 1 );
	printf("ret : %d, reason : %s, encryName : %s, [%d],[%s]\n", 
			ret.retval, ret.reason, encryName, __LINE__, __FILE__);

}


void test_decryFile_RSA_AES()
{
	char *file = "C_16_01_04_10_16_10_030_B_L_ENCRYPT_RSA_AES.jpg";
	char decryName[1024] = { 0 };
	retval_t ret;
	ret = mix_RSA_AES_decryFile(file, PRIVATEKEY, decryName);
	printf("ret : %d, reason : %s, decryName : %s, [%d],[%s]\n",
				ret.retval, ret.reason, decryName, __LINE__, __FILE__);

}


int main()
{
	//test_encryFile_RSA();
	//test_decryFile_RSA();
	test_encryFile_RSA_AES();
	test_decryFile_RSA_AES();

	return 0;
}


