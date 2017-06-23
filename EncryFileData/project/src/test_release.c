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
	//char *file = "C_16_01_04_10_16_10_030_B_L.jpg";
	char *file = "111.txt";
	char *publicKey = "./opub.pem";
	char encryName[1024] = { 0 };
	retval_t ret;
	
	ret = encryptFile(file, publicKey, encryName, 0 );
	printf("ret : %d, reason : %s, encryName : %s, [%d],[%s]\n",
			ret.retval, ret.reason, encryName, __LINE__, __FILE__);
	
}

void test_decryFile_RSA()
{
	//char *file = "C_16_01_04_10_16_10_030_B_L_ENCRYPT.jpg";
	char *file = "111_ENCRYPT.txt";
	char *privateKey = "./private.pem";
	char decryName[1024] = { 0 };
	retval_t ret;

	ret = decryptFile(file, privateKey, decryName);
	printf("ret : %d, reason : %s, decryName : %s, [%d],[%s]\n",
			ret.retval, ret.reason, decryName, __LINE__, __FILE__);

}

void test_encryFile_RSA_AES()
{
	//char *file = "C_16_01_04_10_16_10_030_B_L.jpg";
	char *file = "111.txt";
	char *publicKey = "./mypublicKey.pem";
	//char *publicKey = PUBLICKEY;
	
	char encryName[1024] = { 0 };
	char *passwd = "1545adw8751";
	retval_t ret;
	
	ret = mix_RSA_AES_encryFile(file, passwd, publicKey, encryName, 0 );
	printf("ret : %d, reason : %s, encryName : %s, [%d],[%s]\n", 
			ret.retval, ret.reason, encryName, __LINE__, __FILE__);

}


void test_decryFile_RSA_AES()
{
	//char *file = "C_16_01_04_10_16_10_030_B_L_ENCRYPT_RSA_AES.jpg";
	char *file = "111_ENCRYPT_RSA_AES.txt";
	char *privateKey = "./myprivateKey.pem";
	//char *privateKey = PRIVATEKEY;
	char decryName[1024] = { 0 };
	retval_t ret;
	ret = mix_RSA_AES_decryFile(file, privateKey, decryName);
	printf("ret : %d, reason : %s, decryName : %s, [%d],[%s]\n",
				ret.retval, ret.reason, decryName, __LINE__, __FILE__);

}

void test_creat_key()
{
	retval_t ret;
	char *publicKey = "mypublicKey.pem";
	char *privateKey = "myprivateKey.pem";
	ret = create_private_public_key(publicKey, privateKey );
	printf("ret : %d, reason : %s [%d],[%s]\n",
					ret.retval, ret.reason, __LINE__, __FILE__);

}

void test_decry_dir()
{
	retval_t	ret;
	char *privateKey = "myprivateKey.pem";
	char *srcFile = "/home/yyx/MyEncryProject/EncryFileData/project/encry/111_AES_RSA_ENCRY.txt";
	char *dstFile = "/home/yyx/MyEncryProject/EncryFileData/project/decry/111_AES_RSA_DECRY.txt";

	ret = decryDirAllFile(srcFile, dstFile, privateKey);
	if(ret.retval < 0)
	{
		printf("Error : %s\n", ret.reason);
		return;
	}
	else
	{
		printf("OK : decry Dir success ...\n" );
		return;
	}
}

void test_encry_dir()
{
	char *srcFile = "/home/yyx/MyEncryProject/EncryFileData/project/111.txt";
	char *encryFile = "/home/yyx/MyEncryProject/EncryFileData/project/encry/111_AES_RSA_ENCRY.txt";
	char *publicKey = "mypublicKey.pem";
	retval_t ret;

	ret = encryDirAllFile(srcFile, encryFile, publicKey, 0);
	if(ret.retval < 0)
	{
		printf("Error : %s", ret.reason);
		return;
	}
	else
	{
		printf("OK : encry Dir success ...\n" );
		return;
	}
	
}
int main()
{
	//test_encryFile_RSA();
	//test_decryFile_RSA();
	test_creat_key();
	//test_encryFile_RSA_AES();
	//test_decryFile_RSA_AES();
	test_encry_dir();
	test_decry_dir();

	return 0;
}


