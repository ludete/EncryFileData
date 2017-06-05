#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <semaphore.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>


#include "encryDecryFile.h"
#include "include_sub_function.h"
#include "include_EncryDecry.h"
#include "thread_pool.h"

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>


#define ENCRYMAXSIZE  245
#define DECRYMAXSIZE  256
#define LIVETHRM    10

#define _OS_LINUX_ 1




/*create The public Key
*@param : fileName   public Key absolute path
*/
retval_t create_public_key(char *fileName, void *pRsa);



retval_t encryptFile(char *filePath, char *publicKey, char *encFileName, int encryType)
{
	retval_t ret;
    FILE *srcFp = NULL, *encryFp = NULL; 
    char srcContent[ENCRYMAXSIZE];
    int nread = 0, enDataLenth = 0, nwrite = 0;
    char encryptData[DECRYMAXSIZE] = { 0 };
    char cmdBuf[FILENAMELENTH] = { 0 };
    RSA  *pRsa = NULL;


	memset(&ret, 0, sizeof(retval_t));
	if(!filePath || !publicKey)
	{		
		ret.retval = -1;
		sprintf(ret.reason, "Err : filePath : %p, publicPathKey : %p, [%d],[%s]", filePath, publicKey, __LINE__, __FILE__);
		goto End;  
	}

	
	//0. 判断原始文件是否存在
	if(!if_file_exist(filePath))
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : file : %s is not exist [%d],[%s]", filePath, __LINE__, __FILE__); 				
		goto End;	
	}

	//1. open The file
	if((srcFp = fopen(filePath, "rb")) == NULL) 	
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : open The file Error : %s, [%d],[%s]", filePath, __LINE__, __FILE__);
		goto End;  
	}
		
	//2. get The encryName And create The file
	package_encry_file_name(filePath, encFileName);
	if(if_file_exist(encFileName))
	{
		sprintf(cmdBuf, "rm %s", encFileName);
		if((pox_system(cmdBuf)) < 0)
		{
			ret.retval = -1;
			sprintf(ret.reason, "Err : func pox_system() : %s, [%d],[%s]", cmdBuf, __LINE__, __FILE__);
			goto End;  			
		}
	}
	if((encryFp = fopen(encFileName, "ab+")) == NULL)	
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : open The file Error : %s, [%d],[%s]", encFileName, __LINE__, __FILE__);
		goto End;  
	}


	//3. choose The type for encryFile
	if(encryType == 0)
	{
		ret = get_public_key((void **)&pRsa, publicKey);
		if(ret.retval < 0)
		{		
	        goto End;
		}
	}
	else if(encryType == 1)
	{	
	    get_cert_pubKey((void **)&pRsa, publicKey);
		if(ret.retval < 0)
		{		
	        goto End;
		}
	}
	else
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : No find The encryType : %d, [%d],[%s]", encryType,  __LINE__, __FILE__);		
		goto End;
	}

	//4. encrypt Data from file; once 245 BYTE
	while(!(feof(srcFp)))
	{		
		if((nread = fread(srcContent, 1, ENCRYMAXSIZE, srcFp)) < 0)				
		{
			ret.retval = -1;
			sprintf(ret.reason, "Err : read File : %s, [%d],[%s]", filePath, __LINE__, __FILE__); 	
			goto End;
		}
		if((enDataLenth = encry_data(srcContent, nread, encryptData, pRsa)) < 0)	
		{
			ret.retval = -1;
			sprintf(ret.reason, "Err : encry Data [%d],[%s]",  __LINE__, __FILE__); 	
			goto End;
		}
		if((nwrite = fwrite(encryptData, 1, enDataLenth, encryFp)) < 0) 
		{
			ret.retval = -1;
			sprintf(ret.reason, "Err : write File : %s, [%d],[%s]", encFileName,__LINE__, __FILE__); 	
			goto End;
		}
		memset(srcContent, 0, ENCRYMAXSIZE);
		memset(encryptData, 0, DECRYMAXSIZE);  
	}

	
End:
	if(srcFp)				fclose(srcFp);
	if(encryFp) 			fclose(encryFp);
	if(pRsa)				RSA_free(pRsa); 

	return ret;
}






//解密文件
retval_t decryptFile(char *filePath, char *privatePathKey, char *decFileName)
{
    retval_t ret;
    FILE *srcFp = NULL, *decryFp = NULL;
    char srcContent[DECRYMAXSIZE];
    int nread = 0, deDataLenth = 0, nwrite = 0;
    char decryptData[ENCRYMAXSIZE] = { 0 };
    char cmdBuf[FILENAMELENTH] = { 0 };
    RSA  *pRsa = NULL;

	memset(&ret, 0, sizeof(retval_t));
    if(!filePath || !privatePathKey)
    {
       	ret.retval = -1;
		sprintf(ret.reason, "Err : elemet is NULL : %s ,%s, [%d],[%s]", filePath , privatePathKey ,__LINE__, __FILE__); 	
		goto End;  
    }
	
	//0. 判断原始文件是否存在
	if(!if_file_exist(filePath))
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : file : %s is not exist [%d],[%s]", filePath, __LINE__, __FILE__); 				
		goto End;	
	}

    //1. open The file
    if((srcFp = fopen(filePath, "rb")) == NULL)	
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : open File : %s, [%d],[%s]", filePath,__LINE__, __FILE__);	
		goto End; 
	}

    //2. package The decryFileName
    package_decry_file_name(filePath, decFileName);

    //3. create The decrypt File
    if(if_file_exist(decFileName))
    {
        sprintf(cmdBuf, "rm %s", decFileName);
        if((pox_system(cmdBuf)) < 0)
        {
        	ret.retval = -1;
			sprintf(ret.reason, "Err : func pox_system() : %s, [%d],[%s]", cmdBuf, __LINE__, __FILE__);	
			goto End; 
        }
    }
    if((decryFp = fopen(decFileName, "ab+")) == NULL)		assert(0);

    //4. get The private Key News
    if(get_privateKey_new((void **)&pRsa, privatePathKey) < 0)
    {
    	ret.retval = -1;
		sprintf(ret.reason, "Err : func get_privateKey_new() : %s, [%d],[%s]", privatePathKey, __LINE__, __FILE__);	
		goto End;     
    }

    //5. encrypt Data from file; once 245 BYTE
    while(!(feof(srcFp)))
    {
        if((nread = fread(srcContent, 1, sizeof(srcContent) , srcFp)) < 0)
		{
			ret.retval = -1;
			sprintf(ret.reason, "Err : func fread() : %s, [%d],[%s]", filePath, __LINE__, __FILE__); 
			goto End;
		}
        if(nread == 0)			break;
        if((deDataLenth = decry_data(srcContent, DECRYMAXSIZE, decryptData, pRsa)) < 0)	
		{
			ret.retval = -1;
			sprintf(ret.reason, "Err : func decry_data()  [%d],[%s]", __LINE__, __FILE__); 
			goto End;
		}
        if((nwrite = fwrite(decryptData, 1, deDataLenth, decryFp)) < 0)	
		{
			ret.retval = -1;
			sprintf(ret.reason, "Err : func fwrite() : %s, [%d],[%s]", decFileName,__LINE__, __FILE__); 
			goto End;
		}
        memset(srcContent, 0,  DECRYMAXSIZE);   
        memset(decryptData, 0, ENCRYMAXSIZE);  
    }

End:
    if(srcFp)				fclose(srcFp);
    if(decryFp)				fclose(decryFp);
    if(pRsa)				RSA_free(pRsa);

    return ret;	
}

retval_t mix_RSA_AES_encryFile(char *file, char *passWdSrc, char *publicPathKey, char *encryName, int encryType)
{
	retval_t ret ;
	AES_KEY aes_key;				
	char cmdBuf[FILENAMELENTH] = { 0 };
	FILE *srcFp = NULL, *decryFp = NULL;
	char srcData[AES_BLOCK_SIZE] = { 0 }, outData[AES_BLOCK_SIZE] = { 0 };
	int nread = 0, passLen = 0;
	char passwd[33] = { 0 };
	RSA *pRsa = NULL;
	char enData_RSA[DECRYMAXSIZE] = { 0 };

	memset(&ret, 0, sizeof(retval_t));
	

	if(!file || !passWdSrc || !publicPathKey || !encryName)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : file : %p, passwd : %p, publicPathKey : %p, encryName : %p, [%d],[%s]", 
			file, passWdSrc, publicPathKey, encryName, __LINE__, __FILE__); 
		goto End;
	}
	
	//0. 判断原始文件是否存在
	if(!if_file_exist(file))
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : file : %s is not exist [%d],[%s]", file, __LINE__, __FILE__); 				
		goto End;	
	}
	
	//1. 进行用户秘钥的配置(输入最大为32字节), 16, 24, 32字节
	passLen = strlen(passWdSrc);	
	if(passLen == 16 || passLen == 24 || passLen == 32)
	{
		myprint("passwd OK");		
	}
	else if(passLen < 16)
	{
		strcpy(passwd, passWdSrc);
		while(passLen < 16)
		{
			passwd[passLen++] = 49;
		}		
	}
	else if(passLen < 24)
	{
		strcpy(passwd, passWdSrc);
		while(passLen < 24)
		{
			passwd[passLen++] = 49;
		}
	}
	else if(passLen < 32)
	{
		strcpy(passwd, passWdSrc);
		while(passLen < 32)
		{
			passwd[passLen++] = 49;
		}
	}
	else
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : The passwd Lenth is too large %d > MAXSize 32, [%d],[%s]", 
				passLen, __LINE__, __FILE__); 
		goto End;	
	}

			
	//2. get The cert news And encry password data in use RSA style
	if(encryType == 0)
	{
		ret = get_public_key((void **)&pRsa, publicPathKey);
		if(ret.retval < 0)
		{		
	        goto End;
		}
	}
	else if(encryType == 1)
	{	
	    get_cert_pubKey((void **)&pRsa, publicPathKey);
		if(ret.retval < 0)
		{		
	        goto End;
		}
	}
	else
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : No find The encryType : %d, [%d],[%s]", encryType, __LINE__, __FILE__); 				
		goto End;				
	}
	if((encry_data(passwd, passLen, enData_RSA, pRsa)) < 0)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func encry_data() [%d],[%s]", __LINE__, __FILE__); 				
		goto End;	
	}

	//3.package The encryFileName And open The file
	package_AES_RSA_encry_file_name(file, encryName);
	if(if_file_exist(encryName))
	{
		sprintf(cmdBuf, "rm %s", encryName);
		if((pox_system(cmdBuf)) < 0)
		{
			ret.retval = -1;
			sprintf(ret.reason, "Err : func pox_system() : %s [%d],[%s]", cmdBuf, __LINE__, __FILE__); 				
			goto End;		
		}
	}
	if((srcFp = fopen(file, "rb")) == NULL)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func fopen() : %s [%d],[%s]", file, __LINE__, __FILE__); 				
		goto End;	
	}
	if((decryFp = fopen(encryName, "wb")) == NULL)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func fopen() : %s [%d],[%s]", encryName, __LINE__, __FILE__); 				
		goto End;
	}


	//4.write RSA encry data to encryFile
	if((fwrite(enData_RSA, 1, sizeof(enData_RSA), decryFp)) < 0)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func fwrite() : %s [%d],[%s]", encryName, __LINE__, __FILE__); 				
		goto End;		
	}

	//5.设置OpenSSL格式的秘钥
	if(AES_set_encrypt_key((const unsigned char*)passwd, passLen * 8, &aes_key) < 0)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func AES_set_encrypt_key(), [%d],[%s]", __LINE__, __FILE__); 				
		goto End;	
	}


	//6.encry file Data 	   
	while(!feof(srcFp))
	{	
		if((nread = fread(srcData, 1, AES_BLOCK_SIZE, srcFp)) < 0)
		{
			ret.retval = -1;
			sprintf(ret.reason, "Err : func fread(), fileName : %s, [%d],[%s]", file, __LINE__, __FILE__); 				
			goto End;					
		}
		
		AES_encrypt((unsigned char*)srcData, (unsigned char*)outData, &aes_key);
		
		if((fwrite(outData, 1, nread, decryFp)) < 0)
		{
			ret.retval = -1;
			sprintf(ret.reason, "Err : func fwrite(), fileName : %s, [%d],[%s]", encryName, __LINE__, __FILE__); 				
			goto End;
		}
		memset(outData, 0,AES_BLOCK_SIZE );
		memset(srcData, 0,AES_BLOCK_SIZE );
	}

	AES_encrypt((unsigned char*)"\r\n", (unsigned char*)outData, &aes_key);
	if((fwrite(outData, 1, 2, decryFp)) < 0)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func fwrite(), fileName : %s, [%d],[%s]", encryName, __LINE__, __FILE__); 				
		goto End;
	}

End:
	
	if(decryFp) 		fclose(decryFp);
	if(srcFp)			fclose(srcFp);
	if(pRsa)			RSA_free(pRsa);

	return ret;
}

retval_t mix_RSA_AES_decryFile(char *file, char *privatePathKey, char *decryName)
{
	retval_t ret;
	AES_KEY aes_key;				//OpenSSL格式的秘钥
	char cmdBuf[FILENAMELENTH] = { 0 };
	FILE *srcFp = NULL, *decryFp = NULL;
	char srcData[AES_BLOCK_SIZE] = { 0 }, outData[AES_BLOCK_SIZE] = { 0 };
	int nread = 0, passLen = 0;
	char passwd[33] = { 0 };
	char encryPassData[256] = { 0 };
	RSA  *pRsa = NULL;

	memset(&ret, 0, sizeof(retval_t));
	
	if(!file || !privatePathKey || !decryName)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : file : %p, privatePathKey : %p, decryFile : %p, [%d],[%s]", 
			file, privatePathKey, decryName, __LINE__, __FILE__); 				
		goto End;
	}
	
	//1. 判断原始文件是否存在
	if(!if_file_exist(file))
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : file : %s is not exist [%d],[%s]", file, __LINE__, __FILE__); 				
		goto End;	
	}

	//2. 生成解密文件名,并判该文件是否存在, 存在则删除
	package_AES_RSA_decry_file_name(file, decryName);
	if(if_file_exist(decryName))
	{
		sprintf(cmdBuf, "rm %s", decryName);
		if((pox_system(cmdBuf)) < 0)
		{
			ret.retval = -1;
			sprintf(ret.reason, "Err : func pox_system() : %s [%d],[%s]", cmdBuf, __LINE__, __FILE__); 				
			goto End;
		}
	}

	//3.打开文件
	if((srcFp = fopen(file, "rb")) == NULL)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func fopen() : %s [%d],[%s]", file, __LINE__, __FILE__); 				
		goto End;
	}
	if((decryFp = fopen(decryName, "wb")) == NULL)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func fopen() : %s [%d],[%s]", decryName, __LINE__, __FILE__); 				
		goto End;
	}

	//4.获取私钥信息
	if((get_privateKey_new((void **)&pRsa, privatePathKey)) < 0)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func get_privateKey_new() [%d],[%s]", __LINE__, __FILE__); 				
		goto End;
	}

	//5.read encry password from src File,  注意: 非对称加密, 加密的密文长度为256(固定)
	if((fread(encryPassData, 1, 256, srcFp)) != 256)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func fread() : %s, [%d],[%s]", file, __LINE__, __FILE__); 				
		goto End;
	}
	if((passLen = decry_data(encryPassData, 256, passwd, pRsa)) < 0)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func decry_data() [%d],[%s]", __LINE__, __FILE__); 				
		goto End;
	}

	
	//6. set The Symmetric encryption key
	if(AES_set_decrypt_key((const unsigned char*)passwd, passLen * 8, &aes_key) < 0)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func AES_set_decrypt_key() [%d],[%s]", __LINE__, __FILE__); 				
		goto End;
	}

	int srcLenth = get_file_size(file);
	int nReadLenth = srcLenth - 256 - 2;
	int nWriteLenth = 0;
	printf("fileName : %s, fileLenth : %d, nReadLenth : %d, [%d],[%s]", 
			file, srcLenth, nReadLenth, __LINE__, __FILE__);
	
	
	//7.encry file Data 	   
	while(!feof(srcFp))
	{
		if((nread = fread(srcData, 1, AES_BLOCK_SIZE, srcFp)) < 0)
		{
			ret.retval = -1;
			sprintf(ret.reason, "Err : func fread() : %s, [%d],[%s]", file, __LINE__, __FILE__); 				
			goto End;
		}
		AES_decrypt((unsigned char*)srcData, (unsigned char*)outData, &aes_key);
		nWriteLenth += nread;
		if(nReadLenth < nWriteLenth)
		{
			nread = nread - (nWriteLenth - nReadLenth);
			if((fwrite(outData, 1, nread, decryFp)) < 0)
			{
				ret.retval = -1;
				sprintf(ret.reason, "Err : func fwrite() : %s, [%d],[%s]", decryName, __LINE__, __FILE__); 				
				goto End;
			}
			break;
		}
		else if(nReadLenth == nWriteLenth) 
		{
			if((fwrite(outData, 1, nread, decryFp)) < 0)
			{
				ret.retval = -1;
				sprintf(ret.reason, "Err : func fwrite() : %s, [%d],[%s]", decryName, __LINE__, __FILE__); 				
				goto End;
			}
		}	
		else
		{
			if((fwrite(outData, 1, nread, decryFp)) < 0)
			{
				ret.retval = -1;
				sprintf(ret.reason, "Err : func fwrite() : %s, [%d],[%s]", decryName, __LINE__, __FILE__);				
				goto End;
			}
		}
		memset(outData, 0,AES_BLOCK_SIZE );
		memset(srcData, 0,AES_BLOCK_SIZE );
	}

End:
	if(decryFp)			fclose(decryFp);
	if(srcFp)			fclose(srcFp);
	if(pRsa)			RSA_free(pRsa);

	return ret;
}

void testWriteRSA2PEM()
{
    //生成密钥对
    RSA *r = RSA_new();
    int bits = 2048;
    BIGNUM *e = BN_new();
    BN_set_word(e, 65537);
    RSA_generate_key_ex(r, bits, e, NULL);
    
    RSA_print_fp(stdout, r, 0);
    
    BIO *out;
    out = BIO_new_file("./opriv.pem","w");
    //这里生成的私钥没有加密，可选加密
    int ret = PEM_write_bio_RSAPrivateKey(out, r, NULL, NULL, 0, NULL, NULL);
    printf("writepri:%d\n",ret);
    BIO_flush(out);
    BIO_free(out);
    
    out = BIO_new_file("./opub.pem","w");
    ret = PEM_write_bio_RSAPublicKey(out, r);
    printf("writepub:%d\n",ret);
    BIO_flush(out);
    BIO_free(out);
    
    BN_free(e);
    RSA_free(r);

}




retval_t create_private_public_key(char *publicKey, char *privateKey)
{
	retval_t ret;
	RSA *pRsa = NULL;;
    int bits = 2048;					//秘钥长度(bit)
    BIGNUM *bn_new = NULL;
	BIO *out = NULL;

	memset(&ret, 0, sizeof(retval_t));

	//1. create The key news
	if((pRsa = RSA_new()) == NULL)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func RSA_new() [%d],[%s]", __LINE__, __FILE__); 				
		goto End;
	}

	//2. new what; I don`t Konw too; 
	if((bn_new = BN_new()) == NULL)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func BN_new() [%d],[%s]", __LINE__, __FILE__);				
		goto End;
	}

	//3.set The element flag
    BN_set_word(bn_new, 65537);
	RSA_generate_key_ex(pRsa, bits, bn_new, NULL);

	//4.create The file for private Key
	if((out = BIO_new_file(privateKey, "wb")) == NULL)
  	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : create privateKey : %s [%d],[%s]", privateKey, __LINE__, __FILE__);				
		goto End;
	}

	//5.这里生成的私钥没有加密，可选加密
    if((PEM_write_bio_RSAPrivateKey(out, pRsa, NULL, NULL, 0, NULL, NULL)) != 1)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : write privateKey : %s, [%d],[%s]", privateKey ,__LINE__, __FILE__);				
		goto End;
	}
	BIO_flush(out);


	//6.生成私钥
	ret = create_public_key(publicKey, (void*)pRsa);
	
End:	
	if(out) 		BIO_free(out);
	if(bn_new)		BN_free(bn_new);
	if(pRsa)		RSA_free(pRsa);
		
	return ret;
}


retval_t create_public_key(char *publicKey, void *pRsaSrc)
{
	retval_t ret;
	BIO *out = NULL;
	RSA *pRsa = (RSA *)pRsaSrc;
	
	memset(&ret, 0, sizeof(retval_t));
	//1.create The file for public Key
	if((out = BIO_new_file(publicKey, "wb")) == NULL)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : create publicKey : %s [%d],[%s]", publicKey, __LINE__, __FILE__);				
		goto End;

	}

	//2. write News for public key
	if((PEM_write_bio_RSAPublicKey(out, pRsa)) != 1)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : write publicKey : %s, [%d],[%s]", publicKey, __LINE__, __FILE__);				
		goto End;
	}
	BIO_flush(out);

End:	
	if(out) 		BIO_free(out);
	
	return ret;
}


