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
#include "thread_pool.h"

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define ENCRYFLAG  "_ENCRYPT"
#define DECRYFLAG  "_DECRYPT"
#define MUTILENCYR "_ENCRYPT_RSA_AES"
#define MUTILDECYR "_DECRYPT_RSA_AES"
#define ENCRYMAXSIZE  245
#define DECRYMAXSIZE  256
#define LIVETHRM    10

#define _OS_LINUX_ 1

int encry_data(char *str, int lenth, char *enData, RSA *pRsa);

int decry_data(char *str, int lenth, char *deData, RSA *pRsa);

void package_encry_file_name(char *filePath, char *encFileName);

void package_decry_file_name(char *filePath, char *decFileName);

void package_AES_RSA_encry_file_name(char *filePath, char *encFileName);

void package_AES_RSA_decry_file_name(char *filePath, char *decFileName);


/*获取证书文件信息
*@param : pRsa : 公钥信息
*@param : publicPathKey : 证书文件路径
*/
retval_t get_cert_pubKey(RSA  **pRsa, char *publicPathKey);

/*获取公钥信息
*@param : pRsa : 公钥信息
*@param : publicKey : 公钥文件路径
*/
retval_t get_public_key(RSA **pRsa, char *publicKey);

int get_privateKey_new(RSA  **pRsa, char *privatePathKey);


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
		ret = get_public_key(&pRsa, publicKey);
		if(ret.retval < 0)
		{		
	        goto End;
		}
	}
	else if(encryType == 1)
	{	
	    get_cert_pubKey(&pRsa, publicKey);
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
    if(get_privateKey_new(&pRsa, privatePathKey) < 0)
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
		ret = get_public_key(&pRsa, publicPathKey);
		if(ret.retval < 0)
		{		
	        goto End;
		}
	}
	else if(encryType == 1)
	{	
	    get_cert_pubKey(&pRsa, publicPathKey);
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
	if((get_privateKey_new(&pRsa, privatePathKey)) < 0)
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
		if((fwrite(outData, 1, nread, decryFp)) < 0)
		{
			ret.retval = -1;
			sprintf(ret.reason, "Err : func fwrite() : %s, [%d],[%s]", decryName, __LINE__, __FILE__); 				
			goto End;
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


int encry_data(char *str, int lenth, char *enData, RSA *pRsa)
{
    int ret = 0;
    if(!str || lenth < 0 || !enData || !pRsa)
    {
        myprint("Err : str : %p, lenth : %d, enData : %p, pRsa : %p ", str, lenth, enData, pRsa);       
        ret = -1;
        goto End;  
    }

    //1. public Key encrypt Data
    if((ret = RSA_public_encrypt(lenth, (unsigned char *)str, (unsigned char *)enData, pRsa, RSA_PKCS1_PADDING)) < 0)
    {
        myprint("Err : func RSA_public_encrypt()");	
        goto End;        
    } 

End:
    return ret;
}

void package_encry_file_name(char *filePath, char *encFileName)
{
    char *tmp = NULL;
    char suffix[20] = { 0 };
    char path[FILENAMELENTH] = { 0 };
    char name[FILENAMELENTH] = { 0 };

    //2. get The SrcFile suffix
    if((tmp = strrchr(filePath, '.')))			
    {
        memcpy(suffix, tmp, strlen(tmp));
    }

    //3. get The path 
#ifdef _OS_WIN_
    if((tmp = strrchr(filePath, '\\')))		
    {
        memcpy(path, filePath, MY_MIN(FILENAMELENTH, strlen(filePath) - strlen(tmp)));
        strcat(path, "\\");
    }
#endif

#ifdef	_OS_LINUX_
    if((tmp = strrchr(filePath, '/')))		
    {
        memcpy(path, filePath, MY_MIN(FILENAMELENTH, strlen(filePath) - strlen(tmp)));
        strcat(path, "/");
    }
#endif

    //4. get The FILE name 
    if(tmp == NULL)
    {
        memcpy(name, filePath, MY_MIN(FILENAMELENTH, strlen(filePath) - strlen(suffix)));
    }
    else
    {
        memcpy(name, tmp + 1, MY_MIN(FILENAMELENTH, strlen(tmp) - strlen(suffix) - 1));
    }

    //5. package The decryFileName
#ifdef  _OS_WIN_
    sprintf(encFileName, "%s%s%s%s", path, name, ENCRYFLAG, suffix);
#endif
#ifdef  _OS_LINUX_
    sprintf(encFileName, "%s%s%s%s", path, name, ENCRYFLAG, suffix);
#endif

}


//组装 解密文件名
void package_decry_file_name(char *filePath, char *decFileName)
{
    char *tmp = NULL;
    char suffix[20] = { 0 };
    char path[FILENAMELENTH] = { 0 };
    char name[FILENAMELENTH] = { 0 };
    char tmpname[FILENAMELENTH] = { 0 };

	myprint("filePath : %s", filePath);

    //2. get The SrcFile suffix
    if((tmp = strrchr(filePath, '.')))			
    {
        memcpy(suffix, tmp, strlen(tmp));
    }

    //3. get The path 
#ifdef _OS_WIN_
    if((tmp = strrchr(filePath, '\\')))		
    {
        memcpy(path, filePath, MY_MIN(516, strlen(filePath) - strlen(tmp)));
        strcat(path, "\\");
    }
#endif

#ifdef  _OS_LINUX_

    if((tmp = strrchr(filePath, '/')))		
    {
        memcpy(path, filePath, MY_MIN(516, strlen(filePath) - strlen(tmp)));
        strcat(path, "/");
    }
#endif

    //4. get The FILE name 
    if(tmp == NULL)
    {
        memcpy(tmpname, filePath, MY_MIN(258, strlen(filePath) - strlen(suffix)));
    }
    else
    {
        memcpy(tmpname, tmp, MY_MIN(258, strlen(tmp) - strlen(suffix)));
    }

    if((tmp = memstr(tmpname, strlen(tmpname), ENCRYFLAG)))
    {
        memcpy(name, tmpname, strlen(tmpname) - strlen(tmp));
    }
    else
    {
        myprint("No find encrypt File, The name : %s", tmpname);
        return;
    }

    //5. package The decryFileName
#ifdef	_OS_WIN_
    sprintf(decFileName, "%s%s%s%s", path, name, DECRYFLAG, suffix);
#endif
#ifdef	_OS_LINUX_
    sprintf(decFileName, "%s%s%s%s", path, name, DECRYFLAG, suffix);
#endif


}



void package_AES_RSA_encry_file_name(char *filePath, char *encFileName)
{
    char *tmp = NULL;
    char suffix[20] = { 0 };
    char path[FILENAMELENTH] = { 0 };
    char name[FILENAMELENTH] = { 0 };

    //2. get The SrcFile suffix
    if((tmp = strrchr(filePath, '.')))			
    {
        memcpy(suffix, tmp, strlen(tmp));
    }

    //3. get The path 
#ifdef _OS_WIN_
    if((tmp = strrchr(filePath, '\\')))		
    {
        memcpy(path, filePath, MY_MIN(FILENAMELENTH, strlen(filePath) - strlen(tmp)));
        strcat(path, "\\");
    }
#endif

#ifdef	_OS_LINUX_
    if((tmp = strrchr(filePath, '/')))		
    {
        memcpy(path, filePath, MY_MIN(FILENAMELENTH, strlen(filePath) - strlen(tmp)));
        strcat(path, "/");
    }
#endif

    //4. get The FILE name 
    if(tmp == NULL)
    {
        memcpy(name, filePath, MY_MIN(FILENAMELENTH, strlen(filePath) - strlen(suffix)));
    }
    else
    {
        memcpy(name, tmp + 1, MY_MIN(FILENAMELENTH, strlen(tmp) - strlen(suffix) - 1));
    }

    //5. package The decryFileName
#ifdef  _OS_WIN_
    sprintf(encFileName, "%s%s%s%s", path, name, MUTILENCYR, suffix);
#endif
#ifdef  _OS_LINUX_
    sprintf(encFileName, "%s%s%s%s", path, name, MUTILENCYR, suffix);
#endif


}


//组装 解密文件名
void package_AES_RSA_decry_file_name(char *filePath, char *decFileName)
{
    char *tmp = NULL;
    char suffix[20] = { 0 };
    char path[FILENAMELENTH] = { 0 };
    char name[FILENAMELENTH] = { 0 };
    char tmpname[FILENAMELENTH] = { 0 };

    //2. get The SrcFile suffix
    if((tmp = strrchr(filePath, '.')))			
    {
        memcpy(suffix, tmp, strlen(tmp));
    }

    //3. get The path 
#ifdef _OS_WIN_
    if((tmp = strrchr(filePath, '\\')))		
    {
        memcpy(path, filePath, MY_MIN(FILENAMELENTH, strlen(filePath) - strlen(tmp)));
        strcat(path, "\\");
    }
#endif

#ifdef  _OS_LINUX_

    if((tmp = strrchr(filePath, '/')))		
    {
        memcpy(path, filePath, MY_MIN(FILENAMELENTH, strlen(filePath) - strlen(tmp)));
        strcat(path, "/");
    }
#endif

    //4. get The FILE name 
    if(tmp == NULL)
    {
        memcpy(tmpname, filePath, MY_MIN(FILENAMELENTH, strlen(filePath) - strlen(suffix)));
    }
    else
    {
        memcpy(tmpname, tmp, MY_MIN(FILENAMELENTH, strlen(tmp) - strlen(suffix)));
    }

    if((tmp = memstr(tmpname, strlen(tmpname), MUTILENCYR)))
    {
        memcpy(name, tmpname, strlen(tmpname) - strlen(tmp));
    }
    else
    {
        myprint("No find encrypt File, The name : %s", tmpname);
        return;
    }

    //5. package The decryFileName
#ifdef	_OS_WIN_
    sprintf(decFileName, "%s%s%s%s", path, name, MUTILDECYR, suffix);
#endif
#ifdef	_OS_LINUX_
    sprintf(decFileName, "%s%s%s%s", path, name, MUTILDECYR, suffix);
#endif


}

int decry_data(char *str, int lenth, char *deData, RSA *pRsa)
{
    int ret = 0;

    if(!str || lenth < 0 || !deData || !pRsa)
    {
        myprint("Err : str : %p, lenth : %d, deData : %p, pRsa : %p ", str, lenth, deData, pRsa);       
        ret = -1;
        goto End;  
    }

    //1. private Key decrypt Data
    if((ret = RSA_private_decrypt(lenth, (unsigned char *)str, (unsigned char *)deData, pRsa, RSA_PKCS1_PADDING)) < 0)
    {
        myprint("Err : func RSA_private_decrypt()");
        ERR_print_errors_fp(stdout);  
        goto End;		 
    } 

End:

    return ret;
}


//get the certficate news 
retval_t get_cert_pubKey(RSA  **pRsa, char *publicPathKey)
{
    retval_t ret;
    RSA  *tmpRsa = NULL;
    BIO  *tmpBio = NULL; 
    X509 *tmpX509 = NULL;      
    EVP_PKEY *tmpEvpKey = NULL;  
  
	memset(&ret, 0, sizeof(retval_t));
    //1.get The public Key from cert
    if((tmpBio = BIO_new_file(publicPathKey, "rb" )) == NULL)
	{		
		ret.retval = -1;
		sprintf(ret.reason, "Err : func BIO_new_file() [%d],[%s]", __LINE__, __FILE__);
		goto End;  		
	}
    if((tmpX509 = PEM_read_bio_X509(tmpBio, NULL, NULL, NULL)) == NULL)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func PEM_read_bio_X509() [%d],[%s]", __LINE__, __FILE__);
		goto End; 
	}
    if((tmpEvpKey = X509_get_pubkey(tmpX509)) == NULL)						
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func X509_get_pubkey() [%d],[%s]", __LINE__, __FILE__);
		goto End; 
	}
    if((tmpRsa = EVP_PKEY_get1_RSA(tmpEvpKey)) == NULL) 					
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : func EVP_PKEY_get1_RSA() [%d],[%s]", __LINE__, __FILE__);
		goto End; 
	}

    *pRsa = tmpRsa;

End:

    if(tmpEvpKey)					EVP_PKEY_free(tmpEvpKey);   
    if(tmpBio)    					BIO_free(tmpBio); 

    return ret; 
}


retval_t get_public_key(RSA **pRsa, char *publicKey)
{
	retval_t ret;
	FILE *fpKey = NULL;
	
	memset(&ret, 0, sizeof(retval_t));
	if((fpKey = fopen(publicKey, "rb")) == NULL)
	{
		ret.retval = -1;
		sprintf(ret.reason, "Err : open The file Error : %s, [%d],[%s]", publicKey, __LINE__, __FILE__);
		goto End;
	}


	if((*pRsa = PEM_read_RSAPublicKey(fpKey, NULL, NULL, NULL)) == NULL) 
	{		
		ret.retval = -1;
		sprintf(ret.reason, "Err : get The public Key Error : %s, [%d],[%s]", publicKey, __LINE__, __FILE__);
		goto End;
	}

End:
	if(fpKey)		fclose(fpKey);
	
	return ret;
}

//get The private Key News
int get_privateKey_new(RSA  **pRsa, char *privatePathKey)
{
    int ret = 0;
    RSA  *tmpRsa = NULL;
    FILE *tmpKeyFp = NULL;

    if(!pRsa || !privatePathKey)
    {
        myprint("Err : pRsa : %p, privatePathKey : %p", pRsa, privatePathKey); 	  
        ret = -1;
        goto End;  
    }

    //1. open the private Key
    if((tmpKeyFp = fopen(privatePathKey, "r")) == NULL)
    {
        myprint("Err : func fopen() %s", privatePathKey); 
        ret = -1;
        goto End;  
    } 

    //2. get The news from private Key
    if((tmpRsa = PEM_read_RSAPrivateKey(tmpKeyFp, NULL, NULL, NULL)) == NULL)
    {
        myprint("Err : func PEM_read_RSAPrivateKey() ");
        ret = -1;
        ERR_print_errors_fp(stdout);    
        goto End; 
    }
	
    *pRsa = tmpRsa;

End:

    if(tmpKeyFp)			fclose(tmpKeyFp);
	
    return ret;
}

