#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "encryptData.h"

#define ENCRYFLAG  "_ENCRYPT"
#define DECRYFLAG  "_DECRYPT"
//#define _OS_LINUX_ 1


typedef void (*sighandler_t)(int);


//juege The specify File exist 
bool if_file_exist(const char *filePath)
{
	if(filePath == NULL)
		assert(0);
	if(access(filePath, F_OK) == 0)
		return true;

	return false;
}

//自实现 system 系统命令
int pox_system(const char *cmd_line) 
{ 
	int ret = 0; 	
	sighandler_t old_handler; 
	old_handler = signal(SIGCHLD, SIG_DFL); 
	ret = system(cmd_line); 
	signal(SIGCHLD, old_handler); 

	if(ret == 127)
	{
		printf("Err : The cmd is absent, no Find cmd\n");
		ret = -1;
	}
	
	return ret; 
 }

//获取子串在母串中的位置
char* memstr(char* full_data, int full_data_len, char* substr) 
{ 
     if (full_data == NULL || full_data_len <= 0 || substr == NULL) { 
         return NULL; 
     } 
     if (*substr == '\0') { 
         return NULL; 
     } 
     int sublen = strlen(substr); 
     int i; 
     char* cur = full_data; 
     int last_possible = full_data_len - sublen + 1; 
     for (i = 0; i < last_possible; i++) { 
         if (*cur == *substr) { 
             //assert(full_data_len - i >= sublen);  
             if (memcmp(cur, substr, sublen) == 0) { 
                 //found  
                 return cur; 
             } 
        } 
         cur++; 
     }                                                                                                                                                    

     return NULL;
 }


//公钥加密信息
char* my_encrypt_publicKey(char *str, int lenth, char *publicPathKey)
{
	char *pEnData = NULL;
	RSA  *pRsa = NULL;
	FILE *fpKey = NULL;
	int  rsaLen = 0;
	
	if(!str || lenth < 0 || !publicPathKey)
	{
		myprint("Err : str : %p, lenth : %d, publicPathKey : %p", str, lenth, publicPathKey);       
        goto End;  
	}
	
	//1. open the public Key
	if((fpKey = fopen(publicPathKey,"r")) == NULL)
	{
		myprint("Err : func fopen() %s", publicPathKey);       
        goto End;  
    }   
	
	//2. get The news from public Key
	//if((pRsa = PEM_read_RSA_PUBKEY(fpKey, NULL, NULL, NULL)) == NULL)	
	if((pRsa = PEM_read_RSAPublicKey(fpKey, NULL, NULL, NULL)) == NULL)	
	{
		myprint("Err : func PEM_read_RSA_PUBKEY()");      
		ERR_print_errors_fp(stdout); 
        goto End;   
	}
	
	//3. get The Lenth from  public Key News
	rsaLen = RSA_size(pRsa);	
	pEnData = malloc(rsaLen + 1);
	memset(pEnData, 0, rsaLen + 1 );
	
	//4. public Key encrypt Data
	//if((RSA_public_encrypt(rsaLen, (unsigned char *)str, (unsigned char *)pEnData, pRsa, RSA_NO_PADDING)) < 0)
	if((RSA_public_encrypt(lenth, (unsigned char *)str, (unsigned char *)pEnData, pRsa, RSA_PKCS1_PADDING)) < 0)
	{
		myprint("Err : func RSA_public_encrypt()");
		goto End;        
	}
	
	
End:
	
	if(pRsa)  			RSA_free(pRsa);
	if(fpKey)			fclose(fpKey);
	
	return pEnData;
}


//证书加密信息
char* my_encrypt_publicCert(char *str, int lenth, int *enDataLenth, char *publicPathKey)
{
	char *pEnData = NULL;
	RSA  *pRsa = NULL;
	FILE *fpKey = NULL;
	BIO  *b = NULL; 
	X509 *x = NULL;      
    EVP_PKEY *k = NULL;  
    
	if(!str || lenth < 0 || !publicPathKey || !enDataLenth)
	{
		myprint("Err : str : %p, lenth : %d, publicPathKey : %p", str, lenth, publicPathKey);       
        goto End;  
	}
//	printf("=========== 11 =============\n");

	//1.get The public Key from cert
	if((b = BIO_new_file(publicPathKey,"rb")) == NULL)		assert(0);	 
	if((x=PEM_read_bio_X509(b,NULL,NULL,NULL)) == NULL)		assert(0); 
    if((k=X509_get_pubkey(x)) == NULL)						assert(0); 
    if((pRsa=EVP_PKEY_get1_RSA(k)) == NULL)					assert(0);
	
//	 printf("=========== 12 =============\n");
	 
	//2. alloc The encrypData Content
	pEnData = malloc(RSA_size(pRsa) + 1);
	memset(pEnData, 0, RSA_size(pRsa) + 1 );

	// printf("=========== 13  RSA_size(pRsa) : %d =============\n",  RSA_size(pRsa));

	//3. public Key encrypt Data
	if((*enDataLenth = RSA_public_encrypt(lenth, (unsigned char *)str, (unsigned char *)pEnData, pRsa, RSA_PKCS1_PADDING)) < 0)
	{
		myprint("Err : func RSA_public_encrypt()");
		free(pEnData);
		pEnData = NULL;
		goto End;        
	} 
	//printf("=========== 14 =============\n");
	
End:
	
	if(pRsa)  			RSA_free(pRsa);
	if(fpKey)			fclose(fpKey);
	if(k)				EVP_PKEY_free(k);   
    if(b)    			BIO_free(b);  
	
	return pEnData;
}


char* my_decrypt(char *str, int lenth, int *deDataLenth, char *privatePathKey)
{
	char *pDeData = NULL;
	RSA  *pRsa = NULL;
	FILE *fpKey = NULL;
	
	if(!str || lenth < 0 || !privatePathKey)
	{
		myprint("Err : str : %p, lenth : %d, privatePathKey : %p", str, lenth, privatePathKey);       
        goto End;  
	}
	
	//1. open the private Key
	if((fpKey = fopen(privatePathKey,"r")) == NULL)
	{
		myprint("Err : func fopen() %s", privatePathKey);       
        goto End;  
    }   
    
    //2. get The news from private Key
    if((pRsa = PEM_read_RSAPrivateKey(fpKey, NULL, NULL, NULL)) == NULL)
    {
    	myprint("Err : func PEM_read_RSAPrivateKey() ");   
    	ERR_print_errors_fp(stdout);    
        goto End; 
    }
    
    //3. get The Lenth from  private Key News	
	pDeData = malloc(lenth + 1);
	memset(pDeData, 0, lenth + 1 );
    
    //if((RSA_private_decrypt(rsaLen,  (unsigned char *)str,  (unsigned char *)pDeData, pRsa, RSA_NO_PADDING)) < 0)
	if((*deDataLenth = RSA_private_decrypt(lenth, (unsigned char *)str, (unsigned char *)pDeData, pRsa, RSA_PKCS1_PADDING)) < 0)
    {
    	myprint("Err : func RSA_private_decrypt()");
		free(pDeData);
		pDeData = NULL;
		goto End; 
    }
    
End:
	
	if(pRsa)  			RSA_free(pRsa);
	if(fpKey)			fclose(fpKey);
	
	return pDeData;
}



//解密文件
int decryptFileData(char *filePath, char *privatePathKey)
{
	int ret = 0;
	FILE *srcFp = NULL, *decryFp = NULL;
	char *tmp = NULL;
	char decFileName[FILENAMELENTH] = { 0 };
	char srcContent[256];
	int nread = 0, deDataLenth = 0, nwrite = 0;
	char *decryptData = NULL;
	char suffix[15] = { 0 };
	char path[516] = { 0 };
	char name[258] = { 0 }, tmpname[256] = { 0 }, cmdBuf[1024] = { 0 };
	
	if(!filePath || !privatePathKey)
	{
		myprint("Err : filePath : %p", filePath); 	  
		goto End;  
	}
	
	//1. open The file
	if((srcFp = fopen(filePath, "rb")) == NULL)		assert(0);
	
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
		ret = -1;
		goto End;
	}

	//5. package The decryFileName
	#ifdef  _OS_WIN_
	sprintf(decFileName, "%s%s%s%s", path, name, DECRYFLAG, suffix);
	#endif
	#ifdef  _OS_LINUX_
	sprintf(decFileName, "%s%s%s%s", path, name, DECRYFLAG, suffix);
	#endif

	//3. create The decrypt File
	myprint("decFileName : %s", decFileName);
	if(if_file_exist(decFileName))
	{
		sprintf(cmdBuf, "rm %s", decFileName);
		if((ret = pox_system(cmdBuf)) < 0)
		{
			myprint("Err : func pox_system()");
			goto End;
		}
	}
	if((decryFp = fopen(decFileName, "ab+")) == NULL)		assert(0);

	//2. encrypt Data from file; once 245 BYTE
	while(!(feof(srcFp)))
	{
		if((nread = fread(srcContent, 1, sizeof(srcContent) , srcFp)) < 0)				assert(0);
		if(nread == 0)	break;
		if((decryptData = my_decrypt(srcContent, 256, &deDataLenth, privatePathKey)) == NULL)	assert(0);		
		if((nwrite = fwrite(decryptData, 1, deDataLenth, decryFp)) < 0)					assert(0);    
		memset(srcContent, 0, sizeof(srcContent));                    		
	}

End:
	if(srcFp)				fclose(srcFp);
	if(decryFp)				fclose(decryFp);
	return ret;	
}

//加密文件
int encryptFileData(char *filePath, char *publicPathKey)
{
	int ret = 0;
	FILE *srcFp = NULL, *encryFp = NULL;
	char *tmp = NULL;
	char encFileName[FILENAMELENTH];
	char srcContent[245];
	int nread = 0, enDataLenth = 0, nwrite = 0;
	char *encryptData = NULL;
	char cmdBuf[1024] = { 0 };
	char suffix[15] = { 0 };
	char path[516] = { 0 }, name[256] = { 0 };
	
	if(!filePath || !publicPathKey)
	{
		myprint("Err : filePath : %p", filePath); 	  
		goto End;  
	}

	//1. open The file
	if((srcFp = fopen(filePath, "rb")) == NULL)		assert(0);
	
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
	
#ifdef	_OS_LINUX_
	if((tmp = strrchr(filePath, '/')))		
	{
		memcpy(path, filePath, MY_MIN(516, strlen(filePath) - strlen(tmp)));
		strcat(path, "/");
	}
#endif

	//4. get The FILE name 
	if(tmp == NULL)
	{
		memcpy(name, filePath, MY_MIN(258, strlen(filePath) - strlen(suffix)));
	}
	else
	{
		memcpy(name, tmp + 1, MY_MIN(258, strlen(tmp) - strlen(suffix) - 1));
	}

	//5. package The decryFileName
	#ifdef  _OS_WIN_
	sprintf(encFileName, "%s%s%s%s", path, name, ENCRYFLAG, suffix);
	#endif
	#ifdef  _OS_LINUX_
	sprintf(encFileName, "%s%s%s%s", path, name, ENCRYFLAG, suffix);
	#endif
	
	//6.open The encFile
	myprint("encFileName : %s", encFileName);
	if(if_file_exist(encFileName))
	{
		sprintf(cmdBuf, "rm %s", encFileName);
		if((ret = pox_system(cmdBuf)) < 0)
		{
			myprint("Err : func pox_system()");
			goto End;
		}
	}
	if((encryFp = fopen(encFileName, "ab+")) == NULL)		assert(0);

	//2. encrypt Data from file; once 245 BYTE
	while(!(feof(srcFp)))
	{		
		if((nread = fread(srcContent, 1, sizeof(srcContent), srcFp)) < 0)				assert(0);
		if((encryptData = my_encrypt_publicCert(srcContent, nread, &enDataLenth, publicPathKey)) == NULL)	assert(0);		
		if((nwrite = fwrite(encryptData, 1, enDataLenth, encryFp)) < 0)					assert(0);  
		memset(srcContent, 0, sizeof(srcContent));                   		
	}
			
End:
	if(srcFp)				fclose(srcFp);
	if(encryFp)				fclose(encryFp);
		
	return ret;
}

