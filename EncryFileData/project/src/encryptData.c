#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>

#include "encryptData.h"
#include "include_sub_function.h"

#define ENCRYFLAG  "_ENCRYPT"
#define DECRYFLAG  "_DECRYPT"
#define ENCRYMAXSIZE  245
#define LIVETHRM    10


struct _encry_handle{
	
	char 		*srcFile;
	char 		*encryFile;
	uint32_t	 encrySize;
	uint32_t     initPosition;
	RSA			*pRsa;
	int 		workRoundNum;
	
};



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

//get the certficate news 
int get_cert_pubKey( EVP_PKEY **evpKey, BIO  **bioHandle, RSA  **pRsa, char *publicPathKey)
{
	int ret = 0;
	RSA  *tmpRsa = NULL;
	BIO  *tmpBio = NULL; 
	X509 *tmpX509 = NULL;      
    EVP_PKEY *tmpEvpKey = NULL;  
	
	if(!evpKey || !pRsa || !publicPathKey || !bioHandle)
	{
		myprint("Err : evpKey : %p, pRsa : %p, publicPathKey : %p, bioHandle : %p", evpKey, pRsa, publicPathKey, bioHandle);       
		ret = -1;
		goto End;  
	}

	//1.get The public Key from cert
	if((tmpBio = BIO_new_file(publicPathKey, "rb" )) == NULL)				assert(0);	
	if((tmpX509 = PEM_read_bio_X509(tmpBio, NULL, NULL, NULL)) == NULL) 	assert(0); 
	if((tmpEvpKey = X509_get_pubkey(tmpX509)) == NULL)						assert(0); 
	if((tmpRsa = EVP_PKEY_get1_RSA(tmpEvpKey)) == NULL) 					assert(0);

	*evpKey = tmpEvpKey;
	*bioHandle = tmpBio;
	*pRsa = tmpRsa;

End:

	if(ret < 0)
	{			
		if(tmpRsa)  				RSA_free(tmpRsa);
		if(tmpEvpKey)				EVP_PKEY_free(tmpEvpKey);   
	    if(tmpBio)    				BIO_free(tmpBio); 
	}
	
	return ret; 
}


//证书加密信息
char* my_encrypt_publicCert(char *str, int lenth, int *enDataLenth, char *publicPathKey)
{
	char *pEnData = NULL;
	RSA  *pRsa = NULL;
	BIO  *b = NULL;      
    EVP_PKEY *k = NULL;  
    
	if(!str || lenth < 0 || !publicPathKey || !enDataLenth)
	{
		myprint("Err : str : %p, lenth : %d, publicPathKey : %p", str, lenth, publicPathKey);       
        goto End;  
	}

	if(get_cert_pubKey(&k, &b, &pRsa, publicPathKey) < 0)
	{
		myprint("Err : func get_cert_pubKey()");
		goto End;	
	}

	//2. alloc The encrypData Content
	pEnData = malloc(RSA_size(pRsa) + 1);
	memset(pEnData, 0, RSA_size(pRsa) + 1 );

	//3. public Key encrypt Data
	if((*enDataLenth = RSA_public_encrypt(lenth, (unsigned char *)str, (unsigned char *)pEnData, pRsa, RSA_PKCS1_PADDING)) < 0)
	{
		myprint("Err : func RSA_public_encrypt()");
		free(pEnData);
		pEnData = NULL;
		goto End;        
	} 
End:
	
	if(pRsa)  			RSA_free(pRsa);
	if(k)				EVP_PKEY_free(k);   
    if(b)    			BIO_free(b);  
	
	return pEnData;
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


//解密信息
char* my_decrypt(char *str, int lenth, int *deDataLenth, char *privatePathKey)
{
	char *pDeData = NULL;
	RSA  *pRsa = NULL;
	
	if(!str || lenth < 0 || !privatePathKey)
	{
		myprint("Err : str : %p, lenth : %d, privatePathKey : %p", str, lenth, privatePathKey);       
        goto End;  
	}

	if(get_privateKey_new(&pRsa, privatePathKey) < 0)
	{
		myprint("Err : func get_privateKey_new() "); 	  
		goto End;  
	}
 
    //3. get The Lenth from  private Key News	
	pDeData = malloc(RSA_size(pRsa) + 1);;
	memset(pDeData, 0, RSA_size(pRsa) + 1 );
    
	if((*deDataLenth = RSA_private_decrypt(256, (unsigned char *)str, (unsigned char *)pDeData, pRsa, RSA_PKCS1_PADDING)) < 0)
    {
    	myprint("Err : func RSA_private_decrypt()");
		free(pDeData);
		pDeData = NULL;
		goto End; 
    }
    
End:
	
	if(pRsa)  			RSA_free(pRsa);
	
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
	RSA  *pRsa = NULL;
	
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

	//6. create The decrypt File
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

	//7. get The private Key News
	if(get_privateKey_new(&pRsa, privatePathKey) < 0)
	{
		myprint("Err : func get_privateKey_new() "); 	  
		goto End;  
	}

	//8. alloc The memory for encrypt Data
	decryptData = malloc(RSA_size(pRsa) + 1);
	memset(decryptData, 0, RSA_size(pRsa) + 1 );

	//8. encrypt Data from file; once 245 BYTE
	while(!(feof(srcFp)))
	{
		if((nread = fread(srcContent, 1, sizeof(srcContent) , srcFp)) < 0)						assert(0);
		if(nread == 0)			break;
		if((deDataLenth = decry_data(srcContent, 256, decryptData, pRsa)) < 0)					assert(0);
		if((nwrite = fwrite(decryptData, 1, deDataLenth, decryFp)) < 0)							assert(0);    
		memset(srcContent, 0, sizeof(srcContent));   
		memset(decryptData, 0, RSA_size(pRsa) + 1);  
	}

End:
	if(srcFp)				fclose(srcFp);
	if(decryFp)				fclose(decryFp);
	if(pRsa)				RSA_free(pRsa);
	if(decryptData)			free(decryptData);
	
	return ret;	
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
		goto End;		 
	} 

End:
	
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
	RSA  *pRsa = NULL;
	BIO  *b = NULL;      
    EVP_PKEY *k = NULL; 

	
	if(!filePath || !publicPathKey)
	{
		myprint("Err : filePath : %p", filePath); 
		ret = -1;
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

	//7.get The cert news
	if(get_cert_pubKey(&k, &b, &pRsa, publicPathKey) < 0)
	{
		myprint("Err : func get_cert_pubKey()");
		goto End;	
	}
	
	//8. alloc The memory for encrypt Data
	encryptData = malloc(RSA_size(pRsa) + 1);
	memset(encryptData, 0, RSA_size(pRsa) + 1 );

	//9. encrypt Data from file; once 245 BYTE
	while(!(feof(srcFp)))
	{		
		if((nread = fread(srcContent, 1, sizeof(srcContent), srcFp)) < 0)				assert(0);
		if((enDataLenth = encry_data(srcContent, nread, encryptData, pRsa)) < 0)		assert(0);
		if((nwrite = fwrite(encryptData, 1, enDataLenth, encryFp)) < 0)					assert(0);  
		memset(srcContent, 0, sizeof(srcContent));
		memset(encryptData, 0, RSA_size(pRsa) + 1);  
	}
			
End:
	if(srcFp)				fclose(srcFp);
	if(encryFp)				fclose(encryFp);
	if(pRsa)  				RSA_free(pRsa);
	if(k)					EVP_PKEY_free(k);   
    if(b)    				BIO_free(b);  
	if(encryptData)			free(encryptData);
	
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


int mutilEncryFile(char *filePath, char *publicPathKey)
{
	int ret = 0;
	int roundNum = 0;			//文件加密的总轮次数
	int threadNum = 0;			//加密文件所需的总线程数
	int lowRoundNum = 0, MaxRoundNum = 0;	//每个线程的最低加密次数 和最大加密次数
	if(!filePath || !publicPathKey)
	
	//1. get The file encry round Number
	if((roundNum = get_encryNum_fromFile(filePath, ENCRYMAXSIZE)) < 0)
	{
		myprint("Err : func get_encryNum_fromFile()");
		ret = -1;
		goto End; 		
	}
	
	//2. get The thread Number for work to encry file
	if((threadNum = get_workThreadNum(roundNum, LIVETHRM, &lowRoundNum)) < 0)
	{
		myprint("Err : func get_workThreadNum()");
		ret = -1;
		goto End; 	
	}
	
	
	get_residueSize_needThreadNum(filePath, threadNum, lowRoundNum, ENCRYMAXSIZE)
	
End:	
	return ret;
}

int get_residueSize_needThreadNum(char *filePath, int threadNum, int lowRoundNum, int baseSize, int *size)
{
	int ret = 0;	
	int fileSize = 0;		//文件大小
	int resiFileSize = 0;
	
	
	if(lowRoundNum == 0)		return 0;
	
	if(!filePath || threadNum < 0 || lowRoundNum < 0 || baseSize < 0)	
	{
		myprint("Err : filePath : %p, threadNum : %d, lowRoundNum : %d, baseSize : %d", filePath, threadNum, lowRoundNum, baseSize);
		ret = -1;
		goto End; 	
	}	
		
	//1. get fileSize	
	if((fileSize = get_file_size(filePath)) < 0)
	{
		myprint("Err : func get_file_size()");
		ret = -1;
		goto End; 
	}
	
	//2.get The residue fileSize
	resiFileSize = fileSize - threadNum * baseSize * lowRoundNum;
	
	//3. get The residue fileSize need threadNum
	ret = resiFileSize / baseSize;
	
	//4.
	if((resiFileSize % baseSize) > 0)	
		size = resiFileSize - baseSize * ret;
End:
			
	return ret;
}