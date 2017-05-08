#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<assert.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>

#include "encryptData.h"

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
	printf("=========== 11 =============\n");

	//1.get The public Key from cert
	if((b = BIO_new_file(publicPathKey,"rb")) == NULL)		assert(0);	 
	if((x=PEM_read_bio_X509(b,NULL,NULL,NULL)) == NULL)		assert(0); 
    if((k=X509_get_pubkey(x)) == NULL)						assert(0); 
    if((pRsa=EVP_PKEY_get1_RSA(k)) == NULL)					assert(0);
	
	 printf("=========== 12 =============\n");
	 
	//2. alloc The encrypData Content
	pEnData = malloc(RSA_size(pRsa) + 1);
	memset(pEnData, 0, RSA_size(pRsa) + 1 );

	 printf("=========== 13  RSA_size(pRsa) : %d =============\n",  RSA_size(pRsa));

	//3. public Key encrypt Data
	if((*enDataLenth = RSA_public_encrypt(lenth, (unsigned char *)str, (unsigned char *)pEnData, pRsa, RSA_PKCS1_PADDING)) < 0)
	{
		myprint("Err : func RSA_public_encrypt()");
		free(pEnData);
		pEnData = NULL;
		goto End;        
	} 
	printf("=========== 14 =============\n");
	
End:
	
	if(pRsa)  			RSA_free(pRsa);
	if(fpKey)			fclose(fpKey);
	if(k)				EVP_PKEY_free(k);   
    if(b)    			BIO_free(b);  
	
	return pEnData;
}


char* my_decrypt(char *str, int lenth, char *privatePathKey)
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
	if((RSA_private_decrypt(lenth, (unsigned char *)str, (unsigned char *)pDeData, pRsa, RSA_PKCS1_PADDING)) < 0)
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


int encryptFileData(char *filePath)
{
	int ret = 0;
	FILE *srcFp = NULL, *encryFp = NULL;
	char *tmp = NULL;
	char decFileName[FILENAMELENTH];
	char srcContent[245];

	if(!filePath)
	{
		myprint("Err : filePath : %p", filePath); 	  
		goto End;  
	}

	//1. open The file
	if((srcFp = fopen(filePath, "rb")) == NULL)		assert(0);

	//2. get The SrcFile suffix
	memset(decFileName, 0, FILENAMELENTH);
	if((tmp = strrchr(filePath, '.')))		sprintf(decFileName, "%s", );		
	{
		memcpy(decFileName, filePath, strlen(filePath) - strlen(tmp));
		strcat(decFileName, "_ENCRYPT");
		strcat(decFileName, tmp);
	}
	else
	{
		memcpy(decFileName, filePath, strlen(filePath) - strlen(tmp));
		strcat(decFileName, "_ENCRYPT");
	}

	//3. create The encrypt File
	if((encryFp = fopen(decFileName, "ab+")) == NULL)		assert(0);

	//2. encrypt Data from file; once 245 BYTE
	while(!(feof(fp)))
	{
		
	}
			
End:

	return ret;
}

