#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>

#include "encryptData.h"


char* my_encrypt02(char *str, int lenth, char *publicPathKey)
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
	pEnData = (unsigned char *)malloc(rsaLen + 1);
	memset(pEnData, 0, rsaLen + 1 );
	
	//4. public Key encrypt Data
	if((RSA_public_encrypt(rsaLen, (unsigned char *)str, (unsigned char *)pEnData, pRsa, RSA_NO_PADDING)) < 0)
	{
		myprint("Err : func RSA_public_encrypt()");
		goto End;        
	}
	
	
End:
	
	if(pRsa)  			RSA_free(pRsa);
	if(fpKey)			fclose(fpKey);
	
	return (char *)pEnData;
}


char* my_decrypt02(char *str, int lenth, char *privatePathKey)
{
	char *pDeData = NULL;
	RSA  *pRsa = NULL;
	FILE *fpKey = NULL;
	int  rsaLen = 0;
	
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
	rsaLen = RSA_size(pRsa);	
	pDeData = (unsigned char *)malloc(rsaLen + 1);
	memset(pDeData, 0, rsaLen + 1 );
    
    if((RSA_private_decrypt(rsaLen,  (unsigned char *)str,  (unsigned char *)pDeData, pRsa, RSA_NO_PADDING)) < 0)
    {
    	myprint("Err : func RSA_private_decrypt()");
		goto End; 
    }
    
End:
	
	if(pRsa)  			RSA_free(pRsa);
	if(fpKey)			fclose(fpKey);
	
	return (char *)pDeData;
}


//从证书中获取公钥信息
char* my_encrypt(char *str, int lenth, char *publicPathKey)
{
	char *pEnData = NULL;
	RSA  *pRsa = NULL;
	FILE *fpKey = NULL;
	int  rsaLen = 0;
	BIO  *b = NULL; 
	X509 *x = NULL;      
    EVP_PKEY *k = NULL;  
    
	if(!str || lenth < 0 || !publicPathKey)
	{
		myprint("Err : str : %p, lenth : %d, publicPathKey : %p", str, lenth, publicPathKey);       
        goto End;  
	}
	
	b=BIO_new_file(publicPathKey,"rb"); 
	x=PEM_read_bio_X509(b,NULL,NULL,NULL);  
    k=X509_get_pubkey(x);  
    pRsa=EVP_PKEY_get1_RSA(k); 
	
	//3. get The Lenth from  public Key News
	rsaLen = RSA_size(pRsa);	
	pEnData = (unsigned char *)malloc(rsaLen + 1);
	memset(pEnData, 0, rsaLen + 1 );
	
	//4. public Key encrypt Data
	if((RSA_public_encrypt(rsaLen, (unsigned char *)str, (unsigned char *)pEnData, pRsa, RSA_NO_PADDING)) < 0)
	{
		myprint("Err : func RSA_public_encrypt()");
		goto End;        
	}
	
	
End:
	
	if(pRsa)  			RSA_free(pRsa);
	if(fpKey)			fclose(fpKey);
	
	return (char *)pEnData;
}


char* my_decrypt(char *str, int lenth, char *privatePathKey)
{
	char *pDeData = NULL;
	RSA  *pRsa = NULL;
	FILE *fpKey = NULL;
	int  rsaLen = 0;
	
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
	rsaLen = RSA_size(pRsa);	
	pDeData = (unsigned char *)malloc(rsaLen + 1);
	memset(pDeData, 0, rsaLen + 1 );
    
    if((RSA_private_decrypt(rsaLen,  (unsigned char *)str,  (unsigned char *)pDeData, pRsa, RSA_NO_PADDING)) < 0)
    {
    	myprint("Err : func RSA_private_decrypt()");
		goto End; 
    }
    
End:
	
	if(pRsa)  			RSA_free(pRsa);
	if(fpKey)			fclose(fpKey);
	
	return (char *)pDeData;
}

