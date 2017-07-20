#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "include_EncryDecry.h"
#include "include_sub_function.h"

#define ENCRYFLAG  "_ENCRYPT"
#define DECRYFLAG  "_DECRYPT"
#define MUTILENCYR "_ENCRYPT_RSA_AES"
#define MUTILDECYR "_DECRYPT_RSA_AES"

#define _OS_LINUX_ 1


//get The private Key News
int get_privateKey_new(void  **pRsaSrc, char *privatePathKey)
{
    int ret = 0;
    RSA  *tmpRsa = NULL;
    FILE *tmpKeyFp = NULL;
	RSA **pRsa = (RSA**)pRsaSrc;

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



retval_t get_public_key(void **pRsaSrc, char *publicKey)
{
	retval_t ret;
	FILE *fpKey = NULL;
	RSA **pRsa = (RSA**)pRsaSrc;
	
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



//get the certficate news 
retval_t get_cert_pubKey(void  **pRsaSrc, char *publicPathKey)
{
    retval_t ret;
    RSA  *tmpRsa = NULL;
    BIO  *tmpBio = NULL; 
    X509 *tmpX509 = NULL;      
    EVP_PKEY *tmpEvpKey = NULL;  
  	RSA **pRsa = (RSA**)pRsaSrc;
  
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


int decry_data(char *str, int lenth, char *deData, void *pRsaSrc)
{
    int ret = 0;
	RSA *pRsa = (RSA*)pRsaSrc;

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




int encry_data(char *str, int lenth, char *enData, void *pRsaSrc)
{
    int ret = 0;
	RSA *pRsa = (RSA*)pRsaSrc;
		
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




void package_AES_RSA_encry_dirfile_name(char *filePath, char *storeDir, char *encFileName)
{
    char *tmp = NULL;
    char suffix[20] = { 0 };
    char name[FILENAMELENTH] = { 0 };

    //2. get The SrcFile suffix
    if((tmp = strrchr(filePath, '.')))			
    {
        memcpy(suffix, tmp, strlen(tmp));
    }

    //3. get The path 
#ifdef _OS_WIN_
	tmp = strrchr(filePath, '\\');
#endif

#ifdef	_OS_LINUX_
	tmp = strrchr(filePath, '/');	
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
    sprintf(encFileName, "%s/%s%s%s", storeDir, name, MUTILENCYR, suffix);
#endif
#ifdef  _OS_LINUX_
    sprintf(encFileName, "%s/%s%s%s", storeDir, name, MUTILENCYR, suffix);
#endif


}



//组装 解密文件名
void package_AES_RSA_decry_dirfile_name(char *filePath,char *storeDir, char *decFileName)
{
    char *tmp = NULL;
    char suffix[20] = { 0 };
    char name[FILENAMELENTH] = { 0 };
    char tmpname[FILENAMELENTH] = { 0 };

    //2. get The SrcFile suffix
    if((tmp = strrchr(filePath, '.')))			
    {
        memcpy(suffix, tmp, strlen(tmp));
    }

    //3. get The path 
#ifdef _OS_WIN_
	tmp = strrchr(filePath, '\\');
#endif

#ifdef  _OS_LINUX_
	tmp = strrchr(filePath, '/');
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
    sprintf(decFileName, "%s/%s%s%s", storeDir, name, MUTILDECYR, suffix);
#endif
#ifdef	_OS_LINUX_
    sprintf(decFileName, "%s/%s%s%s", storeDir, name, MUTILDECYR, suffix);
#endif


}

