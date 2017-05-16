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

#include "encryptData.h"
#include "include_sub_function.h"
#include "thread_pool.h"

#define ENCRYFLAG  "_ENCRYPT"
#define DECRYFLAG  "_DECRYPT"
#define ENCRYMAXSIZE  245
#define DECRYMAXSIZE  256
#define LIVETHRM    3
#define CACHEDECRYSIZE 1024 * 1225

encryHandle_t	*threadWorkHandle = NULL;	
RSA  *g_pRsa = NULL;
sem_t  g_sem_notify_task_complete;
char **g_cache_memory = NULL;
pthread_mutex_t g_muetx_lock = PTHREAD_MUTEX_INITIALIZER;


int g_fd = 0;

struct _encry_handle{

    char 		srcFile[FILENAMELENTH];			//原始文件的绝对路径
    char 		encryFile[FILENAMELENTH];		//加密后文件局对路径
    uint32_t	encrySize;						//线程加密数据的字节
    uint32_t    readInitPosition;				//读取文件的起始位置
    uint32_t	writeInitPosition;				//写文件的起始位置
    //RSA			*pRsa;							//秘钥
    //int 		workRoundNum;					//线程的加密轮次

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
int get_cert_pubKey(RSA  **pRsa, char *publicPathKey)
{
    int ret = 0;
    RSA  *tmpRsa = NULL;
    BIO  *tmpBio = NULL; 
    X509 *tmpX509 = NULL;      
    EVP_PKEY *tmpEvpKey = NULL;  

    if(!pRsa || !publicPathKey )
    {
        myprint("Err :  pRsa : %p, publicPathKey : %p", pRsa, publicPathKey);       
        ret = -1;
        goto End;  
    }

    //1.get The public Key from cert
    if((tmpBio = BIO_new_file(publicPathKey, "rb" )) == NULL)				assert(0);	
    if((tmpX509 = PEM_read_bio_X509(tmpBio, NULL, NULL, NULL)) == NULL) 	assert(0); 
    if((tmpEvpKey = X509_get_pubkey(tmpX509)) == NULL)						assert(0); 
    if((tmpRsa = EVP_PKEY_get1_RSA(tmpEvpKey)) == NULL) 					assert(0);

    *pRsa = tmpRsa;

End:

    if(ret < 0)
    {			
        if(tmpRsa)  				RSA_free(tmpRsa);	
        return ret;
    }

    if(tmpEvpKey)					EVP_PKEY_free(tmpEvpKey);   
    if(tmpBio)    					BIO_free(tmpBio); 

    return ret; 
}


//证书加密信息
char* my_encrypt_publicCert(char *str, int lenth, int *enDataLenth, char *publicPathKey)
{
    char *pEnData = NULL;
    RSA  *pRsa = NULL;


    if(!str || lenth < 0 || !publicPathKey || !enDataLenth)
    {
        myprint("Err : str : %p, lenth : %d, publicPathKey : %p", str, lenth, publicPathKey);       
        goto End;  
    }

    if(get_cert_pubKey(&pRsa, publicPathKey) < 0)
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
    char decFileName[FILENAMELENTH] = { 0 };
    char srcContent[256];
    int nread = 0, deDataLenth = 0, nwrite = 0;
    char *decryptData = NULL;
    char cmdBuf[1024] = { 0 };
    RSA  *pRsa = NULL;
    //char tmpRsa[256] = { 0 };

    if(!filePath || !privatePathKey)
    {
        myprint("Err : filePath : %p", filePath); 	  
        goto End;  
    }

    //1. open The file
    if((srcFp = fopen(filePath, "rb")) == NULL)		assert(0);

    //2. package The decryFileName
    package_decry_file_name(filePath, decFileName);

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

    //4. get The private Key News
    if(get_privateKey_new(&pRsa, privatePathKey) < 0)
    {
        myprint("Err : func get_privateKey_new() "); 	  
        goto End;  
    }
    //memcpy(tmpRsa, pRsa, RSA_size(pRsa));

    //5. alloc The memory for encrypt Data
    decryptData = malloc(RSA_size(pRsa) + 1);
    memset(decryptData, 0, RSA_size(pRsa) + 1 );

    //6. encrypt Data from file; once 245 BYTE
    while(!(feof(srcFp)))
    {
        if((nread = fread(srcContent, 1, sizeof(srcContent) , srcFp)) < 0)						assert(0);
        if(nread == 0)			break;
        if((deDataLenth = decry_data(srcContent, DECRYMAXSIZE, decryptData, pRsa)) < 0)			assert(0);
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
        ERR_print_errors_fp(stdout);  
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
    char encFileName[FILENAMELENTH];
    char srcContent[245];
    int nread = 0, enDataLenth = 0, nwrite = 0;
    char *encryptData = NULL;
    char cmdBuf[FILENAMELENTH] = { 0 };
    RSA  *pRsa = NULL;


    if(!filePath || !publicPathKey)
    {
        myprint("Err : filePath : %p, publicPathKey : %p", filePath, publicPathKey); 
        ret = -1;
        goto End;  
    }

    //1. open The file
    if((srcFp = fopen(filePath, "rb")) == NULL)		assert(0);
    	
        //2. get The encryName
        package_encry_file_name(filePath, encFileName);

    //3. open The encFile
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

    //4. get The cert news
    if(get_cert_pubKey(&pRsa, publicPathKey) < 0)
    {
        myprint("Err : func get_cert_pubKey()");
        goto End;	
    }

    //5. alloc The memory for encrypt Data
    encryptData = malloc(RSA_size(pRsa) + 1);
    memset(encryptData, 0, RSA_size(pRsa) + 1 );

    //6. encrypt Data from file; once 245 BYTE
    while(!(feof(srcFp)))
    {		
        if((nread = fread(srcContent, 1, sizeof(srcContent), srcFp)) < 0)				assert(0);
        if((enDataLenth = encry_data(srcContent, nread, encryptData, pRsa)) < 0)		assert(0);
        if((nwrite = fwrite(encryptData, 1, enDataLenth, encryFp)) < 0)					assert(0);  
        memset(srcContent, 0, sizeof(srcContent));
        memset(encryptData, 0, RSA_size(pRsa) + 1);  
    }
    myprint("nread : %d, enDataLenth : %d", nread, enDataLenth);

End:
    if(srcFp)				fclose(srcFp);
    if(encryFp)				fclose(encryFp);
    if(pRsa)  				RSA_free(pRsa); 
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


#if 0
int mutilEncryFile(char *filePath, char *publicPathKey)
{
    int ret = 0, i = 0;
    int roundNum = 0;							//文件加密的总轮次数
    int threadNum = 0;							//加密文件所需的总线程数
    int lowRoundNum = 0;						//每个线程的最低加密次数 
    int residRoundLowNum =0;					//剩余文件所需最小线程数(即所需工作轮次)
    int lastFileSize = 0;						//最后剩余文件的大小
    int readLocation = 0, writeLocation = 0;		//每个线程打开读写两个文件的位置
    //线程集合
    char encryFileName[FILENAMELENTH] = { 0 };	//加密后文件的绝对路径(或文件名)
    RSA *pRsa = NULL;
    threadpool_t *pool;
    if(!filePath || !publicPathKey)
    {
        myprint("Err : filePath : %p, publicPathKey : %p", filePath, publicPathKey); 
        ret = -1;
        goto End;  
    }
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
    //3. get The residue size of file to work need threadNum(equal : need work round Number)
    if((residRoundLowNum = get_residueSize_needThreadNum(filePath, threadNum, lowRoundNum, ENCRYMAXSIZE, &lastFileSize)) < 0)
    {
        myprint("Err : func get_workThreadNum()");
        ret = -1;
        goto End; 
    }
    //4. get The encryFileName and rsa public Key
    package_encry_file_name(filePath, encryFileName);
    if((ret = get_cert_pubKey(&pRsa, publicPathKey)) < 0)
    {
        myprint("Err : func get_cert_pubKey()");
        ret = -1;
        goto End; 
    }
    //5. deal with per-thread work 
    memset(threadWorkHandle, 0 , sizeof(encryHandle_t) * LIVETHRM);
    for(i = 0; i < threadNum; i++)
    {
        memcpy(threadWorkHandle[i].srcFile, filePath, MY_MIN(FILENAMELENTH, strlen(filePath)));
        memcpy(threadWorkHandle[i].encryFile, encryFileName, MY_MIN(FILENAMELENTH, strlen(encryFileName)));
        threadWorkHandle[i].encrySize = ENCRYMAXSIZE * lowRoundNum;
        memcpy((threadWorkHandle[i].pRsa), pRsa, RSA_size(pRsa));
    }
    if(residRoundLowNum > 0)	//最多次数的加密线程
    {
        for(i = 0; i < residRoundLowNum; i++)
        {
            threadWorkHandle[i].encrySize += ENCRYMAXSIZE;
            threadWorkHandle[i].readInitPosition = readLocation;
            threadWorkHandle[i].writeInitPosition = writeLocation;
            writeLocation += (lowRoundNum + 1) * DECRYMAXSIZE;
            readLocation += threadWorkHandle[i].encrySize;
        }
    }
    else
    {
        for(i = 0; i < threadNum; i++)
        {
            threadWorkHandle[i].encrySize += ENCRYMAXSIZE;
            threadWorkHandle[i].readInitPosition = readLocation;
            threadWorkHandle[i].writeInitPosition = writeLocation;
            writeLocation += (lowRoundNum + 1) * DECRYMAXSIZE;
            readLocation += threadWorkHandle[i].encrySize;
        }
    }
    if(lastFileSize > 0)		//解决最后一个线程和 中间的平均线程
    { 
        //中间的平均线程
        for(; i < threadNum - 1; i++)
        {
            //threadWorkHandle[i].encrySize += ENCRYMAXSIZE;
            threadWorkHandle[i].readInitPosition = readLocation;
            threadWorkHandle[i].writeInitPosition = writeLocation;
            writeLocation += lowRoundNum * DECRYMAXSIZE;
            readLocation += threadWorkHandle[i].encrySize;
        }
        //最后一个线程
        threadWorkHandle[i].readInitPosition = readLocation;
        threadWorkHandle[i].writeInitPosition = writeLocation;
        threadWorkHandle[i].encrySize += lastFileSize;
    }
    else
    {
        //剩余的所有线程工作量
        for(; i < threadNum; i++)
        {
            threadWorkHandle[i].readInitPosition = readLocation;
            threadWorkHandle[i].writeInitPosition = writeLocation;
            writeLocation += lowRoundNum * DECRYMAXSIZE;
            readLocation += threadWorkHandle[i].encrySize;
        }
    }
    if((pool = init()) == NULL)
    {
        myprint("Err : func init_thread_pool()");
        ret = -1;
        goto End; 
    }
    for(i = 0; i < threadNum; i++)
    {
        threadpool_add(pool, encry_process, (void *)&threadWorkHandle[i]);
    }
    threadpool_destroy(pool);	
End:	
    if(pRsa)  				RSA_free(pRsa); 
    return ret;
}
#endif

#if 0
int mutilEncryFile022(char *filePath, char *publicPathKey)
{
    int ret = 0, i = 0;
    int roundNum = 0;							//文件加密的总轮次数
    int threadNum = 0;							//加密文件所需的总线程数
    int lowRoundNum = 0;						//每个线程的最低加密次数 
    int residRoundLowNum =0;					//剩余文件所需最小线程数(即所需工作轮次)
    int lastFileSize = 0;						//最后剩余文件的大小
    int readLocation = 0, writeLocation = 0;		//每个线程打开读写两个文件的位置
    encryHandle_t	threadWorkHandle[LIVETHRM];	//线程集合
    char encryFileName[FILENAMELENTH] = { 0 };	//加密后文件的绝对路径(或文件名)
    RSA *pRsa = NULL;
    threadpool_t *pool;
    if(!filePath || !publicPathKey)
    {
        myprint("Err : filePath : %p, publicPathKey : %p", filePath, publicPathKey); 
        ret = -1;
        goto End;  
    }
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
    //3. get The residue size of file to work need threadNum(equal : need work round Number)
    if((residRoundLowNum = get_residueSize_needThreadNum(filePath, threadNum, lowRoundNum, ENCRYMAXSIZE, &lastFileSize)) < 0)
    {
        myprint("Err : func get_workThreadNum()");
        ret = -1;
        goto End; 
    }
    //4. get The encryFileName and rsa public Key
    package_encry_file_name(filePath, encryFileName);
    if((ret = get_cert_pubKey(&pRsa, publicPathKey)) < 0)
    {
        myprint("Err : func get_cert_pubKey()");
        ret = -1;
        goto End; 
    }
    //5. deal with per-thread work 
    memset(threadWorkHandle, 0 , sizeof(encryHandle_t) * LIVETHRM);
    for(i = 0; i < threadNum; i++)
    {
        memcpy(threadWorkHandle[i].srcFile, filePath, MY_MIN(FILENAMELENTH, strlen(filePath)));
        memcpy(threadWorkHandle[i].encryFile, encryFileName, MY_MIN(FILENAMELENTH, strlen(encryFileName)));
        threadWorkHandle[i].encrySize = ENCRYMAXSIZE * lowRoundNum;
        memcpy((threadWorkHandle[i].pRsa), pRsa, RSA_size(pRsa));
    }
    if(residRoundLowNum > 0)	//最多次数的加密线程
    {
        for(i = 0; i < residRoundLowNum; i++)
        {
            threadWorkHandle[i].encrySize += ENCRYMAXSIZE;
            threadWorkHandle[i].readInitPosition = readLocation;
            threadWorkHandle[i].writeInitPosition = writeLocation;
            writeLocation += (lowRoundNum + 1) * DECRYMAXSIZE;
            readLocation += threadWorkHandle[i].encrySize;
        }
    }
    else
    {
    }
    if(lastFileSize > 0)		//解决最后一个线程和 中间的平均线程
    { 
        threadWorkHandle[threadNum].readInitPosition = readLocation;
        threadWorkHandle[i].writeInitPosition = writeLocation;
        threadWorkHandle[i].encrySize += lastFileSize;
        readLocation += threadWorkHandle[i++].encrySize;
    }
    else
    {
    }
    threadWorkHandle[i].readInitPosition = readLocation;
    if((pool = init_thread_pool()) == NULL)
    {
        myprint("Err : func init_thread_pool()");
        ret = -1;
        goto End; 
    }
    for(i = 0; i < threadNum; i++)
    {
        threadpool_add(pool, process, (void *)&threadWorkHandle[i]);
    }
    threadpool_destroy(pool);	
End:	
    if(pRsa)  				RSA_free(pRsa); 
    return ret;
}
#endif




/*
 *@param : threadNum  	工作线程数
 *@param : lowRoundNum	工作线程最低工作轮次
 *@param : baseNum		读取文件切割的基数大小
 */
void dealwith_per_threadWork(char *filePath, char *decryFileName, int threadNum, int lowRoundNum, int readBaseNum, int writeBaseNum)
{
    int frontThreadTotalByte = 0;
    int rearThreadTotalByte = 0;
    	int fileSize = 0;
    int i = 0, readLocation = 0, writeLocation = 0;

    //1. get The file Size
    if((fileSize = get_file_size(filePath)) < 0)
    {
        myprint("Err : func get_file_size() ");
        assert(0);		
    }

    //2.caculate The front And rear total Bytes
    if(threadNum == LIVETHRM)
    {	
        frontThreadTotalByte = lowRoundNum * readBaseNum * (LIVETHRM - 1) ;
        rearThreadTotalByte = fileSize - frontThreadTotalByte;
		myprint("rearThreadTotalByte : %d", rearThreadTotalByte);
    }
    else
    {
        frontThreadTotalByte = readBaseNum * (threadNum - 1) ;
        rearThreadTotalByte = fileSize - frontThreadTotalByte;
    }

    memset(threadWorkHandle, 0 , sizeof(encryHandle_t) * LIVETHRM);

    if(threadNum > 1)
    {	
        for(i = 0; i < threadNum - 1; i++)
        {
            strcpy(threadWorkHandle[i].srcFile, filePath);
            strcpy(threadWorkHandle[i].encryFile, decryFileName);
            threadWorkHandle[i].encrySize = readBaseNum * lowRoundNum;
            threadWorkHandle[i].readInitPosition = readLocation;
            threadWorkHandle[i].writeInitPosition = writeLocation;
            readLocation += threadWorkHandle[i].encrySize;		
            writeLocation += writeBaseNum * lowRoundNum;			
        }
    }
    strcpy(threadWorkHandle[i].srcFile, filePath);
    strcpy(threadWorkHandle[i].encryFile, decryFileName);
    threadWorkHandle[i].encrySize = rearThreadTotalByte;
    threadWorkHandle[i].readInitPosition = readLocation;
    threadWorkHandle[i].writeInitPosition = writeLocation;		

}

#if 0
/*
 *@param : threadNum  	工作线程数
 *@param : lowRoundNum	工作线程最低工作轮次
 *@param : baseNum		读取文件切割的基数大小
 */
void dealwith_per_threadWork_Rsa(char *filePath, char *decryFileName, RSA *pRsa, int threadNum, int lowRoundNum, int readBaseNum, int writeBaseNum)
{
    int frontThreadTotalByte = 0;
    int rearThreadTotalByte = 0;
    	int fileSize = 0;
    int i = 0, readLocation = 0, writeLocation = 0;
    //1. get The file Size
    if((fileSize = get_file_size(filePath)) < 0)
    {
        myprint("Err : func get_file_size() ");
        assert(0);		
    }
    //2.caculate The front And rear total Bytes
    if(threadNum == LIVETHRM)
    {	
        frontThreadTotalByte = lowRoundNum * readBaseNum * (LIVETHRM - 1) ;
        rearThreadTotalByte = fileSize - frontThreadTotalByte;
    }
    else
    {
        frontThreadTotalByte = readBaseNum * (threadNum - 1) ;
        rearThreadTotalByte = fileSize - frontThreadTotalByte;
    }
    memset(threadWorkHandle, 0 , sizeof(encryHandle_t) * LIVETHRM);
    if(threadNum > 1)
    {	
        for(i = 0; i < threadNum - 1; i++)
        {
            strcpy(threadWorkHandle[i].srcFile, filePath);
            strcpy(threadWorkHandle[i].encryFile, decryFileName);
            threadWorkHandle[i].encrySize = readBaseNum * lowRoundNum;
            threadWorkHandle[i].readInitPosition = readLocation;
            threadWorkHandle[i].writeInitPosition = writeLocation;
            readLocation += threadWorkHandle[i].encrySize;		
            writeLocation += writeBaseNum * lowRoundNum;
            memcpy(threadWorkHandle[i].pRsa, pRsa, RSA_size(pRsa));
        }
    }
    strcpy(threadWorkHandle[i].srcFile, filePath);
    strcpy(threadWorkHandle[i].encryFile, decryFileName);
    threadWorkHandle[i].encrySize = rearThreadTotalByte;
    threadWorkHandle[i].readInitPosition = readLocation;
    threadWorkHandle[i].writeInitPosition = writeLocation;		
    memcpy(threadWorkHandle[i].pRsa, pRsa, RSA_size(pRsa));
    myprint("threadWorkHandle[i].pRsa : %d", RSA_size((RSA*)threadWorkHandle[i].pRsa));
}
#endif

int multiDecryFile(char *filePath, char *privatePathKey, threadpool_t *pool)
{
    int ret = 0;
    int roundNum = 0; 				//本文件需要解密的总轮次
    int threadNum = 0;				//解密文件需要的线程总数
    int lowRoundNum = 0;			//每个线程最低的工作轮次
    RSA *pRsa = NULL;				//秘钥信息
    char decryFileName[FILENAMELENTH] = { 0 };
    int i = 0, begin, end;			//定义时间开始和结束标志位  ;
	char cmdBuf[FILENAMELENTH] = { 0 };
//	int  fd = 0;
	begin=clock();//开始计时

    if(!filePath || !privatePathKey)
    {
        myprint("Err : filePath : %p, privatePathKey : %p", filePath, privatePathKey); 
        ret = -1;
        goto End;  
    }  
	if(!if_file_exist(filePath))
	{
		myprint("Err : filePath : %s is not exist", filePath); 
		ret = -1;
		goto End;

	}

	
    //1. get The file encry round Number
    if((roundNum = get_encryNum_fromFile(filePath, DECRYMAXSIZE)) < 0)
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
   myprint("--------- 2 threadNum : %d, lowRoundNum : %d ------------", threadNum, lowRoundNum);

    //3. get The encryFileName and rsa public Key
    package_decry_file_name(filePath, decryFileName);
    if(get_privateKey_new(&pRsa, privatePathKey) < 0)
    {
        myprint("Err : func get_privateKey_new() "); 	  
        goto End;  
    }
    g_pRsa = pRsa;
	
    //4. deal with per-thread work
    dealwith_per_threadWork(filePath, decryFileName, threadNum, lowRoundNum, DECRYMAXSIZE, DECRYMAXSIZE);

	if(if_file_exist(decryFileName))
	{
	 	sprintf(cmdBuf, "rm %s", decryFileName);
	 	if((ret = pox_system(cmdBuf)) < 0)
	 	{
		 	myprint("Err : func pox_system()");
		 	goto End;
	 	}
	}
	
#if 1
	if((g_fd = open(decryFileName,  O_WRONLY | O_APPEND | O_CREAT, 0777 )) < 0)
	{
		myprint("Err : thread 0x%x working	func fopen()", (unsigned int)pthread_self());
		goto End;
	}
#endif
	
    //5. add working for Thread
    for(i = 0; i < threadNum; i++)
    {
        threadpool_add(pool, decry_process, (void *)i);
    }

	//6. wait The child working OK
	for(i = 0; i < threadNum; i++)
		sem_wait(&g_sem_notify_task_complete);

	if(g_fd > 0)	close(g_fd);		

	//7. caculate Time for program runing 
	end=clock();//结束计时  
    printf("The operation time : %d\n", end-begin);//差为时间，单位毫秒  
End:	

    if(g_pRsa)
	{
		RSA_free(g_pRsa); 
		g_pRsa = NULL;
	}
    return ret;
}

void write_file(int fd, char *srcContent, int Lenth, int position, int index)
{


	if((flock(fd, LOCK_EX)) < 0)
	{
		myprint("Err : func flock()");
		assert(0);
	}

	if((lseek(fd, threadWorkHandle[index].writeInitPosition + position, SEEK_SET)) == -1)
	{
		myprint("Err : func lseek()");
		assert(0);
	}

	if((write(fd, srcContent, Lenth)) < 0)
	{		
		myprint("Err : func write()");
		assert(0);
	}

	if((flock(fd, LOCK_UN)) < 0)
	{
		myprint("Err : func flock()");
		assert(0);
	}


}


void write_file_fp(FILE* fp, char *srcContent, int Lenth, int position, int index)
{
	int nwrite = 0, len = 0;
	pthread_mutex_lock(&g_muetx_lock);

	printf("---------- 1 -----------\n");
	if((fseek(fp, threadWorkHandle[index].writeInitPosition + position, SEEK_SET)) == -1)
	{
		myprint("Err : func lseek()");
		assert(0);
	}
	while(nwrite < Lenth)
	{
		printf("---------- 2 -----------\n");
		if((len = fwrite( srcContent + nwrite, 1, Lenth - nwrite, fp)) < 0)
		{		
			myprint("Err : func fwrite()");
			assert(0);
		}		
		nwrite += len;
	}
	printf("nwrite : %d \n", nwrite);
	fflush(fp);

	pthread_mutex_unlock(&g_muetx_lock);


}


void decry_process(void *arg)
{
    int  index = (int)arg;
    char pRsa[256] = { 0 };	
    int	 nread = 0, nwrite = 0;
	int  cacheSize = 0, position = 0;
    int  nworkSize = 0;
   // int  deDataLenth = 0;
    char srcContent[DECRYMAXSIZE] = { 0 };
	FILE *srcFp = NULL, *decryFp = NULL;
	char *tmp = g_cache_memory[index];
	int  begin, end;			  //定义时间开始和结束标志位  ;
	begin=clock();//开始计时
	int fd = 0;
    memcpy(pRsa, g_pRsa, RSA_size(g_pRsa));

    printf("\nthread 0x%x working on, decrySize : %d, rsaSize : %d, index : %d\n",(unsigned int)pthread_self(), 
    		threadWorkHandle[index].encrySize, RSA_size((RSA*)pRsa), index);


    //1. open The file
    if((srcFp = fopen(threadWorkHandle[index].srcFile, "rb")) < 0)
    {
        myprint("Err : thread 0x%x working	func fopen()", (unsigned int)pthread_self());
        goto End;
    }
#if 0
    if((decryFp = fopen(threadWorkHandle[index].encryFile, "ab")) < 0)
    {
        myprint("Err : thread 0x%x working	func fopen()", (unsigned int)pthread_self());
        goto End;
    }
#endif
#if 0
	if((fd = open(threadWorkHandle[index].encryFile,  O_WRONLY | O_APPEND | O_CREAT, 0777 )) < 0)
	{
		myprint("Err : thread 0x%x working	func fopen()", (unsigned int)pthread_self());
		goto End;
	}
#endif

    //2. move file descriptor
    if((fseek(srcFp, threadWorkHandle[index].readInitPosition, SEEK_SET)) == -1)
    {
        myprint("Err : thread 0x%x working	func fseek()", (unsigned int)pthread_self());
        goto End;
    }
	myprint("readInitPosition : %d, writeInitPosition : %d ", threadWorkHandle[index].readInitPosition, threadWorkHandle[index].writeInitPosition);

    //3. encrypt Data from file; once 245 BYTE
    while(nworkSize < threadWorkHandle[index].encrySize)
    {
        if((nread = fread(srcContent, 1, sizeof(srcContent) , srcFp)) < 0)				assert(0);
		memcpy(tmp + cacheSize, srcContent, nread);
		cacheSize += nread;
		position += cacheSize;
		if(cacheSize == CACHEDECRYSIZE)		
		{
			write_file(g_fd, g_cache_memory[index], cacheSize, position, index);
			cacheSize = 0;
		}							    
        memset(srcContent, 0, DECRYMAXSIZE);   
        nworkSize += nread;
    }
	printf("\n\n");
	myprint("cacheSize : %d",cacheSize);
	if(cacheSize <= CACHEDECRYSIZE)
		write_file(g_fd, g_cache_memory[index], cacheSize, position, index);

	sem_post(&g_sem_notify_task_complete);
	end=clock();//结束计时	
	printf("The operation time : %d\n", end-begin);//差为时间，单位毫秒  

	
End:
    if(srcFp)   	fclose(srcFp);
    if(decryFp)		
    {      
        fclose(decryFp);
    }	
	if(fd > 0)		close(fd);
	
    return;
}


#if 1
void decry_process_decry(void *arg)
{
    int  index = (int)arg;
    char pRsa[256] = { 0 };	
    int	 nread = 0, nwrite = 0;
    int  nworkSize = 0;
    int  deDataLenth = 0;
    char srcContent[DECRYMAXSIZE] = { 0 };
    char decryptData[DECRYMAXSIZE] = { 0 };
	FILE *srcFp = NULL, *decryFp = NULL;
	int  begin, end;			  //定义时间开始和结束标志位  ;
	begin=clock();//开始计时

    memcpy(pRsa, g_pRsa, RSA_size(g_pRsa));

    printf("\nthread 0x%x working on, decrySize : %d, rsaSize : %d, index : %d\n",(unsigned int)pthread_self(), 
    		threadWorkHandle[index].encrySize, RSA_size((RSA*)pRsa), index);


    //1. open The file
    if((srcFp = fopen(threadWorkHandle[index].srcFile, "rb")) < 0)
    {
        myprint("Err : thread 0x%x working	func fopen()", (unsigned int)pthread_self());
        goto End;
    }
    if((decryFp = fopen(threadWorkHandle[index].encryFile, "ab+")) < 0)
    {
        myprint("Err : thread 0x%x working	func fopen()", (unsigned int)pthread_self());
        goto End;
    }

    //2. move file descriptor
    if((fseek(srcFp, threadWorkHandle[index].readInitPosition, SEEK_SET)) == -1)
    {
        myprint("Err : thread 0x%x working	func fseek()", (unsigned int)pthread_self());
        goto End;
    }
    if((fseek(decryFp, threadWorkHandle[index].writeInitPosition, SEEK_SET)) == -1)
    {
        myprint("Err : thread 0x%x working	func fseek()", (unsigned int)pthread_self());
        goto End;
    }

	myprint("readInitPosition : %d, writeInitPosition : %d ", threadWorkHandle[index].readInitPosition, threadWorkHandle[index].writeInitPosition);

    //6. encrypt Data from file; once 245 BYTE
    while(nworkSize < threadWorkHandle[index].encrySize)
    {
        if((nread = fread(srcContent, 1, sizeof(srcContent) , srcFp)) < 0)						assert(0);	
        if((deDataLenth = decry_data(srcContent, DECRYMAXSIZE, decryptData, (RSA*)pRsa)) < 0)					assert(0);  
		myprint("deDataLenth : %d", deDataLenth);
		if((nwrite = fwrite(decryptData, 1, deDataLenth, decryFp)) < 0)							assert(0);    
        memset(srcContent, 0, DECRYMAXSIZE);   
        memset(decryptData, 0, DECRYMAXSIZE);
        nworkSize += nread;
    }

	sem_post(&g_sem_notify_task_complete);
	end=clock();//结束计时	
	printf("The operation time : %d\n", end-begin);//差为时间，单位毫秒  

	
End:
    if(srcFp)   	fclose(srcFp);
    if(srcFp)		
    {
        //fflush(decryFp);
        fclose(decryFp);
    }	
    return;
}
#endif



void encry_process(void *arg)
{
    encryHandle_t *handle = (encryHandle_t *)arg;
    FILE *srcFp = NULL, *desFp = NULL;
    //RSA *pRsa = (RSA *)handle->pRsa;

    printf("thread 0x%x working on \n ",(unsigned int)pthread_self());

    //1. open The file
    if((srcFp = fopen(handle->srcFile, "rb")) < 0)
    {
        myprint("Err : thread 0x%x working  func fopen()", (unsigned int)pthread_self());
        goto End;
    }
    if((desFp = fopen(handle->encryFile, "ab+")) < 0)
    {
        myprint("Err : thread 0x%x working  func fopen()", (unsigned int)pthread_self());
        goto End;
    }

    // int fseek(FILE * stream, long offset, int fromwhere);
    //2. move file descriptor
    if((fseek(srcFp, handle->readInitPosition, SEEK_SET)) == -1)
    {
        myprint("Err : thread 0x%x working	func fseek()", (unsigned int)pthread_self());
        goto End;
    }
    if((fseek(desFp, handle->readInitPosition, SEEK_SET)) == -1)
    {
        myprint("Err : thread 0x%x working	func fseek()", (unsigned int)pthread_self());
        goto End;
    }


End:

    if(desFp)
    {
        fflush(desFp);
        fclose(desFp);
    }
    if(srcFp)		fclose(desFp);
}



threadpool_t *init()
{
    threadpool_t *pool = NULL;
	int i = 0;
	
    //1. init The threadPool
    if((pool = threadpool_create(LIVETHRM, LIVETHRM + 10, LIVETHRM)) == NULL)
        myprint("Err : func threadpool_create()");	

    //2. init The global varibal
    if((threadWorkHandle = malloc(sizeof(encryHandle_t) * LIVETHRM)) == NULL)
    {
        myprint("Err : func malloc()");	
        threadpool_destroy(pool);
        pool = NULL;
    }
	memset(threadWorkHandle, 0, sizeof(encryHandle_t) * LIVETHRM);

	g_cache_memory = malloc(sizeof(char *) * LIVETHRM);
	for(i = 0; i < LIVETHRM; i++)
	{
		g_cache_memory[i] = malloc(sizeof(char) * CACHEDECRYSIZE);
	}
	
	sem_init(&g_sem_notify_task_complete, 0, 0);
    

    return pool;	
}	

int destroy(threadpool_t *pool )
{
	int i = 0;
    threadpool_destroy(pool);
    free(threadWorkHandle);
	pthread_mutex_destroy(&g_muetx_lock);

	for(i = 0; i < LIVETHRM; i++)	
		free(g_cache_memory[i]);
	free(g_cache_memory);
	
    return 0;
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
        *size = resiFileSize - baseSize * ret;
End:

    return ret;
}


//组装 解密文件名
void package_decry_file_name(char *filePath, char *decFileName)
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


int test_pthread_mutex_Num()
{
    int ret = 0;
    ret = CRYPTO_num_locks();
    return ret;

}
