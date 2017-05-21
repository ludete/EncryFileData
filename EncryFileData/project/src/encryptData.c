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

#include "encryptData.h"
#include "include_sub_function.h"
#include "thread_pool.h"
#include <openssl/aes.h>

#define ENCRYFLAG  "_ENCRYPT"
#define DECRYFLAG  "_DECRYPT"
#define MUTILENCYR "_ENCRYPT_RSA_AES"
#define MUTILDECYR "_DECRYPT_RSA_AES"
#define ENCRYMAXSIZE  245
#define DECRYMAXSIZE  256
#define LIVETHRM    10
#define CACHEDECRYSIZE 1024 * 1225

encryHandle_t	*g_threadWorkHandle = NULL;	
RSA  *g_pRsa = NULL;
sem_t  g_sem_notify_task_complete;
char **g_cache_memory = NULL;
pthread_mutex_t g_muetx_writeLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_muetx_readLock = PTHREAD_MUTEX_INITIALIZER;

char *g_decryFile = NULL;
char *g_srcFile = NULL;

int g_fd = 0;

struct _encry_handle{

    char 		srcFile[FILENAMELENTH];			//ԭʼ�ļ��ľ���·��
    char 		encryFile[FILENAMELENTH];		//���ܺ��ļ��ֶ�·��
    uint32_t	encrySize;						//�̼߳������ݵ��ֽ�
    uint32_t    readInitPosition;				//��ȡ�ļ�����ʼλ��
    uint32_t	writeInitPosition;				//д�ļ�����ʼλ��
    char		pRsa[256];						//��Կ
    char 		*mapSrcFileAddr;				//ԭʼ�ļ�ӳ���ַ
	char 		*mapDstFileAddr;				//Ŀ���ļ�ӳ���ַ

};


//��Կ������Ϣ
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


//֤�������Ϣ
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


//������Ϣ
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


//�����ļ�
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

//�����ļ�
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
 


void dealwith_per_threadWork(RSA *pRsa, char *mapSrcaddr, char *mapDstaddr, int threadNum,
							int beforeSize, int behindSize, int writeBase, int perRound)
{
	int i = 0;

	for(i = 0; i < threadNum; i++)
	{
		memcpy(g_threadWorkHandle[i].encryFile, g_decryFile, strlen(g_decryFile));
		memcpy(g_threadWorkHandle[i].srcFile, g_srcFile, strlen(g_srcFile));
		g_threadWorkHandle[i].encrySize = beforeSize;
		g_threadWorkHandle[i].mapDstFileAddr = mapDstaddr;
		g_threadWorkHandle[i].mapSrcFileAddr = mapSrcaddr;
		memcpy(g_threadWorkHandle[i].pRsa, pRsa, RSA_size(pRsa));
		g_threadWorkHandle[i].readInitPosition = beforeSize * i;
		g_threadWorkHandle[i].writeInitPosition = writeBase * perRound * i;
	}

	if(behindSize > 0)		g_threadWorkHandle[threadNum - 1].encrySize = behindSize;
	
}



int multiDecryFile(char *filePath, char *privatePathKey, threadpool_t *pool)
{
	int ret = 0;
  	int threadNum = 0;			  		//�����ļ���Ҫ���߳�����
  	int perRoundNum = 0;			  	//ÿ���߳���͵Ĺ����ִ�
  	int beforeSize = 0;					//ǰ�������̹߳�����С
  	int behindSize = 0;					//���һ���̹߳�����С
  	int srcFileSize = 0;				//ԭʼ�ļ���С
 	RSA *pRsa = NULL; 			  		//��Կ��Ϣ
 	char *mp_src = NULL, *mp_dst = NULL;//�����ļ�ӳ�������̵ĵ�ַ	
 	int fd_src = 0, fd_dst = 0;			//�����ļ�������
 	char decryFileName[FILENAMELENTH] = { 0 };
	int modSize = 0;					//ʣ���ļ���С
	int i = 0;
	
	//1. jurge The file is exsit
	if(!filePath || !privatePathKey)
	{
		myprint("Err : filePath : %p, privatePathKey : %p", filePath, privatePathKey); 
		ret = -1;
		goto End;  
	}  
	if(!if_file_exist(filePath))
	{
		myprint("Err : func if_file_exist(), filePath : %s", filePath); 
		ret = -1;
		goto End;
	}

	//2. caculate The element
	if((ret = get_workSize_thread(filePath, DECRYMAXSIZE, LIVETHRM, &threadNum, &beforeSize, &behindSize, &perRoundNum, &modSize)) < 0)
	{
		myprint("Err : func get_workSize_thread()"); 
		ret = -1;
		goto End;
	}

	//3.get The encryFileName and rsa provate Key
	package_decry_file_name(filePath, decryFileName);
    if((ret = get_privateKey_new(&pRsa, privatePathKey)) < 0)
    {
        myprint("Err : func get_privateKey_new() "); 	  
        goto End;  
    }

	//4.
	if((srcFileSize = get_file_size(filePath)) < 0)
	{
		myprint("Err : func get_file_size() ");	 
		goto End;
	}
	if((fd_src = open(filePath, O_RDONLY)) < 0)
	{
		myprint("Err : func open(), FileName : %s ", filePath);  
		goto End;
	}
	if((fd_dst = open(decryFileName, O_RDWR | O_CREAT | O_TRUNC, 0666)) < 0)
	{
		myprint("Err : func open(), FileName : %s ", decryFileName );	
		goto End;
	}
	if((ret = ftruncate(fd_dst, srcFileSize)) < 0)
	{
		myprint("Err : func ftruncate(), FileName " );	
		goto End;
	}

	if((mp_src = (char *)mmap(NULL, srcFileSize, PROT_READ, MAP_SHARED, fd_src, 0)) == MAP_FAILED)
	{
		myprint("Err : func mmap(), FileName : %s ", filePath );	
		goto End;
	}
	if((mp_dst = (char *)mmap(NULL, srcFileSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd_dst, 0)) == MAP_FAILED)
	{
		myprint("Err : func mmap(), FileName : %s ", decryFileName );	
		goto End;
	}

	//5.caculate The per_thread working
	dealwith_per_threadWork(pRsa, mp_src, mp_dst, threadNum, beforeSize, behindSize, ENCRYMAXSIZE, perRoundNum);
	printf("\n");
	myprint("mp_src : %p, mp_dst : %p",mp_src,mp_dst);
	printf("\n");
	//6. add task to per_Thread 
	for(i = 0; i < threadNum; i++)
    {
        threadpool_add(pool, decry_process, (void *)i);
    }

	//7. wait The child working OK
	for(i = 0; i < threadNum; i++)
		sem_wait(&g_sem_notify_task_complete);

End:
	if(pRsa)						RSA_free(g_pRsa); 
	if(fd_dst > 0)					close(fd_dst);
	if(fd_src > 0)					close(fd_src);
	if(mp_dst != MAP_FAILED)		munmap(mp_dst, srcFileSize);
    if(mp_src != MAP_FAILED)		munmap(mp_src, srcFileSize);	


	return ret;
}



#if 1
int multiDecryFile_inFileFp(char *filePath, char *privatePathKey, threadpool_t *pool)
{
    int ret = 0;
    int roundNum = 0; 				//���ļ���Ҫ���ܵ����ִ�
    int threadNum = 0;				//�����ļ���Ҫ���߳�����
    int lowRoundNum = 0;			//ÿ���߳���͵Ĺ����ִ�
    RSA *pRsa = NULL;				//��Կ��Ϣ
    char decryFileName[FILENAMELENTH] = { 0 };
    int i = 0, begin, end;			//����ʱ�俪ʼ�ͽ�����־λ  ;
	char cmdBuf[FILENAMELENTH] = { 0 };
	int  beforeSize = 0, behindSize = 0;
	int perRoundNum = 0,  modSize = 0;


	begin=clock();//��ʼ��ʱ

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

	//2. caculate The element
	if((ret = get_workSize_thread(filePath, DECRYMAXSIZE, LIVETHRM, &threadNum, &beforeSize, &behindSize, &perRoundNum, &modSize)) < 0)
	{
		myprint("Err : func get_workSize_thread()"); 
		ret = -1;
		goto End;
	}


    //3. get The encryFileName and rsa public Key
    package_decry_file_name(filePath, decryFileName);
    if(get_privateKey_new(&pRsa, privatePathKey) < 0)
    {
        myprint("Err : func get_privateKey_new() "); 	  
        goto End;  
    } 
	
	g_srcFile = filePath;
	g_decryFile = decryFileName;

	//4.caculate The per_thread working
	dealwith_per_threadWork(pRsa, NULL, NULL, threadNum, beforeSize, behindSize, ENCRYMAXSIZE, perRoundNum);
	printf("\n");

	if(if_file_exist(decryFileName))
	{
	 	sprintf(cmdBuf, "rm %s", decryFileName);
	 	if((ret = pox_system(cmdBuf)) < 0)
	 	{
		 	myprint("Err : func pox_system()");
		 	goto End;
	 	}
	}
	
	
    //5. add working for Thread
    for(i = 0; i < threadNum; i++)
    {
        threadpool_add(pool, decry_process_fp, (void *)i);
    }

	//6. wait The child working OK
	for(i = 0; i < threadNum; i++)
		sem_wait(&g_sem_notify_task_complete);

	if(g_fd > 0)	close(g_fd);		


	//7. caculate Time for program runing 
	end=clock();//������ʱ  
    printf("The operation time : %d\n", end-begin);//��Ϊʱ�䣬��λ����  
End:	

    if(g_pRsa)
	{
		RSA_free(g_pRsa); 
		g_pRsa = NULL;
	}
    return ret;
}
#endif



void decry_process(void *arg)
{
    int  index = (int)arg;
	int  begin, end;			  //����ʱ�俪ʼ�ͽ�����־λ  ;
	int nWorkSize = 0;
	int deDataLenth = 0;
	char decryptData[DECRYMAXSIZE] = { 0 };
	
	begin=clock();//��ʼ��ʱ
 
 
  
	myprint("mapSrcFileAddr : %p, mapDstFileAddr : %p, readInitPosition : %d, writeInitPosition : %d , encrySize : %d", 
		g_threadWorkHandle[index].mapSrcFileAddr, g_threadWorkHandle[index].mapDstFileAddr,
		g_threadWorkHandle[index].readInitPosition, g_threadWorkHandle[index].writeInitPosition,
		g_threadWorkHandle[index].encrySize);

	//1. ���ж�ȡ����������, ��������д���ļ�ӳ����
    while(nWorkSize < g_threadWorkHandle[index].encrySize)
    {
        if((deDataLenth = decry_data(g_threadWorkHandle[index].mapSrcFileAddr + g_threadWorkHandle[index].readInitPosition,
			DECRYMAXSIZE, decryptData, (RSA *)(g_threadWorkHandle[index].pRsa))) < 0)					
			assert(0);  
		g_threadWorkHandle[index].readInitPosition += DECRYMAXSIZE;		
		memcpy(g_threadWorkHandle[index].mapDstFileAddr + g_threadWorkHandle[index].writeInitPosition,
			decryptData, deDataLenth);
		g_threadWorkHandle[index].writeInitPosition += deDataLenth;
 
        memset(decryptData, 0, DECRYMAXSIZE);
        nWorkSize += DECRYMAXSIZE;
    }

	//2.֪ͨ���̸߳��̹߳������������	
	sem_post(&g_sem_notify_task_complete);
	end=clock();//������ʱ	
	printf("The operation time : %d\n", end-begin);//��Ϊʱ�䣬��λ����  

	
    return;
}



void decry_process_OK_copyFile(void *arg)
{
    int  index = (int)arg;
	int  begin, end;			  //����ʱ�俪ʼ�ͽ�����־λ  ;
	begin=clock();//��ʼ��ʱ
 
 
    //2. move file descriptor And read data to cache memory
	myprint("mapSrcFileAddr : %p, mapDstFileAddr : %p, readInitPosition : %d, writeInitPosition : %d , encrySize : %d", 
		g_threadWorkHandle[index].mapSrcFileAddr, g_threadWorkHandle[index].mapDstFileAddr,
		g_threadWorkHandle[index].readInitPosition, g_threadWorkHandle[index].writeInitPosition,
		g_threadWorkHandle[index].encrySize);

	myprint("============= 1 ===============");
	memcpy(g_threadWorkHandle[index].mapDstFileAddr + g_threadWorkHandle[index].writeInitPosition,
			g_threadWorkHandle[index].mapSrcFileAddr + g_threadWorkHandle[index].readInitPosition,
			g_threadWorkHandle[index].encrySize); 
	myprint("============= 2 ===============");	
	
	sem_post(&g_sem_notify_task_complete);
	end=clock();//������ʱ	
	printf("The operation time : %d\n", end-begin);//��Ϊʱ�䣬��λ����  

	
    return;
}

void write_file(FILE* fp, char *srcContent, int Lenth, int index)
{
	int nwrite = 0, len = 0;
	pthread_mutex_lock(&g_muetx_writeLock);

	printf("---------- 1 -----------\n");
	
	if((fseek(fp, g_threadWorkHandle[index].writeInitPosition , SEEK_SET)) == -1)
	{
		myprint("Err : func lseek()");
		assert(0);
	}
	myprint("pthread : %d, The write begin current : %lu, fp : %p", index, ftell(fp), fp);

	while(nwrite < Lenth)
	{
		
		if((len = fwrite( srcContent + nwrite, 1, Lenth - nwrite, fp)) < 0)
		{		
			myprint("Err : func fwrite()");
			assert(0);
		}		
		nwrite += len;
	}

	myprint("pthread : %d, The write end  : %lu, nwrite : %d", index, ftell(fp), nwrite);
	g_threadWorkHandle[index].writeInitPosition += Lenth;
	fflush(fp);
	printf("---------- 2 -----------\n");

	pthread_mutex_unlock(&g_muetx_writeLock);


}



#if 1
void decry_process_fp(void *arg)
{
    int  index = (int)arg;
    int	 nread = 0, readLen = 0;
	int  nWorkSize = 0, totalLenth = 0;
	FILE *srcFp = NULL, *decryFp = NULL;
	int  begin, end;			  //����ʱ�俪ʼ�ͽ�����־λ  ;
	int deDataLenth = 0;
	
	begin=clock();//��ʼ��ʱ


    //1. open The file
    if((srcFp = fopen(g_threadWorkHandle[index].srcFile, "rb")) < 0)
    {
        myprint("Err : thread 0x%x working	func fopen()", (unsigned int)pthread_self());
        goto End;
    }
#if 1
    if((decryFp = fopen(g_threadWorkHandle[index].encryFile, "wb")) < 0)
    {
        myprint("Err : thread 0x%x working	func fopen()", (unsigned int)pthread_self());
        goto End;
    }
#endif

   
	myprint("readInitPosition : %d, writeInitPosition : %d ", g_threadWorkHandle[index].readInitPosition, g_threadWorkHandle[index].writeInitPosition);


	while(totalLenth < g_threadWorkHandle[index].encrySize)
	{
		//2. �ƶ��ļ�������, ����ԭʼ�ļ����ݶ�����һ��������
		pthread_mutex_lock(&g_muetx_readLock);
	    if((fseek(srcFp, g_threadWorkHandle[index].readInitPosition, SEEK_SET)) == -1)
	    {
	        myprint("Err : thread 0x%x working	func fseek()", (unsigned int)pthread_self());
	        goto End;
	    }
		myprint("pthread : %d, The read begin position : %lu ", index, ftell(srcFp));
		//2. ��ȡ�����������߳� ��������
		if(CACHEDECRYSIZE > g_threadWorkHandle[index].encrySize)
		{
			nWorkSize = g_threadWorkHandle[index].encrySize;					
		}
		else
		{
			nWorkSize = CACHEDECRYSIZE;						
		}
		while(readLen < nWorkSize)
		{		
			if((nread = fread(g_cache_memory[2 * index + 1] + readLen, 1, nWorkSize - readLen , srcFp)) < 0)			
			{
				myprint("Err : func fread()");
				assert(0);
			}		
			readLen += nread;
		}
		totalLenth += nWorkSize;
		g_threadWorkHandle[index].readInitPosition += nWorkSize;
		pthread_mutex_unlock(&g_muetx_readLock);

		
		//3.�Զ������������ݽ��н���/����, �������������д��дĿ���ļ�
		
	    if((deDataLenth = decry_data(g_cache_memory[2 * index + 1] + g_threadWorkHandle[index].readInitPosition,
		DECRYMAXSIZE, decryptData, (RSA *)(g_threadWorkHandle[index].pRsa))) < 0)					
		assert(0); 
		memcpy( g_cache_memory[2 * index], g_cache_memory[2 * index + 1], nWorkSize);
		write_file(decryFp, g_cache_memory[2 * index], nWorkSize, index);
			
	}
	
	

	
		
	

	sem_post(&g_sem_notify_task_complete);
	end=clock();//������ʱ	
	printf("The operation time : %d\n", end-begin);//��Ϊʱ�䣬��λ����  

	
End:
    if(srcFp)   	fclose(srcFp);
    if(decryFp)		
    {      
        fclose(decryFp);
    }	
	if(fd > 0)		close(fd);
	
    return;
}
#endif



#if 0
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
	int  begin, end;			  //����ʱ�俪ʼ�ͽ�����־λ  ;
	begin=clock();//��ʼ��ʱ

    memcpy(pRsa, g_pRsa, RSA_size(g_pRsa));

    //1. open The file
    if((srcFp = fopen(g_threadWorkHandle[index].srcFile, "rb")) < 0)
    {
        myprint("Err : thread 0x%x working	func fopen()", (unsigned int)pthread_self());
        goto End;
    }
    if((decryFp = fopen(g_threadWorkHandle[index].encryFile, "ab+")) < 0)
    {
        myprint("Err : thread 0x%x working	func fopen()", (unsigned int)pthread_self());
        goto End;
    }

    //2. move file descriptor
    if((fseek(srcFp, g_threadWorkHandle[index].readInitPosition, SEEK_SET)) == -1)
    {
        myprint("Err : thread 0x%x working	func fseek()", (unsigned int)pthread_self());
        goto End;
    }
    if((fseek(decryFp, g_threadWorkHandle[index].writeInitPosition, SEEK_SET)) == -1)
    {
        myprint("Err : thread 0x%x working	func fseek()", (unsigned int)pthread_self());
        goto End;
    }

	myprint("readInitPosition : %d, writeInitPosition : %d ", g_threadWorkHandle[index].readInitPosition, g_threadWorkHandle[index].writeInitPosition);

    //6. encrypt Data from file; once 245 BYTE
    while(nworkSize < g_threadWorkHandle[index].encrySize)
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
	end=clock();//������ʱ	
	printf("The operation time : %d\n", end-begin);//��Ϊʱ�䣬��λ����  

	
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




threadpool_t *init()
{
    threadpool_t *pool = NULL;
	int i = 0;
	
    //1. init The threadPool
    if((pool = threadpool_create(LIVETHRM, LIVETHRM + 10, LIVETHRM)) == NULL)
        myprint("Err : func threadpool_create()");	

    //2. init The global varibal
    if((g_threadWorkHandle = malloc(sizeof(encryHandle_t) * LIVETHRM)) == NULL)
    {
        myprint("Err : func malloc()");	
        threadpool_destroy(pool);
        pool = NULL;
    }
	memset(g_threadWorkHandle, 0, sizeof(encryHandle_t) * LIVETHRM);

	g_cache_memory = malloc(sizeof(char *) * LIVETHRM * 2);
	for(i = 0; i < LIVETHRM * 2; i++)
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
    free(g_threadWorkHandle);
	pthread_mutex_destroy(&g_muetx_writeLock);
	pthread_mutex_destroy(&g_muetx_readLock);

	for(i = 0; i < LIVETHRM * 2; i++)	
		free(g_cache_memory[i]);
	free(g_cache_memory);
	
	
    return 0;
}


int get_residueSize_needThreadNum(char *filePath, int threadNum, int lowRoundNum, int baseSize, int *size)
{
    int ret = 0;	
    int fileSize = 0;		//�ļ���С
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


//��װ �����ļ���
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



//��װ �����ļ���
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


int test_pthread_mutex_Num()
{
    int ret = 0;
    ret = CRYPTO_num_locks();
    return ret;

}




int encry_file_AES(char *file, char *passWdSrc)
{
	int ret = 0;
	AES_KEY aes_key;				//OpenSSL��ʽ����Կ
	char encryName[FILENAMELENTH] = { 0 }, cmdBuf[FILENAMELENTH] = { 0 };
	FILE *srcFp = NULL, *decryFp = NULL;
	char srcData[AES_BLOCK_SIZE] = { 0 }, outData[AES_BLOCK_SIZE] = { 0 };
	int nread = 0, passLen = 0;
	char passwd[33] = { 0 };

	
	if(!file || !passWdSrc)
	{
		myprint("Err : file : %p, passwd : %p", file, passWdSrc);
		return ret = -1;
	}

	//0. �ж�ԭʼ�ļ��Ƿ����
	if(!if_file_exist(file))
	{
		myprint("Err : file : %s is not exist", file); 
		ret = -1;
		goto End;
	}

	//1. �����û���Կ������(�������Ϊ32�ֽ�), 16, 24, 32�ֽ�
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
		myprint("Err : The passwd Lenth is too large %d > 32", strlen(passwd)); 
		ret = -1;
		goto End;
	}
		
	
	//2.ƴװ���ܺ���ļ���
	package_encry_file_name(file, encryName);
	myprint("encFileName : %s", encryName);
	printf("----------- 1 -------------\n");
	if(if_file_exist(encryName))
	{
		sprintf(cmdBuf, "rm %s", encryName);
		if((ret = pox_system(cmdBuf)) < 0)
		{
			myprint("Err : func pox_system()");
			goto End;
		}
	}

	//5. ������ܵ��ܳ���, ����OpenSSL��ʽ����Կ
    if(AES_set_encrypt_key((const unsigned char*)passwd, passLen * 8, &aes_key) < 0)
    {
        myprint("Err : func AES_set_encrypt_key(),fileName : %s",file); 
		ret = -1;
		goto End;
		assert(0);
    }

	//6. open The file
    if((srcFp = fopen(file, "rb")) == NULL)
	{
		myprint("Err : func fopen(),fileName : %s",file); 
		ret = -1;
		goto End;
		assert(0);
	}  	
	if((decryFp = fopen(encryName, "wb")) == NULL)
	{
		myprint("Err : func fopen(), fileName : %s",encryName); 
		ret = -1;
		goto End;
		assert(0);
	} 


	//7.encry file Data	   	   
	while(!feof(srcFp))
	{	
		if((nread = fread(srcData, 1, AES_BLOCK_SIZE, srcFp)) < 0)
		{
			myprint("Err : func fread(), fileName : %s",file); 
			ret = -1;
			goto End;
			assert(0);
		}
   		
		AES_encrypt((unsigned char*)srcData, (unsigned char*)outData, &aes_key);
		
		if((fwrite(outData, 1, nread, decryFp)) < 0)
		{
			myprint("Err : func fwrite()"); 
			ret = -1;
			goto End;
			assert(0);
		}
		memset(outData, 0,AES_BLOCK_SIZE );
		memset(srcData, 0,AES_BLOCK_SIZE );
	}
	
End:

	if(decryFp)			fclose(decryFp);
	if(srcFp)			fclose(srcFp);
	
	return ret;		
}



int decry_file_AES(char *file, char *passWdSrc)
{
	int	ret = 0;
	AES_KEY aes_key;				//OpenSSL��ʽ����Կ	 
	char encryName[FILENAMELENTH] = { 0 }, cmdBuf[FILENAMELENTH] = { 0 };
	FILE *srcFp = NULL, *decryFp = NULL;
	char srcData[AES_BLOCK_SIZE] = { 0 }, outData[AES_BLOCK_SIZE] = { 0 };
	int  nread = 0, passLen = 0;
	char passwd[33] = { 0 };
	
	if(!file || !passWdSrc)
	{
		myprint("Err : file : %p, passwd : %p", file, passWdSrc);
		return ret = -1;
	}

	//0. �ж�ԭʼ�ļ��Ƿ����
	if(!if_file_exist(file))
	{
		myprint("Err : file : %s is not exist", file); 
		ret = -1;
		goto End;
	}

	//1. �����û���Կ������(�������Ϊ32�ֽ�), 16, 24, 32�ֽ�
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
		myprint("Err : The passwd Lenth is too large %d > 32", strlen(passwd)); 
		ret = -1;
		goto End;
	}

	//2.ƴװ���ܺ���ļ���
	package_decry_file_name(file, encryName);
	myprint("decFileName : %s", encryName);
	printf("----------- 1 -------------\n");
	if(if_file_exist(encryName))
	{
		sprintf(cmdBuf, "rm %s", encryName);
		if((ret = pox_system(cmdBuf)) < 0)
		{
			myprint("Err : func pox_system()");
			goto End;
		}
	}
	printf("----------- 2 -------------\n");

	//4.����OpenSSL��ʽ����Կ	
	if(AES_set_decrypt_key((const unsigned char*)passwd, passLen * 8, &aes_key) < 0)
	{
		myprint("Err : func AES_set_encrypt_key(),fileName : %s",file); 
		ret = -1;
		goto End;
		assert(0);
	}

	//6. open The file
    if((srcFp = fopen(file, "rb")) == NULL)
	{
		myprint("Err : func fopen(),fileName : %s",file); 
		ret = -1;
		goto End;
		assert(0);
	}  	
	printf("----------- 6 -------------\n");
	if((decryFp = fopen(encryName, "wb")) == NULL)
	{
		myprint("Err : func fopen(), fileName : %s",encryName); 
		ret = -1;
		goto End;
		assert(0);
	} 
	printf("----------- 7 -------------\n");

	//7.encry file Data	   	   
	while(!feof(srcFp))
	{
		//printf("----------- 71 -------------\n");
		if((nread = fread(srcData, 1, AES_BLOCK_SIZE, srcFp)) < 0)
		{
			myprint("Err : func fread(), fileName : %s",file); 
			ret = -1;
			goto End;
			assert(0);
		}
		AES_decrypt((unsigned char*)srcData, (unsigned char*)outData, &aes_key);
		//printf("----------- 9 -------------\n");
		if((fwrite(outData, 1, nread, decryFp)) < 0)
		{
			myprint("Err : func fwrite()"); 
			ret = -1;
			goto End;
			assert(0);
		}
		memset(outData, 0,AES_BLOCK_SIZE );
		memset(srcData, 0,AES_BLOCK_SIZE );
	}
	
End:

	if(decryFp)			fclose(decryFp);
	if(srcFp)			fclose(srcFp);

	
	return ret;
}


int mix_RSA_AES_encryFile(char *file, char *passWdSrc, char *publicPathKey)
{
	int ret = 0;
	AES_KEY aes_key;				//OpenSSL��ʽ����Կ
	char encryName[FILENAMELENTH] = { 0 }, cmdBuf[FILENAMELENTH] = { 0 };
	FILE *srcFp = NULL, *decryFp = NULL;
	char srcData[AES_BLOCK_SIZE] = { 0 }, outData[AES_BLOCK_SIZE] = { 0 };
	int nread = 0, passLen = 0;
	char passwd[33] = { 0 };
	RSA *pRsa = NULL;
	char enData_RSA[256] = { 0 };

	if(!file || !passWdSrc || !publicPathKey)
	{
		myprint("Err : file : %p, passwd : %p, publicPathKey : %p", file, passWdSrc, publicPathKey);
		return ret = -1;
	}

	//1. �ж�ԭʼ�ļ��Ƿ����
	if(!if_file_exist(file))
	{
		myprint("Err : file : %s is not exist", file); 
		ret = -1;
		goto End;
	}
	
	//2. �����û���Կ������(�������Ϊ32�ֽ�), 16, 24, 32�ֽ�
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
		myprint("Err : The passwd Lenth is too large %d > 32", strlen(passwd)); 
		ret = -1;
		goto End;
	}
				
	//3. get The cert news And encry password data in use RSA style
	if(get_cert_pubKey(&pRsa, publicPathKey) < 0)
	{
		myprint("Err : func get_cert_pubKey()");
		ret = -1;
		goto End;	
	}
	if((ret = encry_data(passwd, passLen, enData_RSA, pRsa)) < 0)
	{
		myprint("Err : func get_cert_pubKey()");
		ret = -1;
		goto End;	
	}

	//4.package The encryFileName And open The file
	package_AES_RSA_encry_file_name(file, encryName);
	myprint("encryName : %s", encryName);
	if(if_file_exist(encryName))
    {
        sprintf(cmdBuf, "rm %s", encryName);
        if((ret = pox_system(cmdBuf)) < 0)
        {
            myprint("Err : func pox_system() cmd : %s", cmdBuf);
            goto End;
        }
    }
	if((srcFp = fopen(file, "rb")) == NULL)
	{
		myprint("Err : func fopen() fileName : %s", file);
		ret = -1;
		goto End;
	}
	if((decryFp = fopen(encryName, "wb")) == NULL)
	{
		myprint("Err : func fopen() fileName : %s", encryName);
		ret = -1;
		goto End;
	}

	//5.write RSA encry data to encryFile
	if((fwrite(enData_RSA, 1, sizeof(enData_RSA), decryFp)) < 0)
	{
		myprint("Err : func fwrite() fileName : %s", encryName);
		ret = -1;
		goto End;
	}


	//6. ������ܵ��ܳ���, ����OpenSSL��ʽ����Կ
    if(AES_set_encrypt_key((const unsigned char*)passwd, passLen * 8, &aes_key) < 0)
    {
        myprint("Err : func AES_set_encrypt_key(),fileName : %s",file); 
		ret = -1;
		goto End;
		assert(0);
    }

	//7.encry file Data	   	   
	while(!feof(srcFp))
	{	
		if((nread = fread(srcData, 1, AES_BLOCK_SIZE, srcFp)) < 0)
		{
			myprint("Err : func fread(), fileName : %s",file); 
			ret = -1;
			goto End;
			assert(0);
		}
   		
		AES_encrypt((unsigned char*)srcData, (unsigned char*)outData, &aes_key);
		
		if((fwrite(outData, 1, nread, decryFp)) < 0)
		{
			myprint("Err : func fwrite()"); 
			ret = -1;
			goto End;
			assert(0);
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


int mix_RSA_AES_decryFile(char *file, char *privatePathKey)
{
	int ret = 0;
	AES_KEY aes_key;				//OpenSSL��ʽ����Կ
	char decryName[FILENAMELENTH] = { 0 }, cmdBuf[FILENAMELENTH] = { 0 };
	FILE *srcFp = NULL, *decryFp = NULL;
	char srcData[AES_BLOCK_SIZE] = { 0 }, outData[AES_BLOCK_SIZE] = { 0 };
	int nread = 0, passLen = 0;
	char passwd[33] = { 0 };
	char encryPassData[256] = { 0 };
	RSA  *pRsa = NULL;

	
	if(!file || !privatePathKey)
	{
		myprint("Err : file : %p, privatePathKey : %p", file, privatePathKey);
		return ret = -1;
	}

	//1. �ж�ԭʼ�ļ��Ƿ����
	if(!if_file_exist(file))
	{
		myprint("Err : file : %s is not exist", file); 
		ret = -1;
		goto End;
	}

	//2. ���ɽ����ļ���,���и��ļ��Ƿ����, ������ɾ��
	package_AES_RSA_decry_file_name(file, decryName);
	myprint("decryName : %s", decryName);
	if(if_file_exist(decryName))
    {
        sprintf(cmdBuf, "rm %s", decryName);
        if((ret = pox_system(cmdBuf)) < 0)
        {
            myprint("Err : func pox_system() cmd : %s", cmdBuf);
            goto End;
        }
    }

	//3.���ļ�
	if((srcFp = fopen(file, "rb")) == NULL)
	{
		myprint("Err : func fopen() fileName : %s", file);
		ret = -1;
		goto End;
	}
	if((decryFp = fopen(decryName, "wb")) == NULL)
	{
		myprint("Err : func fopen() fileName : %s", decryName);
		ret = -1;
		goto End;
	}

	//4.��ȡ˽Կ��Ϣ
	if((get_privateKey_new(&pRsa, privatePathKey)) < 0)
	{
		myprint("Err : func get_privateKey_new() ");
		ret = -1;
		goto End;

	}
	
	//5.read encry password from src File,  ע��: �ǶԳƼ���, ���ܵ����ĳ���Ϊ256(�̶�)
	if((fread(encryPassData, 1, 256, srcFp)) != 256)
	{
		myprint("Err : func fread() fileName : %s", decryName);
		ret = -1;
		goto End;
	}
	if((passLen = decry_data(encryPassData, 256, passwd, pRsa)) < 0)
	{
		myprint("Err : func decry_data() ");
		ret = -1;
		goto End;
	}

	//6. set The Symmetric encryption key
	if(AES_set_decrypt_key((const unsigned char*)passwd, passLen * 8, &aes_key) < 0)
	{
		myprint("Err : func AES_set_encrypt_key(),fileName : %s",file); 
		ret = -1;
		goto End;
		assert(0);
	}

	//7.encry file Data	   	   
	while(!feof(srcFp))
	{
		if((nread = fread(srcData, 1, AES_BLOCK_SIZE, srcFp)) < 0)
		{
			myprint("Err : func fread(), fileName : %s",file); 
			ret = -1;
			goto End;
			assert(0);
		}
		AES_decrypt((unsigned char*)srcData, (unsigned char*)outData, &aes_key);
		if((fwrite(outData, 1, nread, decryFp)) < 0)
		{
			myprint("Err : func fwrite()"); 
			ret = -1;
			goto End;
			assert(0);
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


