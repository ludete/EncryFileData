#if 0
#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

#include <openssl/aes.h>

#define myprint( x...) do {char bufMessagePut_Stdout_[1024];\
        sprintf(bufMessagePut_Stdout_, x);\
        fprintf(stdout, "%s [%d], [%s]\n", bufMessagePut_Stdout_,__LINE__, __FILE__ );\
   }while (0)



void *child_func(void *arg)
{
	//pthread_detach(pthread_self());
#if 1

	int fd = 0;
	if((fd = open("hello", O_WRONLY | O_CREAT, 0777)) < 0)
	{
		printf("Err : open(), [%d],[%s]\n", __LINE__, __FILE__);		
	}
	else
	{
		printf("open() OK!!!!\n");
	}
	if(fd > 0)	close(fd);
#endif

#if 0
	FILE *fp = NULL;
	if((fp = fopen("hello", "a+")) == NULL )
	{
		printf("Err : fopen(), [%d],[%s]\n", __LINE__, __FILE__);
	}
	else
	{
		printf("fopen() OK!!!!\n");
	}

	if(fp)	fclose(fp);	
#endif	
	
	pthread_exit(NULL);
}

void test_create_file()
{
    int i =0;
	pthread_t pthid[5];

	for(i =0; i < 5; i++)
	{
		pthread_create(&pthid[i], NULL, child_func, NULL);

	}

	for(i = 0; i < 5; i++)
		pthread_join( pthid[i], NULL);

}

int test_aes_encry()
{
	//1. ԭʼ����, 16��1
    unsigned char buf[16];
    memset(buf,1,sizeof(buf));

    unsigned char buf2[16];
    unsigned char buf3[16];

    //2. �����õ�key��ȫ��, ��ָ���� �Գ���Կ
    unsigned char aes_keybuf[32];
    memset(aes_keybuf,0,sizeof(aes_keybuf));

   	//3. ��ָ������Կ�ַ��� ת���� OpenSSL������Կ��ʽ
    AES_KEY aeskey;
	AES_KEY desAeskey;
    AES_set_encrypt_key(aes_keybuf, 256, &aeskey);

	//4. AES��������
    AES_encrypt(buf, buf2, &aeskey);

	//5. ��ָ����Կ�ַ��� ת���� OpenSSL������Կ��ʽ
    AES_set_decrypt_key(aes_keybuf,256,&desAeskey);
    AES_decrypt(buf2,buf3,&desAeskey);

	//if(memcmp())

   	if(memcmp(buf,buf3,sizeof(buf))==0)
      	printf("test success\r\n");
   	else
      	printf("test fail\r\n");

	myprint("AES_BLOCK_SIZE : %d", AES_BLOCK_SIZE);

	return 0;
}

int test_cbcstyle_func(int argc, char** argv)
{  
    AES_KEY aes;  
    unsigned char key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16  
    unsigned char iv[AES_BLOCK_SIZE];         // init vector  
    unsigned char* input_string;  
    unsigned char* encrypt_string;  
    unsigned char* decrypt_string;  
    unsigned int len;        				 // encrypt length (in multiple of AES_BLOCK_SIZE)  
    unsigned int i;  
   
    // check usage  
    if (argc != 2) {  
        fprintf(stderr, "%s <plain text>\n", argv[0]);  
        exit(-1);  
    }  
   
    // set the encryption length; ��ȡԭʼ���ݳ���  
    len = 0;  
    if ((strlen(argv[1]) + 1) % AES_BLOCK_SIZE == 0) {  
        len = strlen(argv[1]) + 1;  
    } else {  
        len = ((strlen(argv[1]) + 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;  
    }  
   
    // set the input string, �����ڴ�, ����ԭʼ����  
    input_string = (unsigned char*)calloc(len, sizeof(unsigned char));  
    if (input_string == NULL) {  
        fprintf(stderr, "Unable to allocate memory for input_string\n");  
        exit(-1);  
    }  
    strncpy((char*)input_string, argv[1], strlen(argv[1]));  

   
    // Generate AES 128-bit key, ����char* ��Կ����  
    for (i=0; i<16; ++i) {  
        key[i] = 32 + i;  
    }  
   
    // Set encryption key  
    for (i=0; i<AES_BLOCK_SIZE; ++i) {  
        iv[i] = 0;  
    }
	
	//���� OpenSSL ������Կ��ʽ
    if (AES_set_encrypt_key(key, 128, &aes) < 0) {  
        fprintf(stderr, "Unable to set encryption key in AES\n");  
        exit(-1);  
    }  
   
    // alloc encrypt_string, ����������ݵ��ڴ�  
    encrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));      
    if (encrypt_string == NULL) {  
        fprintf(stderr, "Unable to allocate memory for encrypt_string\n");  
        exit(-1);  
    }  
   
    // encrypt (iv will change), ���ݼ���  
    AES_cbc_encrypt(input_string, encrypt_string, len, &aes, iv, AES_ENCRYPT);  
   
    // alloc decrypt_string, ����������ݵ��ڴ�  
    decrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));  
    if (decrypt_string == NULL) {  
        fprintf(stderr, "Unable to allocate memory for decrypt_string\n");  
        exit(-1);  
    }  
   
    // Set decryption key,   
    for (i=0; i<AES_BLOCK_SIZE; ++i) {  
        iv[i] = 0;  
    }  
    if (AES_set_decrypt_key(key, 128, &aes) < 0) {  
        fprintf(stderr, "Unable to set decryption key in AES\n");  
        exit(-1);  
    }  
   
    // decrypt  
    AES_cbc_encrypt(encrypt_string, decrypt_string, len, &aes, iv,   
            AES_DECRYPT);  
   
    // print  
    printf("input_string = %s\n", input_string);  
    printf("encrypted string = ");  
    for (i=0; i<len; ++i) {  
        printf("%x%x", (encrypt_string[i] >> 4) & 0xf,   
                encrypt_string[i] & 0xf);      
    }  
    printf("\n");  
    printf("decrypted string = %s\n", decrypt_string);  
   
    return 0;  
}  




int main(int argc, char* argv[])  
{  

	printf("AES_BLOCK_SIZE : %d\r\n", AES_BLOCK_SIZE);
	//test_aes_encry();
	test_cbcstyle_func(argc, argv);
    return 0;  
} 

#endif




#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h> // linux��ͷ�ļ�
#endif
#define FILE_MAX_SIZE (1024*1024)
/*
��õ�ǰʱ���ַ���
@param buffer [out]: ʱ���ַ���
@return ��
*/
void get_local_time(char* buffer)
{
	time_t rawtime;
	struct tm* timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	sprintf(buffer, "%04d-%02d-%02d %02d:%02d:%02d",
	(timeinfo->tm_year+1900), timeinfo->tm_mon, timeinfo->tm_mday,
	timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
}

/*
����ļ���С
@param filename [in]: �ļ���
@return �ļ���С
*/
long get_file_size(char* filename)
{
	long length = 0;
	FILE *fp = NULL;
	fp = fopen(filename, "rb");
	if (fp != NULL)
	{
		fseek(fp, 0, SEEK_END);
		length = ftell(fp);
	}
	if (fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}
	return length;
}

/*
д����־�ļ�
@param filename [in]: ��־�ļ���
@param max_size [in]: ��־�ļ���С����
@param buffer [in]: ��־����
@param buf_size [in]: ��־���ݴ�С
@return ��
*/
void write_log_file(char* filename,long max_size, char* buffer, unsigned buf_size)
{
if (filename != NULL && buffer != NULL)
{
	// �ļ������������, ɾ��
	long length = get_file_size(filename);
	if (length > max_size)
	{
		unlink(filename); // ɾ���ļ�
	}
	
	// д��־
	{
	FILE *fp;
	fp = fopen(filename, "at+");
	if (fp != NULL)
	{
		char now[32];
		memset(now, 0, sizeof(now));
		get_local_time(now);
		fwrite(now, strlen(now)+1, 1, fp);
		fwrite(buffer, buf_size, 1, fp);
		fclose(fp);
		fp = NULL;
	}
	}
}
}
int main(int argc,char** argv)
{
int i;
for (i=0; i<10; ++i)
{
char buffer[32];
memset(buffer, 0, sizeof(buffer));
sprintf(buffer, "====> %d\n", i);
write_log_file("log.txt", FILE_MAX_SIZE, buffer, strlen(buffer));
#ifdef WIN32
Sleep(100); // ����
#else
sleep(1); // ��
#endif
}
// system("pause");
return 0;
}






