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
	//1. 原始数据, 16个1
    unsigned char buf[16];
    memset(buf,1,sizeof(buf));

    unsigned char buf2[16];
    unsigned char buf3[16];

    //2. 测试用的key是全零, 即指定的 对称秘钥
    unsigned char aes_keybuf[32];
    memset(aes_keybuf,0,sizeof(aes_keybuf));

   	//3. 将指定的秘钥字符串 转换成 OpenSSL加密秘钥格式
    AES_KEY aeskey;
	AES_KEY desAeskey;
    AES_set_encrypt_key(aes_keybuf, 256, &aeskey);

	//4. AES加密数据
    AES_encrypt(buf, buf2, &aeskey);

	//5. 将指定秘钥字符串 转换成 OpenSSL解密秘钥格式
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
   
    // set the encryption length  
    len = 0;  
    if ((strlen(argv[1]) + 1) % AES_BLOCK_SIZE == 0) {  
        len = strlen(argv[1]) + 1;  
    } else {  
        len = ((strlen(argv[1]) + 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;  
    }  
   
    // set the input string  
    input_string = (unsigned char*)calloc(len, sizeof(unsigned char));  
    if (input_string == NULL) {  
        fprintf(stderr, "Unable to allocate memory for input_string\n");  
        exit(-1);  
    }  
    strncpy((char*)input_string, argv[1], strlen(argv[1]));  
   
    // Generate AES 128-bit key  
    for (i=0; i<16; ++i) {  
        key[i] = 32 + i;  
    }  
   
    // Set encryption key  
    for (i=0; i<AES_BLOCK_SIZE; ++i) {  
        iv[i] = 0;  
    }
	
    if (AES_set_encrypt_key(key, 128, &aes) < 0) {  
        fprintf(stderr, "Unable to set encryption key in AES\n");  
        exit(-1);  
    }  
   
    // alloc encrypt_string  
    encrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));      
    if (encrypt_string == NULL) {  
        fprintf(stderr, "Unable to allocate memory for encrypt_string\n");  
        exit(-1);  
    }  
   
    // encrypt (iv will change)  
    AES_cbc_encrypt(input_string, encrypt_string, len, &aes, iv, AES_ENCRYPT);  
   
    // alloc decrypt_string  
    decrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));  
    if (decrypt_string == NULL) {  
        fprintf(stderr, "Unable to allocate memory for decrypt_string\n");  
        exit(-1);  
    }  
   
    // Set decryption key  
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

	test_aes_encry();

    return 0;  
} 

