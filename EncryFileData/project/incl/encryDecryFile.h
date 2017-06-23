#ifndef _ENCRY_DECRY_FILE_H_
#define _ENCRY_DECRY_FILE_H_


#ifdef __cplusplus
extern "C" {
#endif

//The func Return value
typedef struct _retval_{

	int retval;            //retval
	char reason[1024];     //retval`s reason; success is all '\0', else have reason

}retval_t;

#define FILENAMELENTH  1024


/*encry file in RSA in single thread
*@param : filePath    		The file will be encry
*@param : publicKey   		publicKey or publicCertKey absolutely path
*@param : encryFileName 	encry File Name
*@param : encryType   		0 publicKey, 1 publicCertKey;
*/
retval_t encryptFile(char *filePath, char *publicKey, char *encryFileName, int encryType);

/*decry file in RSA in single thread
*@param : filePath    		The file will be encry
*@param : privatePathKey   	privatePathKey absolutely path 
*@param : decFileName 		decry File Name
*/
retval_t decryptFile(char *filePath, char *privatePathKey, char *decFileName);

/*encry file in RSA_AES in single thread
*@param : filePath    		The file will be encry
*@param : privatePathKey   	publicKey or publicCertKey absolutely path
*@param : decFileName 		decry File Name
*/
retval_t mix_RSA_AES_encryFile(char *file, char *passWdSrc, char *publicPathKey, char *encryFile, int encryType);

/*decry file in RSA_AES in single thread
*@param : file    			The file will be decry
*@param : privatePathKey   	privatePathKey absolutely path
*@param : decFileName 		decry File Name
*/
retval_t mix_RSA_AES_decryFile(char *file, char *privatePathKey, char *decryFile);


/*create The private Key
*@param : fileName   private key absolute path
*/
retval_t create_private_public_key(char *publicKey, char *privateKey);

/*
*@param : srcFilePath   encryFile absolute path
*@param : dstFilePath   decryFile absolute path
*@param : privateKey    private key absolute path
*/
retval_t decryDirAllFile(char *srcFilePath, char *dstFilePath, char *privateKey);

/*
*@param : srcFilePath   srcFile absolute path
*@param : dstFilePath   encryFile absolute path
*@param : publicKey     public key absolute path
*@param : encryType   	0 publicKey, 1 publicCertKey;
*/
retval_t encryDirAllFile(char *srcFilePath, char *dstFilePath, char *publicKey, int encryType);


#ifdef __cplusplus
}
#endif

#endif

