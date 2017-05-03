#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>

#include "encryptData.h"

#define PRIVATEKEY 	"client-key.pem"
#define PUBLICKEY 	"client-cert.pem"

char* my_encrypt(char *str, int lenth, char *publicPathKey)
{
	char *pEnData = NULL;
	RSA  *pRsa = NULL;
	FILE *fpKey = NULL;
	
	
	
	return NULL;
}


char* my_decrypt(char *str, int lenth, char *privatePathKey)
{
	
	return NULL;
}