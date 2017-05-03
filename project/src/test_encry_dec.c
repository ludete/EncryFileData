#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include "encryptData.h"

int main()
{
	int ret = 0;
	char* str = NULL;
	
	my_encrypt(str, 0, NULL);
	
	my_decrypt(str, 0, NULL);
	
	myprint("hello world");
	
	return ret;
}