#ifndef MYADDDLL_H
#define MYADDDLL_H

#include <QLibrary>


typedef struct _retval_t_{

    int retval;
    char reason[1024];

}retval_t;

typedef void*(func)(char*);
class myAddDll
{
public:    
    myAddDll();    
    ~myAddDll();


public:
    typedef retval_t (*create_private_public_key)(char *publicKey, char *privateKey);
    typedef retval_t (*decryptFile)(char *filePath, char *privatePathKey, char *decFileName);
    typedef retval_t (*encryptFile_RSA)(char *filePath, char *publicKey, char *encryFileName, int encryType);
    typedef retval_t (*encryptFile_RSA_AES)(char *file, char *passWdSrc, char *publicPathKey, char *encryFile, int encryType);

public:
    QLibrary encryHandle;
    QLibrary sslHandle;
    QLibrary cryptHandle;
};

#endif // MYADDDLL_H
