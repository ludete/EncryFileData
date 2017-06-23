#include "myAdddll.h"
#include <QMessageBox>


myAddDll::myAddDll()
{
#if 0
    this->encryHandle("libencrydecry.so");
    this->sslHandle("libssl.so.1.1");
    this->cryptHandle("libcrypto.so.1.1");

    if(!this->encryHandle.load())
    {
        QMessageBox::about(this, "Load *.so", "No Find libencrydecry.so");
    }
    if(!this->sslHandle.load())
    {
        QMessageBox::about(this, "Load *.so", "No Find libssl.so.1.1");
    }
    if(!this->cryptHandle.load())
    {
        QMessageBox::about(this, "Load *.so", "No Find libcrypto.so.1.1");
    }

#endif


}

myAddDll::~myAddDll()
{

}

