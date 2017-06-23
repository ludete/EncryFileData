#include <iostream>
#include <stdio.h>
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QFileDialog>
#include <QByteArray>
#include <QMessageBox>
#include <QInputDialog>
#include <QString>
#include <QDir>

#include "encryDecryFile.h"
#include "mywidget.h"
#include "ui_mywidget.h"



using namespace std;


MyWidget::MyWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MyWidget)
{
    ui->setupUi(this);


    memset(this->encryFile_pri, 0, FILENAMELENTH);
    memset(this->decryFile_pri, 0, FILENAMELENTH);
    memset(this->publicPath_pri, 0, FILENAMELENTH);
    memset(this->privatePath_pri, 0, FILENAMELENTH);
    this->type_pri = true;
}

MyWidget::~MyWidget()
{
    delete ui;
}

int test_list(QString dirPath);

void MyWidget::on_selectEncryKey_clicked()
{
    QByteArray keyba;
    char *tmp = NULL;

    QString path = QFileDialog::getOpenFileName(this, "open", "../", "PEM(*.pem)");
    if(path.isEmpty() == false)     //find The Encry Key
    {
        keyba = path.toLatin1();
        tmp = keyba.data();

        memset(this->publicPath_pri, 0, FILENAMELENTH);
        memcpy( this->publicPath_pri, tmp, MY_MIN(FILENAMELENTH, strlen(tmp)));
    }
}

void MyWidget::on_selectEncryFile_clicked()
{
    QByteArray keyba;
    char *tmp = NULL;

    QString path = QFileDialog::getOpenFileName(this, "open", "../", "*");
    if(path.isEmpty() == false)     //find The Encry Key
    {
        keyba = path.toLatin1();
        tmp = keyba.data();

        memset(this->encryFile_pri, 0, FILENAMELENTH);
        memcpy( this->encryFile_pri, tmp, MY_MIN(FILENAMELENTH, strlen(tmp)));
        this->type_pri = true;
    }
}

void MyWidget::on_selectDecryKey_clicked()
{
    char *tmp = NULL;
    QByteArray keyba;

    QString path = QFileDialog::getOpenFileName(this, "open", "../", "PEM(*.pem)");
    if(path.isEmpty() == false)     //find The Encry Key
    {
        keyba = path.toLatin1();
        tmp = keyba.data();

        memset(this->privatePath_pri, 0, FILENAMELENTH);
        memcpy( this->privatePath_pri, tmp, MY_MIN(FILENAMELENTH, strlen(tmp)));
    }
}

void MyWidget::on_selectDecryFile_clicked()
{
    char *tmp = NULL;
    QByteArray keyba;

    QString path = QFileDialog::getOpenFileName(this, "open", "../", "*");
    if(path.isEmpty() == false)     //find The Encry Key
    {
        keyba = path.toLatin1();
        tmp = keyba.data();

        memset(this->decryFile_pri, 0, FILENAMELENTH);
        memcpy( this->decryFile_pri, tmp, MY_MIN(FILENAMELENTH, strlen(tmp)));
        this->type_pri = true;
    }
}

bool MyWidget::isDirExist(QString fullPath)
{
    QDir dir(fullPath);
    if(dir.exists())
    {
      return true;
    }
    return false;
}

bool MyWidget::createDir(QString dirPath)
{
    QDir dir(dirPath);
    bool ok = dir.mkdir(dirPath); //只创建一级子目录，即必须保证上级目录存在
    return ok;
}

void MyWidget::on_selectDecryDir_clicked()
{
    this->decryDir_pri  = QFileDialog::getExistingDirectory(this,"select Decry DirPath...","../");
    if(decryDir_pri.isEmpty())
    {
        return;
    }
    else
    {
        QMessageBox::about(this, "info", decryDir_pri);
        this->type_pri = false;
    }
}

void MyWidget::on_selectEncryDir_clicked()
{
    this->encryDir_pri  = QFileDialog::getExistingDirectory(this,"select Decry DirPath...","../");
    if(encryDir_pri.isEmpty())
    {
        return;
    }
    else
    {
        QMessageBox::about(this, "info", encryDir_pri);
        this->type_pri = false;
    }
}

void MyWidget::on_Encry_clicked()
{
    retval_t ret ;
    char *passwd = "dqduhquihui23217";
    char encryFileName[FILENAMELENTH] = { 0 };
    bool OK;


    if(this->type_pri)
    {
        if (strlen(this->encryFile_pri ) == 0 )
        {
            QMessageBox::about(this, "EncryFile", "Error : No input EncryFile");
             goto End;
        }
        if( strlen(this->publicPath_pri) == 0)
        {
            QMessageBox::about(this, "PUBLICKEY", "Error : No input publicKey");
             goto End;
        }
        else
        {
            ret = mix_RSA_AES_encryFile(this->encryFile_pri, passwd, this->publicPath_pri, encryFileName, 0);
            if(ret.retval < 0)
            {
                QMessageBox::about(this, "ENCRY FILE", QString(ret.reason));
                 goto End;
            }
            else
            {
                QMessageBox::about(this, "ENCRY FILE", QString(encryFileName));
            }
        }
    }
    else
    {
        if (this->encryDir_pri.isEmpty())
        {
            QMessageBox::about(this, "EncryDir", "Error : No input Decry Dir");
            goto End;
        }
        if( strlen(this->publicPath_pri) == 0)
        {
            QMessageBox::about(this, "PUBLICKEY", "Error : No input privateKey");
            goto End;
        }
        //1. create The dir To store decryFile
        QString  mewStoreDirDecryPath = this->encryDir_pri + "/encryDir";
        if((OK = this->isDirExist(mewStoreDirDecryPath)) == false)
        {
            if((OK = this->createDir(mewStoreDirDecryPath)) == false)
            {
                QString errors = "create dir : " + mewStoreDirDecryPath + " failed";
                QMessageBox::about(this, "Error", errors);
                goto End;
            }
        }

        //2. list Folder content,
        QDir dir(this->encryDir_pri);
        dir.setFilter(QDir::Files | QDir::Hidden | QDir::NoSymLinks);
        QFileInfoList list = dir.entryInfoList();
        for (int i = 0; i < list.size(); ++i)
        {
            QFileInfo fileInfo = list.at(i);
            if(fileInfo.size() > 0 && fileInfo.baseName().indexOf("_ENCRYPT_RSA_AES") <0 && fileInfo.baseName().indexOf("_DECRYPT_RSA_AES") < 0)
            {
               //3. assemble newFilePath
               QByteArray keybaone, keybatwo;
               QString newFilePath = mewStoreDirDecryPath + "/" + fileInfo.baseName() + "_ENCRYPT_RSA_AES."  + fileInfo.suffix();
               keybaone = fileInfo.absoluteFilePath().toLatin1();
               char *srcFile = keybaone.data();
               qDebug() << fileInfo.absoluteFilePath();
               qDebug() << srcFile;
               keybatwo = newFilePath.toLatin1();
               char *dstFile = keybatwo.data();
               qDebug() << newFilePath;
               qDebug() << dstFile;
               ret = encryDirAllFile(srcFile, dstFile, this->publicPath_pri, 0);
               if(ret.retval < 0)
               {
                    QMessageBox::about(this, "Error",  QString(ret.reason));
                    goto End;
               }
            }
        }
        if(ret.retval == 0)
        {
            QMessageBox::about(this, "SUCCESS", "OK, Encry DirAllFile ...");
        }
    }

End:
    memset(this->encryFile_pri, 0 , FILENAMELENTH );
    memset(this->publicPath_pri, 0, FILENAMELENTH);
    this->encryDir_pri = "";

}


void MyWidget::on_Decry_clicked()
{
    retval_t ret;
    char decryFileName[FILENAMELENTH] = { 0 };
    bool OK;
    QByteArray keyba;

    if(this->type_pri)
    {
        //1. encry File
        if (strlen(this->decryFile_pri ) == 0 )
        {
            QMessageBox::about(this, "DecryFile", "No input DecryFile");
            goto End;
        }
        if( strlen(this->privatePath_pri) == 0)
        {
            QMessageBox::about(this, "PRIVATEKEY", "No input privateKey");
            goto End;
        }
        else
        {
            ret = mix_RSA_AES_decryFile(this->decryFile_pri, this->privatePath_pri, decryFileName);
            if(ret.retval < 0)
            {
                QMessageBox::about(this, "DECRY FILE", QString(ret.reason));
                goto End;
            }
            else
            {
                QMessageBox::about(this, "DECRY FILE", QString(decryFileName));
                goto End;
            }
        }
    }
    else        //decry dir
    {

        if (this->decryDir_pri.isEmpty())
        {
            QMessageBox::about(this, "Decry Dir", "No input Decry Dir");
             goto End;
        }
        if( strlen(this->privatePath_pri) == 0)
        {
            QMessageBox::about(this, "PRIVATEKEY", "No input privateKey");
             goto End;
        }
        //1. create The dir To store decryFile
        QString  mewStoreDirDecryPath = this->decryDir_pri + "/decryDir";
        if((OK = this->isDirExist(mewStoreDirDecryPath)) == false)
        {
            if((OK = this->createDir(mewStoreDirDecryPath)) == false)
            {
                QString errors = "create dir : " + mewStoreDirDecryPath + " failed";
                QMessageBox::about(this, "Error", errors);
                 goto End;
            }
        }

        //2. list Folder content,
        QDir dir(this->decryDir_pri);
        dir.setFilter(QDir::Files | QDir::Hidden | QDir::NoSymLinks);
        QFileInfoList list = dir.entryInfoList();
        for (int i = 0; i < list.size(); ++i)
        {
            QFileInfo fileInfo = list.at(i);
            if(fileInfo.size() > 0 && fileInfo.baseName().indexOf("_ENCRYPT_RSA_AES") >= 0)
            {
               QByteArray keybaone, keybatwo;
               //3. assemble newFilePath
               QString newFilePath = mewStoreDirDecryPath + "/" + fileInfo.baseName() + "_DECRYPT_RSA_AES."  + fileInfo.suffix();
               keybaone = fileInfo.absoluteFilePath().toLatin1();
               char *srcFile = keybaone.data();
               keybatwo = newFilePath.toLatin1();
               char *dstFile = keybatwo.data();
               qDebug() << srcFile;
               qDebug() << dstFile;
               ret = decryDirAllFile(srcFile, dstFile, this->privatePath_pri);
               if(ret.retval < 0)
               {
                    QMessageBox::about(this, "Error",  QString(ret.reason));
                    goto End;
               }
            }
        }
        if(ret.retval == 0)
        {
            QMessageBox::about(this, "SUCCESS", "OK, Decry DirAllFile ...");
        }
    }

End:
    memset(privatePath_pri, 0, FILENAMELENTH);
    memset(decryFile_pri, 0, FILENAMELENTH);
    decryDir_pri = "";
}

void MyWidget::on_createKey_clicked()
{
    retval_t ret ;
    char *tmp = NULL;
    QByteArray keyba;
    QMessageBox::StandardButton res;

    //1.promote News for private Key
    res = QMessageBox::information(this, "create private Key", "Enter your Name for privateKey",
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
    if(res == QMessageBox::Yes)
    {
        //2. Enput The privateKey Name
        QString path = QFileDialog::getSaveFileName(this, "save", "../", "PEM(*.PEM)");
        path = path + ".pem";
        QMessageBox::about(this, "path", path);
        if(!path.isEmpty())
        {
            keyba = path.toLatin1();
            tmp = keyba.data();
            strcpy(this->privatePath_pri, tmp);

            //3. Enput The publicKey Name
            res = QMessageBox::information(this, "create public Key", "Enter your Name for publicKey",
                                     QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
            if(res == QMessageBox::Yes)
            {
                QString path = QFileDialog::getSaveFileName(this, "save", "../", "PEM(*.PEM)");
                path = path + ".pem";
                QMessageBox::about(this, "path", path);
                if(!path.isEmpty())
                {
                    keyba = path.toLatin1();
                    tmp = keyba.data();
                    strcpy(this->publicPath_pri, tmp);

                    //4. create The publicKey And privateKey
                    ret = create_private_public_key(publicPath_pri, privatePath_pri);
                    if(ret.retval < 0)
                    {
                        QMessageBox::about(this, "createKey Error", "create publicKey And privateKey Fail");
                    }
                    else
                    {
                        QMessageBox::about(this, "createKey OK", "create publicKey And privateKey Success");
                    }
                }
            }
            else
            {
                QMessageBox::about(this, "create Key", "create publicKey And privateKey Fail");
            }

        }

    }


    memset(this->publicPath_pri, 0, FILENAMELENTH);
    memset(this->privatePath_pri, 0, FILENAMELENTH);
}


void findSubstr()
{
     QString x = "sticky question";
     QString y = "sti";
     x.indexOf(y);               // returns 0
     x.indexOf(y, 1);            // returns 10
     x.indexOf(y, 10);           // returns 10
     x.indexOf(y, 11);           // returns -1
}

int test_list(QString dirPath)
 {
    QByteArray keyba;
     QDir dir(dirPath);
     dir.setFilter(QDir::Files | QDir::Hidden | QDir::NoSymLinks);
//     dir.setSorting(QDir::Size | QDir::Reversed);

     QFileInfoList list = dir.entryInfoList();
     cout << "file Num : " <<list.size() <<endl;
     for (int i = 0; i < list.size(); ++i)
     {
         QFileInfo fileInfo = list.at(i);
//         std::cout << qPrintable(QString("%1 %2").arg(fileInfo.size(), 10)
//                                                 .arg(fileInfo.fileName()));
        keyba = fileInfo.absoluteFilePath().toLatin1();
        char *srcFile = keyba.data();
        qDebug() << srcFile;
        qDebug() << fileInfo.absoluteFilePath();

#if 0
         if(fileInfo.size() > 0)
         {
            QString file = fileInfo.baseName() ;
            qDebug() << file;
            QString suf = fileInfo.suffix();
            qDebug() << suf ;
        }

#endif

     }
     return 0;

#if 0
     //2.transformation DirPath Qstring to char*



#endif

}
