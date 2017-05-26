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
    this->pool_pri = NULL;
}

MyWidget::~MyWidget()
{
    delete ui;
}


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
    }
}

void MyWidget::on_Encry_clicked()
{

    retval_t ret ;
    bool ok = false;
    char *passwd = NULL;
    QByteArray keyba;
    char encryFileName[FILENAMELENTH] = { 0 };

    //1.Get AES passwd
    QString text = QInputDialog::getText(this,
                "Passwd",
                "please Enter your passwd",
                QLineEdit::Normal, QString::null, &ok);
    keyba = text.toLatin1();
    passwd = keyba.data();

    //2.choose The work flow
    if(ok && !text.isEmpty())
    {
        if (strlen(this->encryFile_pri ) == 0 )
        {
            QMessageBox::about(this, "EncryFile", "No input EncryFile");
            return;
        }
        else if( strlen(this->publicPath_pri) == 0)
        {
            QMessageBox::about(this, "PUBLICKEY", "No input publicKey");
            return;
        }
        else
        {
            ret = mix_RSA_AES_encryFile(this->encryFile_pri, passwd, this->publicPath_pri, encryFileName, 0);
            if(ret.retval < 0)
            {
                QMessageBox::about(this, "ENCRY FILE", QString(ret.reason));
            }
            else
            {
                QMessageBox::about(this, "ENCRY FILE", QString(encryFileName));
            }
            memset(this->encryFile_pri, 0 , FILENAMELENTH );
            memset(this->publicPath_pri, 0, FILENAMELENTH);
        }

    }
    else
    {
        QMessageBox::about(this, "PassWd", "No input Passwd");
    }
}

void MyWidget::on_Decry_clicked()
{
    retval_t ret;
    char decryFileName[FILENAMELENTH] = { 0 };


    if (strlen(this->decryFile_pri ) == 0 )
    {
        QMessageBox::about(this, "DecryFile", "No input DecryFile");
        return;
    }
    else if( strlen(this->privatePath_pri) == 0)
    {
        QMessageBox::about(this, "PRIVATEKEY", "No input privateKey");
        return;
    }
    else
    {
        ret = mix_RSA_AES_decryFile(this->decryFile_pri, this->privatePath_pri, decryFileName);
        if(ret.retval < 0)
        {
            QMessageBox::about(this, "DECRY FILE", QString(ret.reason));
        }
        else
        {
            QMessageBox::about(this, "DECRY FILE", QString(decryFileName));
        }
        memset(this->decryFile_pri, 0 , FILENAMELENTH );
        memset(this->privatePath_pri, 0, FILENAMELENTH);
    }

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
