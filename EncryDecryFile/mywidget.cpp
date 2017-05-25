#include "mywidget.h"
#include "ui_mywidget.h"
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QFileDialog>
#include <QByteArray>
#include <iostream>
#include <stdio.h>
#include <QMessageBox>
#include "encryptData.h"



using namespace std;




void test(char *fileName)
{
    cout << "filePath : "<<fileName << endl;

}

MyWidget::MyWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MyWidget)
{
    ui->setupUi(this);

    if((pool_pri = init()) == NULL)
    {
        qDebug() << "Err : init() error";
    }

    memset(this->encryFile_pri, 0, FILENAMELENTH);
    memset(this->decryFile_pri, 0, FILENAMELENTH);
    memset(this->publicPath_pri, 0, FILENAMELENTH);
    memset(this->privatePath_pri, 0, FILENAMELENTH);
    this->pool_pri = NULL;
}

MyWidget::~MyWidget()
{
    destroy(pool_pri);
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

    int ret = 0;

    cout << "encryFile : " << this->encryFile_pri << endl;
    cout << "publicKey : " << this->publicPath_pri << endl;

    if(!this->encryFile_pri || !this->publicPath_pri)
    {
        qDebug() << "Err : The element is NULL" ;
    }
    else
    {
        if((ret = encryptFileData(this->encryFile_pri, this->publicPath_pri)) < 0)
        {
            qDebug() << "Err : func encryptFileData()";
            //QMessageBox::Abort(this, "Err", "EncryFile Error");
        }
        else
        {
            qDebug() << "Encry File OK";
        }
    }

}

void MyWidget::on_Decry_clicked()
{
    int ret = 0;

    cout << "decryFile : " << this->decryFile_pri << endl;
    cout << "privateKey : " << this->privatePath_pri << endl;

    if(!this->decryFile_pri || !this->privatePath_pri)
    {
        qDebug() << "Err : The element is NULL" ;
    }
    else
    {

        if((ret = decryptFileData(this->decryFile_pri, this->privatePath_pri)) < 0)
        {
            qDebug() << "Err : func encryptFileData()";
            //QMessageBox::Abort(this, "Err", "EncryFile Error");
        }
        else
        {
            qDebug() << "Decry File OK";
        }
    }

}
