/********************************************************************************
** Form generated from reading UI file 'mywidget.ui'
**
** Created by: Qt User Interface Compiler version 5.4.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MYWIDGET_H
#define UI_MYWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MyWidget
{
public:
    QPushButton *Decry;
    QPushButton *Encry;
    QPushButton *createKey;
    QPushButton *selectDecryKey;
    QPushButton *selectDecryFile;
    QPushButton *selectEncryFile;
    QPushButton *selectEncryKey;
    QPushButton *selectEncryDir;
    QPushButton *selectDecryDir;
    QLabel *label;
    QLabel *label_2;

    void setupUi(QWidget *MyWidget)
    {
        if (MyWidget->objectName().isEmpty())
            MyWidget->setObjectName(QStringLiteral("MyWidget"));
        MyWidget->resize(533, 429);
        Decry = new QPushButton(MyWidget);
        Decry->setObjectName(QStringLiteral("Decry"));
        Decry->setGeometry(QRect(220, 300, 99, 51));
        Encry = new QPushButton(MyWidget);
        Encry->setObjectName(QStringLiteral("Encry"));
        Encry->setGeometry(QRect(220, 80, 99, 51));
        createKey = new QPushButton(MyWidget);
        createKey->setObjectName(QStringLiteral("createKey"));
        createKey->setGeometry(QRect(220, 190, 99, 51));
        selectDecryKey = new QPushButton(MyWidget);
        selectDecryKey->setObjectName(QStringLiteral("selectDecryKey"));
        selectDecryKey->setGeometry(QRect(370, 300, 131, 51));
        selectDecryFile = new QPushButton(MyWidget);
        selectDecryFile->setObjectName(QStringLiteral("selectDecryFile"));
        selectDecryFile->setGeometry(QRect(20, 250, 131, 51));
        selectEncryFile = new QPushButton(MyWidget);
        selectEncryFile->setObjectName(QStringLiteral("selectEncryFile"));
        selectEncryFile->setGeometry(QRect(20, 30, 131, 51));
        selectEncryKey = new QPushButton(MyWidget);
        selectEncryKey->setObjectName(QStringLiteral("selectEncryKey"));
        selectEncryKey->setGeometry(QRect(370, 80, 131, 51));
        selectEncryDir = new QPushButton(MyWidget);
        selectEncryDir->setObjectName(QStringLiteral("selectEncryDir"));
        selectEncryDir->setGeometry(QRect(20, 130, 131, 51));
        selectDecryDir = new QPushButton(MyWidget);
        selectDecryDir->setObjectName(QStringLiteral("selectDecryDir"));
        selectDecryDir->setGeometry(QRect(20, 350, 131, 51));
        label = new QLabel(MyWidget);
        label->setObjectName(QStringLiteral("label"));
        label->setGeometry(QRect(330, 400, 201, 20));
        label_2 = new QLabel(MyWidget);
        label_2->setObjectName(QStringLiteral("label_2"));
        label_2->setGeometry(QRect(470, 10, 111, 17));

        retranslateUi(MyWidget);

        QMetaObject::connectSlotsByName(MyWidget);
    } // setupUi

    void retranslateUi(QWidget *MyWidget)
    {
        MyWidget->setWindowTitle(QApplication::translate("MyWidget", "EncryDecryFile", 0));
        Decry->setText(QApplication::translate("MyWidget", "Decry", 0));
        Encry->setText(QApplication::translate("MyWidget", "Encry", 0));
        createKey->setText(QApplication::translate("MyWidget", "createKey", 0));
        selectDecryKey->setText(QApplication::translate("MyWidget", "select Decry Key", 0));
        selectDecryFile->setText(QApplication::translate("MyWidget", "select Decry File", 0));
        selectEncryFile->setText(QApplication::translate("MyWidget", "select Encry File", 0));
        selectEncryKey->setText(QApplication::translate("MyWidget", "select Encry Key", 0));
        selectEncryDir->setText(QApplication::translate("MyWidget", "select Encry Dir", 0));
        selectDecryDir->setText(QApplication::translate("MyWidget", "select Decry Dir", 0));
        label->setText(QApplication::translate("MyWidget", "author : yyxyong@163.com", 0));
        label_2->setText(QApplication::translate("MyWidget", "LGPL", 0));
    } // retranslateUi

};

namespace Ui {
    class MyWidget: public Ui_MyWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MYWIDGET_H
