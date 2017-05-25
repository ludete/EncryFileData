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
#include <QtWidgets/QPushButton>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MyWidget
{
public:
    QPushButton *selectEncryKey;
    QPushButton *selectEncryFile;
    QPushButton *selectDecryKey;
    QPushButton *selectDecryFile;
    QPushButton *Decry;
    QPushButton *Encry;

    void setupUi(QWidget *MyWidget)
    {
        if (MyWidget->objectName().isEmpty())
            MyWidget->setObjectName(QStringLiteral("MyWidget"));
        MyWidget->resize(398, 295);
        selectEncryKey = new QPushButton(MyWidget);
        selectEncryKey->setObjectName(QStringLiteral("selectEncryKey"));
        selectEncryKey->setGeometry(QRect(50, 50, 121, 27));
        selectEncryFile = new QPushButton(MyWidget);
        selectEncryFile->setObjectName(QStringLiteral("selectEncryFile"));
        selectEncryFile->setGeometry(QRect(230, 50, 121, 27));
        selectDecryKey = new QPushButton(MyWidget);
        selectDecryKey->setObjectName(QStringLiteral("selectDecryKey"));
        selectDecryKey->setGeometry(QRect(50, 170, 121, 27));
        selectDecryFile = new QPushButton(MyWidget);
        selectDecryFile->setObjectName(QStringLiteral("selectDecryFile"));
        selectDecryFile->setGeometry(QRect(240, 170, 121, 27));
        Decry = new QPushButton(MyWidget);
        Decry->setObjectName(QStringLiteral("Decry"));
        Decry->setGeometry(QRect(150, 240, 99, 27));
        Encry = new QPushButton(MyWidget);
        Encry->setObjectName(QStringLiteral("Encry"));
        Encry->setGeometry(QRect(150, 110, 99, 27));

        retranslateUi(MyWidget);

        QMetaObject::connectSlotsByName(MyWidget);
    } // setupUi

    void retranslateUi(QWidget *MyWidget)
    {
        MyWidget->setWindowTitle(QApplication::translate("MyWidget", "Form", 0));
        selectEncryKey->setText(QApplication::translate("MyWidget", "select Encry Key", 0));
        selectEncryFile->setText(QApplication::translate("MyWidget", "select Encry File", 0));
        selectDecryKey->setText(QApplication::translate("MyWidget", "select Decry Key", 0));
        selectDecryFile->setText(QApplication::translate("MyWidget", "select Decry File", 0));
        Decry->setText(QApplication::translate("MyWidget", "Decry", 0));
        Encry->setText(QApplication::translate("MyWidget", "Encry", 0));
    } // retranslateUi

};

namespace Ui {
    class MyWidget: public Ui_MyWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MYWIDGET_H
