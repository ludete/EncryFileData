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
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MyWidget
{
public:
    QPushButton *Decry;
    QPushButton *Encry;
    QWidget *verticalLayoutWidget;
    QHBoxLayout *horizontalLayout;
    QSpacerItem *horizontalSpacer;
    QPushButton *selectEncryFile;
    QSpacerItem *horizontalSpacer_3;
    QPushButton *selectEncryKey;
    QSpacerItem *horizontalSpacer_2;
    QWidget *verticalLayoutWidget_2;
    QHBoxLayout *horizontalLayout_2;
    QSpacerItem *horizontalSpacer_4;
    QPushButton *selectDecryFile;
    QSpacerItem *horizontalSpacer_5;
    QPushButton *selectDecryKey;
    QSpacerItem *horizontalSpacer_6;
    QPushButton *createKey;

    void setupUi(QWidget *MyWidget)
    {
        if (MyWidget->objectName().isEmpty())
            MyWidget->setObjectName(QStringLiteral("MyWidget"));
        MyWidget->resize(480, 311);
        Decry = new QPushButton(MyWidget);
        Decry->setObjectName(QStringLiteral("Decry"));
        Decry->setGeometry(QRect(200, 260, 99, 27));
        Encry = new QPushButton(MyWidget);
        Encry->setObjectName(QStringLiteral("Encry"));
        Encry->setGeometry(QRect(200, 150, 99, 27));
        verticalLayoutWidget = new QWidget(MyWidget);
        verticalLayoutWidget->setObjectName(QStringLiteral("verticalLayoutWidget"));
        verticalLayoutWidget->setGeometry(QRect(0, 90, 481, 41));
        horizontalLayout = new QHBoxLayout(verticalLayoutWidget);
        horizontalLayout->setObjectName(QStringLiteral("horizontalLayout"));
        horizontalLayout->setContentsMargins(0, 0, 0, 0);
        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        selectEncryFile = new QPushButton(verticalLayoutWidget);
        selectEncryFile->setObjectName(QStringLiteral("selectEncryFile"));

        horizontalLayout->addWidget(selectEncryFile);

        horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_3);

        selectEncryKey = new QPushButton(verticalLayoutWidget);
        selectEncryKey->setObjectName(QStringLiteral("selectEncryKey"));

        horizontalLayout->addWidget(selectEncryKey);

        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_2);

        verticalLayoutWidget_2 = new QWidget(MyWidget);
        verticalLayoutWidget_2->setObjectName(QStringLiteral("verticalLayoutWidget_2"));
        verticalLayoutWidget_2->setGeometry(QRect(0, 200, 481, 41));
        horizontalLayout_2 = new QHBoxLayout(verticalLayoutWidget_2);
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        horizontalLayout_2->setContentsMargins(0, 0, 0, 0);
        horizontalSpacer_4 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_4);

        selectDecryFile = new QPushButton(verticalLayoutWidget_2);
        selectDecryFile->setObjectName(QStringLiteral("selectDecryFile"));

        horizontalLayout_2->addWidget(selectDecryFile);

        horizontalSpacer_5 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_5);

        selectDecryKey = new QPushButton(verticalLayoutWidget_2);
        selectDecryKey->setObjectName(QStringLiteral("selectDecryKey"));

        horizontalLayout_2->addWidget(selectDecryKey);

        horizontalSpacer_6 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer_6);

        createKey = new QPushButton(MyWidget);
        createKey->setObjectName(QStringLiteral("createKey"));
        createKey->setGeometry(QRect(190, 30, 99, 27));

        retranslateUi(MyWidget);

        QMetaObject::connectSlotsByName(MyWidget);
    } // setupUi

    void retranslateUi(QWidget *MyWidget)
    {
        MyWidget->setWindowTitle(QApplication::translate("MyWidget", "EncryDecryFile", 0));
        Decry->setText(QApplication::translate("MyWidget", "Decry", 0));
        Encry->setText(QApplication::translate("MyWidget", "Encry", 0));
        selectEncryFile->setText(QApplication::translate("MyWidget", "select Encry File", 0));
        selectEncryKey->setText(QApplication::translate("MyWidget", "select Encry Key", 0));
        selectDecryFile->setText(QApplication::translate("MyWidget", "select Decry File", 0));
        selectDecryKey->setText(QApplication::translate("MyWidget", "select Decry Key", 0));
        createKey->setText(QApplication::translate("MyWidget", "createKey", 0));
    } // retranslateUi

};

namespace Ui {
    class MyWidget: public Ui_MyWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MYWIDGET_H
