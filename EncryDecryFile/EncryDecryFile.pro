#-------------------------------------------------
#
# Project created by QtCreator 2016-01-04T14:38:13
#
#-------------------------------------------------
QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = EncryDecryFile
TEMPLATE = app


SOURCES += \
    main.cpp \
    mywidget.cpp

HEADERS += \
    mywidget.h \
    encryptData.h

FORMS += \
    mywidget.ui

unix{
INCLUDEPATH += -I/home/yyx02/QtCode/build-EncryDecryFile-Desktop_Qt_5_4_2_GCC_32bit-Release/include

LIBS += -L/home/yyx02/QtCode/build-EncryDecryFile-Desktop_Qt_5_4_2_GCC_32bit-Release/lib -lssl -lcrypto -lencrydecry

}
