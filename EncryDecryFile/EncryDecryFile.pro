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
    mywidget.cpp \
    myAdddll.cpp

HEADERS += \
    mywidget.h \
    encryDecryFile.h \
    myAdddll.h

FORMS += \
    mywidget.ui

#RC_ICONS =EncryDecryFile.ico
RC_FILE += addicon.rc

unix{
INCLUDEPATH += -I/home/yyx02/QtCode/build-EncryDecryFile-Desktop_Qt_5_4_2_GCC_32bit-Release/include

LIBS +=  -L./ -lssl -lcrypto -lencrydecry
LIBS += -lpthread
}

DISTFILES += \
    EncryDecryFile.ico \
    addicon.rc
