QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = thread_signal
TEMPLATE = app

SOURCES += \
    main.c \
    mydialog.cpp

unix{

LIBS += -lpthread

}

HEADERS += \
    mydialog.h
