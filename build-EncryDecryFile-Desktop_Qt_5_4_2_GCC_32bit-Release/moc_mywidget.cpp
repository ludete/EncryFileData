/****************************************************************************
** Meta object code from reading C++ file 'mywidget.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.4.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../EncryDecryFile/mywidget.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'mywidget.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.4.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
struct qt_meta_stringdata_MyWidget_t {
    QByteArrayData data[9];
    char stringdata[171];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_MyWidget_t, stringdata) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_MyWidget_t qt_meta_stringdata_MyWidget = {
    {
QT_MOC_LITERAL(0, 0, 8), // "MyWidget"
QT_MOC_LITERAL(1, 9, 25), // "on_selectEncryKey_clicked"
QT_MOC_LITERAL(2, 35, 0), // ""
QT_MOC_LITERAL(3, 36, 26), // "on_selectEncryFile_clicked"
QT_MOC_LITERAL(4, 63, 25), // "on_selectDecryKey_clicked"
QT_MOC_LITERAL(5, 89, 26), // "on_selectDecryFile_clicked"
QT_MOC_LITERAL(6, 116, 16), // "on_Encry_clicked"
QT_MOC_LITERAL(7, 133, 16), // "on_Decry_clicked"
QT_MOC_LITERAL(8, 150, 20) // "on_createKey_clicked"

    },
    "MyWidget\0on_selectEncryKey_clicked\0\0"
    "on_selectEncryFile_clicked\0"
    "on_selectDecryKey_clicked\0"
    "on_selectDecryFile_clicked\0on_Encry_clicked\0"
    "on_Decry_clicked\0on_createKey_clicked"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_MyWidget[] = {

 // content:
       7,       // revision
       0,       // classname
       0,    0, // classinfo
       7,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   49,    2, 0x08 /* Private */,
       3,    0,   50,    2, 0x08 /* Private */,
       4,    0,   51,    2, 0x08 /* Private */,
       5,    0,   52,    2, 0x08 /* Private */,
       6,    0,   53,    2, 0x08 /* Private */,
       7,    0,   54,    2, 0x08 /* Private */,
       8,    0,   55,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void MyWidget::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        MyWidget *_t = static_cast<MyWidget *>(_o);
        switch (_id) {
        case 0: _t->on_selectEncryKey_clicked(); break;
        case 1: _t->on_selectEncryFile_clicked(); break;
        case 2: _t->on_selectDecryKey_clicked(); break;
        case 3: _t->on_selectDecryFile_clicked(); break;
        case 4: _t->on_Encry_clicked(); break;
        case 5: _t->on_Decry_clicked(); break;
        case 6: _t->on_createKey_clicked(); break;
        default: ;
        }
    }
    Q_UNUSED(_a);
}

const QMetaObject MyWidget::staticMetaObject = {
    { &QWidget::staticMetaObject, qt_meta_stringdata_MyWidget.data,
      qt_meta_data_MyWidget,  qt_static_metacall, Q_NULLPTR, Q_NULLPTR}
};


const QMetaObject *MyWidget::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *MyWidget::qt_metacast(const char *_clname)
{
    if (!_clname) return Q_NULLPTR;
    if (!strcmp(_clname, qt_meta_stringdata_MyWidget.stringdata))
        return static_cast<void*>(const_cast< MyWidget*>(this));
    return QWidget::qt_metacast(_clname);
}

int MyWidget::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 7)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 7;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 7)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 7;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
