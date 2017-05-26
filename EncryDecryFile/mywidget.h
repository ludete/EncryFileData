#ifndef MYWIDGET_H
#define MYWIDGET_H

#include <QWidget>

#define FILENAMELENTH  1024


namespace Ui {
class MyWidget;
}

class MyWidget : public QWidget
{
    Q_OBJECT

public:
    explicit MyWidget(QWidget *parent = 0);
    ~MyWidget();

private slots:
    void on_selectEncryKey_clicked();

    void on_selectEncryFile_clicked();

    void on_selectDecryKey_clicked();

    void on_selectDecryFile_clicked();

    void on_Encry_clicked();

    void on_Decry_clicked();

    void on_createKey_clicked();

private:
    Ui::MyWidget *ui;
    char publicPath_pri[FILENAMELENTH];
    char encryFile_pri[FILENAMELENTH];
    char decryFile_pri[FILENAMELENTH];
    char privatePath_pri[FILENAMELENTH];    
    void *pool_pri;
};

#define MY_MIN(x, y)   ((x) < (y)) ? (x) : (y)



#endif // MYWIDGET_H
