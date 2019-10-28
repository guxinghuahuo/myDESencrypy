#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QDir>
#include <QFileDialog>
#include <QMessageBox>
#include "des.h"
#include <stdio.h>

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = nullptr);
    ~Widget();

private slots:
    void on_plainTextFileSearchBtn_clicked();

    void on_cipherTextFileSearchBtn_clicked();

    void on_keyFileSearchBtn_clicked();

    void on_aboutBtn_clicked();

    void on_encrypyBtn_clicked();

    void on_decrypyBtn_clicked();

private:
    Ui::Widget *ui;
    bool openTextByIODevice(const QString &aFileName);
    des_key deskey;
};

#endif // WIDGET_H
