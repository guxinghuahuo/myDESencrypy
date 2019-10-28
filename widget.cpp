#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
}

Widget::~Widget()
{
    delete ui;
}

void Widget::on_plainTextFileSearchBtn_clicked()
{
    QString curPath = QDir::currentPath();
    QString dlgTitle = "选择一个文件";
    QString filter = "二进制文件(*.dat);;所有文件(*.*)";
    QString plainTextFileName = QFileDialog::getOpenFileName(this, dlgTitle, curPath);
    ui->plainTextFileEdit->setText(plainTextFileName);
}

void Widget::on_cipherTextFileSearchBtn_clicked()
{
    QString curPath = QDir::currentPath();
    QString dlgTitle = "选择一个文件";
    QString filter = "des加密文件(*.dat);;所有文件(*.*)";
    QString cipherTextFileName = QFileDialog::getOpenFileName(this, dlgTitle, curPath, filter);
    ui->cipherTextFileEdit->setText(cipherTextFileName);
}

void Widget::on_keyFileSearchBtn_clicked()
{
    QString curPath = QDir::currentPath();
    QString dlgTitle = "选择一个文件";
    QString filter = "二进制文件(*.dat);;所有文件(*.*)";
    QString keyFileName = QFileDialog::getOpenFileName(this, dlgTitle, curPath, filter);
    ui->keyFileEdit->setText(keyFileName);
}

void Widget::on_aboutBtn_clicked()
{
    QString dlgTitle = "关于作者";
    QString strInfo = "designed by: 孤行花火    version: v1.0";
    QMessageBox::about(this, dlgTitle, strInfo);
}

void Widget::on_encrypyBtn_clicked()
{
    //打开明文文件
    QString plainTextFileName = ui->plainTextFileEdit->text();
    if (plainTextFileName.isEmpty()){
        QString dlgTitle = "文件名输入错误";
        QString strInfo = "文件名输入错误，请指定一个明文文件！";
        QMessageBox::critical(this, dlgTitle, strInfo);
        return;
    }
    QFile plainTextFile(plainTextFileName);
    if (!plainTextFile.exists()) {
        QString dlgTitle = "文件名错误";
        QString strInfo = "文件名不存在！";
        QMessageBox::critical(this, dlgTitle, strInfo);
        return;
    }
    if (!plainTextFile.open(QIODevice::ReadOnly)) {
        QString dlgTitle = "文件打开错误";
        QString strInfo = "文件名打开失败，可能是权限不够！";
        QMessageBox::critical(this, dlgTitle, strInfo);
        return;
    }
    //打开密钥文件
    QString skey;
    unsigned char key[8];
    QString keyFileName = ui->keyFileEdit->text();
    if(!keyFileName.isEmpty()){
        QFile keyFile(keyFileName);
        if (!keyFile.exists()) {
            QString dlgTitle = "文件名错误";
            QString strInfo = "文件名不存在！";
            QMessageBox::critical(this, dlgTitle, strInfo);
            return;
        }
        if (!keyFile.open(QIODevice::ReadOnly)) {
            QString dlgTitle = "文件打开错误";
            QString strInfo = "文件名打开失败，可能是权限不够！";
            QMessageBox::critical(this, dlgTitle, strInfo);
            return;
        }
        //读取密钥到key
        QByteArray keyBytes = keyFile.readAll();
        if (keyBytes.length() != 8) {
            QString dlgTitle = "密钥输入错误";
            QString strInfo = "密钥输入错误，请指定一个16位十六进制密钥！";
            QMessageBox::critical(this, dlgTitle, strInfo);
            return;
        }
        memcpy(key, keyBytes, 8);
        keyFile.close();
    } else if (!(skey = ui->keyEditText->text()).isEmpty()) {
        //十六进制输入
            if(skey.length() != 16){
                QString dlgTitle = "密钥输入错误";
                QString strInfo = "密钥输入错误，请指定一个16位十六进制密钥！";
                QMessageBox::critical(this, dlgTitle, strInfo);
                return;
            }
            //QString转化为unsigned char *
            for (int i = 0; i < 16; i = i + 2){
                bool ok;
                QString k(skey.mid(i, 2));
                key[i/2] = (unsigned char)k.toInt(&ok, 16);
                if (!ok) {
                    QString dlgTitle = "密钥输入错误";
                    QString strInfo = "密钥输入错误，请指定一个16位十六进制密钥！";
                    QMessageBox::critical(this, dlgTitle, strInfo);
                    return;
                }
            }
    } else {
        QString dlgTitle = "密钥输入错误";
        QString strInfo = "密钥输入错误，请指定一个密钥文件，或输入一个密钥！";
        QMessageBox::critical(this, dlgTitle, strInfo);
        return;
    }
    //创建密文文件
    QString cipherTextFileName = plainTextFileName;
    //删除尾部的.dat
    cipherTextFileName = cipherTextFileName.mid(0, cipherTextFileName.length() - 4);
    //添加后缀
    cipherTextFileName.append("(enc).dat");
    QFile cipherTextFile(cipherTextFileName);
    if (!cipherTextFile.exists()) {
        //不覆盖原文件
        if (!cipherTextFile.open(QIODevice::WriteOnly)) {
            QString dlgTitle = "文件打开错误";
            QString strInfo = "文件名打开失败，可能是权限不够！";
            QMessageBox::critical(this, dlgTitle, strInfo);
            return;
        }
    } else {
        //覆盖原文件
        if (!cipherTextFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            QString dlgTitle = "文件打开错误";
            QString strInfo = "文件名打开失败，可能是权限不够！";
            QMessageBox::critical(this, dlgTitle, strInfo);
            return;
        }
    }
    //读取明文字节数组
    QByteArray plainBytes = plainTextFile.readAll();;
    if (plainBytes.length() == 0) {
        QString dlgTitle = "文件错误";
        QString strInfo = "文件内容为空！";
        QMessageBox::critical(this, dlgTitle, strInfo);
        return;
    }
    //每64bit加密一次
    while(plainBytes.length() > 0) {
        if(plainBytes.length() < 8) {//长度不够补零凑
            plainBytes.append(8 - plainBytes.length(), 0x00);
        }
        unsigned char plainText[8];
        unsigned char cipherText[8];
        memcpy(plainText, plainBytes, 8);
        plainBytes.remove(0, 8);
        if (des_setup(key, 8, 0, &deskey) != CRYPT_OK){
            QString dlgTitle = "加密错误";
            QString strInfo = "加密密钥设置错误，未知原因！";
            QMessageBox::critical(this, dlgTitle, strInfo);
            return;
        }
        des_ecb_encrypt(plainText, cipherText, &deskey);
        QByteArray cipherBytes;
        cipherBytes.resize(8);
        memcpy(cipherBytes.data(), cipherText, 8);
        cipherTextFile.write(cipherBytes);
    }
    plainTextFile.close();
    cipherTextFile.close();
    QString successTitle = "加密成功";
    QString successInfo = "加密成功！文件保存在";
    successInfo.append(cipherTextFileName);
    QMessageBox::information(this, successTitle, successInfo);
}

void Widget::on_decrypyBtn_clicked()
{
    //打开密文文件
    QString cipherTextFileName = ui->cipherTextFileEdit->text();
    if (cipherTextFileName.isEmpty()){
        QString dlgTitle = "文件名输入错误";
        QString strInfo = "文件名输入错误，请指定一个密文文件！";
        QMessageBox::critical(this, dlgTitle, strInfo);
        return;
    } else if (!cipherTextFileName.endsWith(".dat")){
        QString dlgTitle = "文件名输入错误";
        QString strInfo = "密钥文件名输入错误，请指定一个des加密文件（*.dat）！";
        QMessageBox::critical(this, dlgTitle, strInfo);
        return;
    }
    QFile cipherTextFile(cipherTextFileName);
    if (!cipherTextFile.exists()) {
        QString dlgTitle = "文件名错误";
        QString strInfo = "文件名不存在！";
        QMessageBox::critical(this, dlgTitle, strInfo);
        return;
    }
    if (!cipherTextFile.open(QIODevice::ReadOnly)) {
        QString dlgTitle = "文件打开错误";
        QString strInfo = "文件名打开失败，可能是权限不够！";
        QMessageBox::critical(this, dlgTitle, strInfo);
        return;
    }
    //打开密钥文件
    QString skey;
    unsigned char key[8];
    QString keyFileName = ui->keyFileEdit->text();
    if(!keyFileName.isEmpty()){
        QFile keyFile(keyFileName);
        if (!keyFile.exists()) {
            QString dlgTitle = "文件名错误";
            QString strInfo = "文件名不存在！";
            QMessageBox::critical(this, dlgTitle, strInfo);
            return;
        }
        if (!keyFile.open(QIODevice::ReadOnly)) {
            QString dlgTitle = "文件打开错误";
            QString strInfo = "文件名打开失败，可能是权限不够！";
            QMessageBox::critical(this, dlgTitle, strInfo);
            return;
        }
        //读取密钥到key
        QByteArray keyBytes = keyFile.readAll();
        if (keyBytes.length() != 8) {
            QString dlgTitle = "密钥输入错误";
            QString strInfo = "密钥输入错误，请指定一个16位十六进制密钥！";
            QMessageBox::critical(this, dlgTitle, strInfo);
            return;
        }
        memcpy(key, keyBytes, 8);
        keyFile.close();
    } else if (!(skey = ui->keyEditText->text()).isEmpty()) {
        //十六进制输入
            if(skey.length() != 16){
                QString dlgTitle = "密钥输入错误";
                QString strInfo = "密钥输入错误，请指定一个16位十六进制密钥！";
                QMessageBox::critical(this, dlgTitle, strInfo);
                return;
            }
            //QString转化为unsigned char *
            for (int i = 0; i < 16; i = i + 2){
                bool ok;
                QString k(skey.mid(i, 2));
                key[i/2] = (unsigned char)k.toInt(&ok, 16);
                if (!ok) {
                    QString dlgTitle = "密钥输入错误";
                    QString strInfo = "密钥输入错误，请指定一个16位十六进制密钥！";
                    QMessageBox::critical(this, dlgTitle, strInfo);
                    return;
                }
            }
    } else {
        QString dlgTitle = "密钥输入错误";
        QString strInfo = "密钥输入错误，请指定一个密钥文件，或输入一个密钥！";
        QMessageBox::critical(this, dlgTitle, strInfo);
        return;
    }
    //创建明文文件
    QString plainTextFileName = cipherTextFileName;
    //删除尾部的(enc)
    if (plainTextFileName.endsWith("(enc).dat")) {
        plainTextFileName = plainTextFileName.mid(0, plainTextFileName.length() - 9);
        //添加后缀
        plainTextFileName.append("(dec).dat");
    } else if (plainTextFileName.endsWith(".dat")) {
        plainTextFileName = plainTextFileName.mid(0, plainTextFileName.length() - 4);
        //添加后缀
        plainTextFileName.append("(dec).dat");
    }
    QFile plainTextFile(plainTextFileName);
    if (!plainTextFile.exists()) {
        //不覆盖原文件
        if (!plainTextFile.open(QIODevice::WriteOnly)) {
            QString dlgTitle = "文件打开错误";
            QString strInfo = "文件名打开失败，可能是权限不够！";
            QMessageBox::critical(this, dlgTitle, strInfo);
            return;
        }
    } else {
        //创建新副本，以防覆盖原文件
        for (int i = 1; plainTextFile.exists(); i++) {
            QString c;
            c.setNum(i - 1);
            QString chk;
            chk.append("(dec");
            chk.append(c);
            chk.append(").dat");
            //删除尾部的(dec)，文件重命名
            if (plainTextFileName.endsWith("(dec).dat")) {
                plainTextFileName = plainTextFileName.mid(0, plainTextFileName.length() - 9);
            } else if (plainTextFileName.endsWith(chk)) {//删除尾部的(dec*).dat
                plainTextFileName = plainTextFileName.mid(0, plainTextFileName.length() - chk.length());
            } else {
                plainTextFileName = plainTextFileName.mid(0, plainTextFileName.length() - 4);
            }
            QString appe;
            c.setNum(i);
            appe.append("(dec");
            appe.append(c);
            appe.append(").dat");
            plainTextFileName.append(appe);
            plainTextFile.setFileName(plainTextFileName);
        }
        if (!plainTextFile.open(QIODevice::WriteOnly)) {
            QString dlgTitle = "文件打开错误";
            QString strInfo = "文件名打开失败，可能是权限不够！";
            QMessageBox::critical(this, dlgTitle, strInfo);
            return;
        }
    }
    //读取密文字节数组
    QByteArray cipherBytes = cipherTextFile.readAll();;
    if (cipherBytes.length() == 0) {
        QString dlgTitle = "文件错误";
        QString strInfo = "文件内容为空！";
        QMessageBox::critical(this, dlgTitle, strInfo);
        return;
    }
    //密文字节长度不为8的整数倍
    if (cipherBytes.length() % 8) {
        QString dlgTitle = "文件错误";
        QString strInfo = "密文文件字节长度错误，文件可能被修改过！";
        QMessageBox::critical(this, dlgTitle, strInfo);
        return;
    }
    //每64bit解密一次
    while(cipherBytes.length() > 0) {
        unsigned char plainText[8];
        unsigned char cipherText[8];
        memcpy(cipherText, cipherBytes, 8);
        cipherBytes.remove(0, 8);
        if (des_setup(key, 8, 0, &deskey) != CRYPT_OK){
            QString dlgTitle = "解密错误";
            QString strInfo = "解密密钥设置错误，未知原因！";
            QMessageBox::critical(this, dlgTitle, strInfo);
            return;
        }
        des_ecb_decrypt(cipherText, plainText, &deskey);
        QByteArray plainBytes;
        plainBytes.resize(8);
        memcpy(plainBytes.data(), plainText, 8);
        plainTextFile.write(plainBytes);
    }
    plainTextFile.close();
    cipherTextFile.close();
    QString successTitle = "解密成功";
    QString successInfo = "解密成功！文件保存在";
    successInfo.append(plainTextFileName);
    QMessageBox::information(this, successTitle, successInfo);
}
