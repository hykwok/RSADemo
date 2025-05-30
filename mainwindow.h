#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtWidgets>

#include "rsaprocess.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

private:
    RSAProcess              m_rsa_process;

    QTextEdit               *edit_private_key;
    QTextEdit               *edit_public_key;

    QTextEdit               *edit_source_encrypt;
    QRadioButton            *btn_private_key_encrypt;
    QRadioButton            *btn_public_key_encrypt;
    QTextEdit               *edit_result_encrypt;

    QTextEdit               *edit_source_decrypt;
    QRadioButton            *btn_private_key_decrypt;
    QRadioButton            *btn_public_key_decrypt;
    QTextEdit               *edit_result_decrypt;

    QGroupBox *createKeyGroup();
    QGroupBox *createEncryptGroup();
    QGroupBox *createDecryptGroup();

    void setupGUI();

protected:

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void clicked_gen_keys(bool);

    void clicked_start_encrypt(bool);
    void clicked_copy_result_encrypt(bool);
    void clicked_clear_source_encrypt(bool);

    void clicked_start_decrypt(bool);
    void clicked_check_result_decrypt(bool);
    void clicked_clear_source_decrypt(bool);

    void clicked_private_key_encrypt(bool);
    void clicked_public_key_encrypt(bool);

    void clicked_private_key_decrypt(bool);
    void clicked_public_key_decrypt(bool);

};
#endif // MAINWINDOW_H
