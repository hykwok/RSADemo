#include "mainwindow.h"

QGroupBox *MainWindow::createKeyGroup()
{
    QGroupBox *group = new QGroupBox(tr("RSA Keys"), this);

    this->edit_private_key = new QTextEdit(group);
    this->edit_public_key = new QTextEdit(group);

    QPushButton *btn_gen_key = new QPushButton(tr("Generate Keys"), group);
    connect(btn_gen_key, SIGNAL(clicked(bool)), this, SLOT(clicked_gen_keys(bool)));

    QGridLayout *layout_group = new QGridLayout;
    group->setLayout(layout_group);

    layout_group->addWidget(new QLabel(tr("Private Key"), group), 0, 0);
    layout_group->addWidget(new QLabel(tr("Public Key"), group), 0, 1);

    layout_group->addWidget(this->edit_private_key, 1, 0);
    layout_group->addWidget(this->edit_public_key, 1, 1);

    layout_group->addWidget(btn_gen_key, 2, 0, 1, 2);

    return group;
}

QGroupBox *MainWindow::createEncryptGroup()
{
    QGroupBox *group = new QGroupBox(tr("Encrypt"), this);

    this->edit_source_encrypt = new QTextEdit(group);

    this->edit_result_encrypt = new QTextEdit(group);
    this->edit_result_encrypt->setReadOnly(true);

    this->btn_private_key_encrypt = new QRadioButton(tr("Use Private Key"), group);
    connect(this->btn_private_key_encrypt, SIGNAL(clicked(bool)), this, SLOT(clicked_private_key_encrypt(bool)));

    this->btn_public_key_encrypt = new QRadioButton(tr("Use Public Key"), group);
    connect(this->btn_public_key_encrypt, SIGNAL(clicked(bool)), this, SLOT(clicked_public_key_encrypt(bool)));

    QPushButton *btn_start_encrypt = new QPushButton(tr("Start Encrypt"), group);
    connect(btn_start_encrypt, SIGNAL(clicked(bool)), this, SLOT(clicked_start_encrypt(bool)));

    QPushButton *btn_copy_encrypt = new QPushButton(tr("Copy result to decrypt region"), group);
    connect(btn_copy_encrypt, SIGNAL(clicked(bool)), this, SLOT(clicked_copy_result_encrypt(bool)));

    QPushButton *btn_clear = new QPushButton(tr("Clear"), group);
    connect(btn_clear, SIGNAL(clicked(bool)), this, SLOT(clicked_clear_source_encrypt(bool)));

    QGridLayout *layout_group = new QGridLayout;
    group->setLayout(layout_group);

    layout_group->addWidget(new QLabel(tr("Source"), group), 0, 0, 1, 3);
    layout_group->addWidget(this->edit_source_encrypt, 1, 0, 1, 3);

    layout_group->addWidget(new QLabel(tr("Result (Base64 Encoding)"), group), 2, 0, 1, 3);
    layout_group->addWidget(this->edit_result_encrypt, 3, 0, 1, 3);

    layout_group->addWidget(this->btn_private_key_encrypt, 4, 0);
    layout_group->addWidget(this->btn_public_key_encrypt, 4, 1);

    layout_group->addWidget(btn_start_encrypt, 5, 0);
    layout_group->addWidget(btn_copy_encrypt, 5, 1);
    layout_group->addWidget(btn_clear, 5, 2);

    this->btn_public_key_encrypt->setChecked(true);

    return group;
}

QGroupBox *MainWindow::createDecryptGroup()
{
    QGroupBox *group = new QGroupBox(tr("Decrypt"), this);

    this->edit_source_decrypt = new QTextEdit(group);

    this->edit_result_decrypt = new QTextEdit(group);
    this->edit_result_decrypt->setReadOnly(true);

    this->btn_private_key_decrypt = new QRadioButton(tr("Use Private Key"), group);
    connect(this->btn_private_key_decrypt, SIGNAL(clicked(bool)), this, SLOT(clicked_private_key_decrypt(bool)));

    this->btn_public_key_decrypt = new QRadioButton(tr("Use Public Key"), group);
    connect(this->btn_public_key_decrypt, SIGNAL(clicked(bool)), this, SLOT(clicked_public_key_decrypt(bool)));

    QPushButton *btn_start_decrypt = new QPushButton(tr("Start Decrypt"), group);
    connect(btn_start_decrypt, SIGNAL(clicked(bool)), this, SLOT(clicked_start_decrypt(bool)));

    QPushButton *btn_check_result = new QPushButton(tr("Check Result"), group);
    connect(btn_check_result, SIGNAL(clicked(bool)), this, SLOT(clicked_check_result_decrypt(bool)));

    QPushButton *btn_clear = new QPushButton(tr("Clear"), group);
    connect(btn_clear, SIGNAL(clicked(bool)), this, SLOT(clicked_clear_source_decrypt(bool)));

    QGridLayout *layout_group = new QGridLayout;
    group->setLayout(layout_group);

    layout_group->addWidget(new QLabel(tr("Source (Base64 Encoding)"), group), 0, 0, 1, 3);
    layout_group->addWidget(this->edit_source_decrypt, 1, 0, 1, 3);

    layout_group->addWidget(new QLabel(tr("Result"), group), 2, 0, 1, 3);
    layout_group->addWidget(this->edit_result_decrypt, 3, 0, 1, 3);

    layout_group->addWidget(this->btn_private_key_decrypt, 4, 0);
    layout_group->addWidget(this->btn_public_key_decrypt, 4, 1);

    layout_group->addWidget(btn_start_decrypt, 5, 0);
    layout_group->addWidget(btn_check_result, 5, 1);
    layout_group->addWidget(btn_clear, 5, 2);

    this->btn_private_key_decrypt->setChecked(true);

    return group;
}

void MainWindow::setupGUI()
{
    QFrame *panel_main = new QFrame(this);
    this->setCentralWidget(panel_main);

    QVBoxLayout *layout_main = new QVBoxLayout;
    panel_main->setLayout(layout_main);

    QGroupBox *group_key = createKeyGroup();
    QGroupBox *group_encrypt = createEncryptGroup();
    QGroupBox *group_decrypt = createDecryptGroup();

    layout_main->addWidget(group_key);

    QHBoxLayout *layout_input = new QHBoxLayout;
    layout_input->addWidget(group_encrypt);
    layout_input->addWidget(group_decrypt);

    layout_main->addLayout(layout_input);
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setupGUI();
}

MainWindow::~MainWindow()
{
}

void MainWindow::clicked_gen_keys(bool)
{
    QByteArray private_key;
    QByteArray public_key;

    this->m_rsa_process.generateRSAKey(private_key, public_key);

    QString str_private_key = QString::fromUtf8(private_key);
    QString str_public_key = QString::fromUtf8(public_key);

    this->edit_private_key->setPlainText(str_private_key);
    this->edit_public_key->setPlainText(str_public_key);
}

void MainWindow::clicked_start_encrypt(bool)
{
    QString source_text = this->edit_source_encrypt->toPlainText();

    if(source_text.isEmpty()) return;

    // get data
    QByteArray source_raw_data = source_text.toUtf8();

    // set key
    bool public_key = false;
    QString key;

    if(this->btn_public_key_encrypt->isChecked()) {
        public_key = true;
        key = this->edit_public_key->toPlainText();
    } else {
        public_key = false;
        key = this->edit_private_key->toPlainText();
    }

    if(key.isEmpty()) return;

    QByteArray key_raw_data = key.toUtf8();

    // start process
    QByteArray result_raw_data;
    this->m_rsa_process.encrypt(public_key, key_raw_data, source_raw_data, result_raw_data);

    // show result
    QString result_text = QString::fromUtf8(result_raw_data.toBase64());
    this->edit_result_encrypt->setPlainText(result_text);
}

void MainWindow::clicked_copy_result_encrypt(bool)
{
    QString text = this->edit_result_encrypt->toPlainText();
    this->edit_source_decrypt->setPlainText(text);
}

void MainWindow::clicked_clear_source_encrypt(bool)
{
    this->edit_source_encrypt->setPlainText("");
}

void MainWindow::clicked_start_decrypt(bool)
{
    QString source_text = this->edit_source_decrypt->toPlainText();

    if(source_text.isEmpty()) return;

    // get data
    QByteArray source_raw_data = QByteArray::fromBase64(source_text.toUtf8());

    // set key
    bool public_key = false;
    QString key;

    if(this->btn_public_key_decrypt->isChecked()) {
        public_key = true;
        key = this->edit_public_key->toPlainText();
    } else {
        public_key = false;
        key = this->edit_private_key->toPlainText();
    }

    if(key.isEmpty()) return;

    QByteArray key_raw_data = key.toUtf8();

    // start process
    QByteArray result_raw_data;
    this->m_rsa_process.decrypt(public_key, key_raw_data, source_raw_data, result_raw_data);

    // show result
    QString result_text = QString::fromUtf8(result_raw_data);
    this->edit_result_decrypt->setPlainText(result_text);
}

void MainWindow::clicked_check_result_decrypt(bool)
{
    QString source = this->edit_source_encrypt->toPlainText();
    QString result = this->edit_result_decrypt->toPlainText();

    if(source == result) {
        QMessageBox::information(this, tr("Compare"), tr("Same"));
    } else {
        QMessageBox::critical(this, tr("Compare"), tr("Different"));
    }
}

void MainWindow::clicked_clear_source_decrypt(bool)
{
    this->edit_source_decrypt->setPlainText("");
}

void MainWindow::clicked_private_key_encrypt(bool)
{
    if(this->btn_private_key_encrypt->isChecked()) {
        if(this->btn_public_key_decrypt->isChecked()) return;

        this->btn_public_key_decrypt->setChecked(true);
    }
}

void MainWindow::clicked_public_key_encrypt(bool)
{
    if(this->btn_public_key_encrypt->isChecked()) {
        if(this->btn_private_key_decrypt->isChecked()) return;

        this->btn_private_key_decrypt->setChecked(true);
    }
}

void MainWindow::clicked_private_key_decrypt(bool)
{
    if(this->btn_private_key_decrypt->isChecked()) {
        if(this->btn_public_key_encrypt->isChecked()) return;

        this->btn_public_key_encrypt->setChecked(true);
    }
}

void MainWindow::clicked_public_key_decrypt(bool)
{
    if(this->btn_public_key_decrypt->isChecked()) {
        if(this->btn_private_key_encrypt->isChecked()) return;

        this->btn_private_key_encrypt->setChecked(true);
    }
}

