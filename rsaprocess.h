#ifndef RSAPROCESS_H
#define RSAPROCESS_H

#include <QtGlobal>
#include <QtCore>

#include "openssl/rsa.h"

class RSAProcess
{
private:
    int              m_padding;

protected:
#if OPENSSL_VERSION_MAJOR > 1
    EVP_PKEY *createRSA(char *key, bool public_key);

    int getBlockSize(EVP_PKEY *key);

    bool encrypt_data(bool public_key, EVP_PKEY *key, const QByteArray in, QByteArray &out);
    bool decrypt_data(bool public_key, EVP_PKEY *key, const QByteArray in, QByteArray &out);
#else
    RSA *createRSA(char *key, bool public_key);

    int getBlockSize(RSA *rsa);

    bool encrypt_data(bool public_key, RSA *rsa, const QByteArray in, QByteArray &out);
    bool decrypt_data(bool public_key, RSA *rsa, const QByteArray in, QByteArray &out);
#endif

    void printError(QString prefix);
    void printError();

public:
    explicit RSAProcess();
    virtual ~RSAProcess();

    bool encrypt(bool public_key, QByteArray key, const QByteArray in, QByteArray &out);
    bool decrypt(bool public_key, QByteArray key, const QByteArray in, QByteArray &out);

    void generateRSAKey(QByteArray &private_key, QByteArray &public_key);
};

#endif // RSAPROCESS_H
