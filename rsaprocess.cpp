#include "rsaprocess.h"

#include <QtDebug>

#include "openssl/pem.h"
#include "openssl/err.h"

#if OPENSSL_VERSION_MAJOR > 1
#include "openssl/encoder.h"
#include "openssl/decoder.h"
#endif

#define KEY_SIZE                    2048

#define SELF_TEST_DATA_SIZE         4096

#if OPENSSL_VERSION_MAJOR > 1
EVP_PKEY *RSAProcess::createRSA(char *key, bool public_key)
{
    // load the input key to BIO
    BIO *keybio = BIO_new_mem_buf(key, -1);

    if(keybio == NULL) {
        qDebug() << __func__ << "> RSAProcess: Cannot create BIO";
        printError();
        return 0;
    }

    EVP_PKEY *pEVPKey = NULL;

//    OSSL_DECODER_CTX *decoder_ctx = NULL;

//    if(public_key) {
//        decoder_ctx = OSSL_DECODER_CTX_new_for_pkey(&pEVPKey, "PEM", NULL, "RSA", EVP_PKEY_PUBLIC_KEY, NULL, NULL);
//    } else {
//        decoder_ctx = OSSL_DECODER_CTX_new_for_pkey(&pEVPKey, "PEM", NULL, "RSA", EVP_PKEY_PRIVATE_KEY, NULL, NULL);
//    }

//    OSSL_DECODER_from_bio(decoder_ctx, keybio);

//    OSSL_DECODER_CTX_free(decoder_ctx);

    if(public_key) {
        PEM_read_bio_PUBKEY(keybio, &pEVPKey, NULL, NULL);
    } else {
        PEM_read_bio_PrivateKey(keybio, &pEVPKey, NULL, NULL);
    }

    if(pEVPKey == NULL) {
        qDebug() << __func__ << "> RSAProcess: Cannot create RSA";
        printError();
        return 0;
    }

    return pEVPKey;
}
#else
RSA *RSAProcess::createRSA(char *key, bool public_key)
{
    RSA *rsa = NULL;
    BIO *keybio = 0;

    keybio = BIO_new_mem_buf(key, -1);

    if(keybio == NULL) {
        qDebug() << "Cannot create BIO";
        printError();
        return 0;
    }

    if(public_key) {
        rsa = PEM_read_bio_RSAPublicKey(keybio, 0, 0, 0);
    } else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, 0, 0, 0);
    }

    BIO_free(keybio);

    if(rsa == NULL) {
        qDebug() << "Cannot create RSA";
        printError();
        return 0;
    }

    return rsa;
}
#endif

void RSAProcess::printError(QString prefix)
{
    char buffer[1024];

    ERR_error_string(ERR_get_error(), buffer);
    QString text(buffer);

    if(prefix.isEmpty()) {
        qDebug() << __func__ << "> RSAProcess: Error:" << text;
    } else {
        qDebug() << __func__ << "> RSAProcess: [" << prefix << "] Error:" << text;
    }
}

void RSAProcess::printError()
{
    printError("");
}

#if OPENSSL_VERSION_MAJOR > 1
int RSAProcess::getBlockSize(EVP_PKEY *key)
{
    if(!key) return 0;

    int size = 0;

    size = EVP_PKEY_get_size(key);

    switch(this->m_padding) {
    case RSA_PKCS1_PADDING:
        size -= RSA_PKCS1_PADDING_SIZE;
        break;
    case RSA_PKCS1_OAEP_PADDING:
        size -= 41;
        break;
    default:
        break;
    }

    return size;
}
#else
int RSAProcess::getBlockSize(RSA *rsa)
{
    int size = 0;

    if(rsa) {
        size = RSA_size(rsa);

        switch(this->m_padding) {
        case RSA_PKCS1_PADDING:
            size -= RSA_PKCS1_PADDING_SIZE;
            break;
        case RSA_PKCS1_OAEP_PADDING:
            size -= 41;
            break;
        default:
            break;
        }
    }

    return size;
}
#endif

RSAProcess::RSAProcess()
{
    ERR_load_crypto_strings();

    this->m_padding = RSA_PKCS1_PADDING;
}

RSAProcess::~RSAProcess()
{
    ERR_free_strings();
}

#if OPENSSL_VERSION_MAJOR > 1
bool RSAProcess::encrypt_data(bool public_key, EVP_PKEY *key, const QByteArray in, QByteArray &out)
{
    out.clear();

    if(!key) return false;

    if(in.isEmpty()) return false;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);

    if(!ctx) return false;

    EVP_PKEY_CTX_set_rsa_padding(ctx, this->m_padding);

    size_t output_block_size = EVP_PKEY_get_size(key);
    unsigned char *out_buffer = new unsigned char[output_block_size];

    size_t total_size = in.size();
    size_t pos = 0;
    unsigned char *pSrc = (unsigned char *)in.data();

    int block_size = getBlockSize(key);

    if(public_key) {
        EVP_PKEY_encrypt_init(ctx);

        while(pos < total_size) {
            int len = total_size - pos;

            if(len > block_size) {
                len = block_size;
            }

            size_t result_len = -1;

            int result = EVP_PKEY_encrypt(ctx, out_buffer, &result_len, pSrc + pos, len);

            if(result > 0) {
                out.append((char*)out_buffer, result_len);
            } else {
                printError(__func__);
            }

            pos += len;
        } // while loop
    } else {
        EVP_PKEY_sign_init(ctx);

        while(pos < total_size) {
            int len = total_size - pos;

            if(len > block_size) {
                len = block_size;
            }

            size_t result_len = -1;

            int result = EVP_PKEY_sign(ctx, out_buffer, &result_len, pSrc + pos, len);

            if(result > 0) {
                out.append((char*)out_buffer, result_len);
            } else {
                printError(__func__);
            }

            pos += len;
        } // while loop
    }

    delete []out_buffer;

    EVP_PKEY_CTX_free(ctx);

    return true;
}

bool RSAProcess::decrypt_data(bool public_key, EVP_PKEY *key, const QByteArray in, QByteArray &out)
{
    out.clear();

    if(!key) return false;

    if(in.isEmpty()) return false;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);

    if(!ctx) return false;

    EVP_PKEY_CTX_set_rsa_padding(ctx, this->m_padding);

    size_t output_block_size = EVP_PKEY_get_size(key);
    size_t total_size = in.size();

    if(total_size < output_block_size) {
        return false;
    }

    unsigned char *out_buffer = new unsigned char[output_block_size];

    size_t pos = 0;
    unsigned char *pSrc = (unsigned char *)in.data();

    if(public_key) {
        EVP_PKEY_verify_recover_init(ctx);

        while(pos < total_size) {
            // read size
            size_t result_len = -1;

            int result = EVP_PKEY_verify_recover(ctx, out_buffer, &result_len, pSrc + pos, output_block_size);

            pos += output_block_size;

            if(result > 0) {
                out.append((char*)out_buffer, result_len);
            } else {
                printError(__func__);
            }
        } // while loop
    } else {
        EVP_PKEY_decrypt_init(ctx);

        while(pos < total_size) {
            // read size
            size_t result_len = -1;

            int result = EVP_PKEY_decrypt(ctx, out_buffer, &result_len, pSrc + pos, output_block_size);

            pos += output_block_size;

            if(result > 0) {
                out.append((char*)out_buffer, result_len);
            } else {
                printError(__func__);
            }
        } // while loop
    }

    delete []out_buffer;

    EVP_PKEY_CTX_free(ctx);

    return true;
}
#else
bool RSAProcess::encrypt_data(bool public_key, RSA *rsa, const QByteArray in, QByteArray &out)
{
    out.clear();

    if(in.isEmpty()) return false;

    if(!rsa) return false;

    int output_block_size = RSA_size(rsa);
    unsigned char *out_buffer = new unsigned char[output_block_size];

    int total_size = in.size();
    int pos = 0;
    unsigned char *pSrc = (unsigned char *)in.data();

    int block_size = getBlockSize(rsa);

    while(pos < total_size) {
        int len = total_size - pos;

        if(len > block_size) {
            len = block_size;
        }

        int result_len = -1;

        if(public_key) {
            result_len = RSA_public_encrypt(len, pSrc + pos, out_buffer, rsa, this->m_padding);
        } else {
            result_len = RSA_private_encrypt(len, pSrc + pos, out_buffer, rsa, this->m_padding);
        }

        if(result_len == output_block_size) {
            out.append((char*)out_buffer, result_len);
        }

        pos += len;
    } // while loop

    delete []out_buffer;

    return true;
}

bool RSAProcess::decrypt_data(bool public_key, RSA *rsa, const QByteArray in, QByteArray &out)
{
    out.clear();

    if(in.isEmpty()) return false;

    if(!rsa) return false;

    int output_block_size = RSA_size(rsa);
    int total_size = in.size();

    if(total_size < output_block_size) return false;

    unsigned char *out_buffer = new unsigned char[output_block_size];

    int pos = 0;
    unsigned char *pSrc = (unsigned char *)in.data();

    while(pos < total_size) {
        // read size
        int result_len = -1;

        if(public_key) {
            result_len = RSA_public_decrypt(output_block_size, pSrc + pos, out_buffer, rsa, this->m_padding);
        } else {
            result_len = RSA_private_decrypt(output_block_size, pSrc + pos, out_buffer, rsa, this->m_padding);
        }

        pos += output_block_size;

        if(result_len > -1) {
            out.append((char*)out_buffer, result_len);
        }
    } // while loop

    delete []out_buffer;

    return true;
}
#endif

#if OPENSSL_VERSION_MAJOR > 1
bool RSAProcess::encrypt(bool public_key, QByteArray key, const QByteArray in, QByteArray &out)
{
    out.clear();

    if(in.isEmpty()) return false;

    if(key.isEmpty()) return false;

    EVP_PKEY *rsa_key = createRSA(key.data(), public_key);

    if(!rsa_key) return false;

    bool ret_flag = encrypt_data(public_key, rsa_key, in, out);

    EVP_PKEY_free(rsa_key);

    return ret_flag;
}

bool RSAProcess::decrypt(bool public_key, QByteArray key, const QByteArray in, QByteArray &out)
{
    out.clear();

    if(in.isEmpty()) return false;

    if(key.isEmpty()) return false;

    EVP_PKEY *rsa_key = createRSA(key.data(), public_key);

    if(!rsa_key) return false;

    bool ret_flag = decrypt_data(public_key, rsa_key, in, out);

    EVP_PKEY_free(rsa_key);

    return ret_flag;
}
#else
bool RSAProcess::encrypt(bool public_key, QByteArray key, const QByteArray in, QByteArray &out)
{
    out.clear();

    if(in.isEmpty()) return false;

    if(key.isEmpty()) return false;

    RSA *rsa_key = createRSA(key.data(), public_key);

    if(!rsa_key) return false;

    bool ret_flag = encrypt_data(public_key, rsa_key, in, out);

    RSA_free(rsa_key);

    return ret_flag;
}

bool RSAProcess::decrypt(bool public_key, QByteArray key, const QByteArray in, QByteArray &out)
{
    out.clear();

    if(in.isEmpty()) return false;

    if(key.isEmpty()) return false;

    RSA *rsa_key = createRSA(key.data(), public_key);

    if(!rsa_key) return false;

    bool ret_flag = decrypt_data(public_key, rsa_key, in, out);

    RSA_free(rsa_key);

    return ret_flag;
}
#endif

#if OPENSSL_VERSION_MAJOR > 1
void RSAProcess::generateRSAKey(QByteArray &private_key, QByteArray &public_key)
{
    EVP_PKEY *pEVPKey = EVP_RSA_gen(KEY_SIZE);

    BUF_MEM *pBMem = 0;

    // private key
    BIO *pBIO_private = BIO_new(BIO_s_mem());

    OSSL_ENCODER_CTX *ossl_ctx_private = OSSL_ENCODER_CTX_new_for_pkey(pEVPKey, EVP_PKEY_PRIVATE_KEY, "PEM", NULL, NULL);

    OSSL_ENCODER_to_bio(ossl_ctx_private, pBIO_private);

    BIO_get_mem_ptr(pBIO_private, &pBMem);

    private_key.clear();
    private_key.append(pBMem->data, pBMem->length);

    OSSL_ENCODER_CTX_free(ossl_ctx_private);
    BIO_free(pBIO_private);

    // public key
    BIO *pBIO_public = BIO_new(BIO_s_mem());

    OSSL_ENCODER_CTX *ossl_ctx_public = OSSL_ENCODER_CTX_new_for_pkey(pEVPKey, EVP_PKEY_PUBLIC_KEY, "PEM", NULL, NULL);

    OSSL_ENCODER_to_bio(ossl_ctx_public, pBIO_public);

    BIO_get_mem_ptr(pBIO_public, &pBMem);

    public_key.clear();
    public_key.append(pBMem->data, pBMem->length);

    OSSL_ENCODER_CTX_free(ossl_ctx_public);
    BIO_free(pBIO_public);

    EVP_PKEY_free(pEVPKey);
}
#else
void RSAProcess::generateRSAKey(QByteArray &private_key, QByteArray &public_key)
{
    RSA *pRSA = RSA_new();
    BIGNUM *pBNe = BN_new();
    BN_set_word(pBNe, RSA_3);
    RSA_generate_key_ex(pRSA, KEY_SIZE, pBNe, NULL);
    BN_free(pBNe);

    BUF_MEM *pBMem = 0;

    // private key
    BIO *pBIO_private = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pBIO_private, pRSA, NULL, NULL, 0, NULL, NULL);

    BIO_get_mem_ptr(pBIO_private, &pBMem);

    private_key.append(pBMem->data, pBMem->length);

    BIO_free(pBIO_private);

    // public key
    BIO *pBIO_public = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPublicKey(pBIO_public, pRSA);

    BIO_get_mem_ptr(pBIO_public, &pBMem);

    public_key.append(pBMem->data, pBMem->length);

    BIO_free(pBIO_public);

    RSA_free(pRSA);
}
#endif
