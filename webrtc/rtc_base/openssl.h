/*
 *  Copyright 2013 The WebRTC Project Authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#ifndef WEBRTC_RTC_BASE_OPENSSL_H_
#define WEBRTC_RTC_BASE_OPENSSL_H_

#include <openssl/ssl.h>

#if (OPENSSL_VERSION_NUMBER < 0x10000000L)
#error OpenSSL is older than 1.0.0, which is the minimum supported version.
#endif

#ifdef __MINGW32__
struct evp_cipher_st {
    int nid;  //对称算法 nid
    int block_size;  //对称算法每次加解密的字节数
    /* Default value for variable length ciphers */
    int key_len;  //对称算法的密钥长度字节数
    int iv_len;  //对称算法的填充长度
    /* Various flags */
    unsigned long flags;  //用于标记
    /* init key */
    /*加密初始化函数，用来初始化 ctx， key 为对称密钥值， iv 为初始化向量， enc用于指明是要加密还是解密，这些信息存放在 ctx 中*/
    int (*init) (EVP_CIPHER_CTX *ctx, const unsigned char *key,
                 const unsigned char *iv, int enc);
    /* encrypt/decrypt data */
    /*对称运算函数，用于加密或解密*/
    int (*do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
    /* cleanup ctx 清除上下文函数*/
    int (*cleanup) (EVP_CIPHER_CTX *);
    /* how big ctx->cipher_data needs to be */
    int ctx_size;
    /* Populate a ASN1_TYPE with parameters */
    /*设置上下文参数函数*/
    int (*set_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Get parameters from a ASN1_TYPE */
    /*获取上下文参数函数*/
    int (*get_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Miscellaneous operations 控制函数,实现各种其他操作*/
    int (*ctrl) (EVP_CIPHER_CTX *, int type, int arg, void *ptr);
    /* Application data 用于存放应用数据*/
    void *app_data;
} /* EVP_CIPHER */ ;
struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    ENGINE *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided */
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    /* FIXME: Should this even exist? It appears unused */
    void *app_data;             /* application stuff */
    int key_len;                /* May change for variable length cipher */
    unsigned long flags;        /* Various flags */
    void *cipher_data;          /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */
} /* EVP_CIPHER_CTX */ ;
struct evp_md_ctx_st {
    const EVP_MD *digest;
    /* functional reference if 'digest' is ENGINE-provided */
    ENGINE *engine;            
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVP_MD */
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
} /* EVP_MD_CTX */ ;
/*
 * Type needs to be a bit field Sub-type needs to be for variations on the
 * method, as in, can it do arbitrary encryption....
 */
struct evp_pkey_st {
    int type;
    int save_type;
    int references;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    union {
        void *ptr;
# ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa;     /* RSA */
# endif
# ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
        struct dh_st *dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;   /* ECC */
# endif
    } pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    CRYPTO_RWLOCK *lock;
} /* EVP_PKEY */ ;
struct evp_md_st {
    int type;  //摘要类型，一般是摘要算法 NID
    int pkey_type;  //公钥类型，一般是签名算法 NID
    int md_size;  //摘要值大小，为字节数
    unsigned long flags;  //用于设置标记
    /*摘要算法初始化函数*/
    int (*init) (EVP_MD_CTX *ctx);
    /*多次摘要函数*/
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    /*摘要完结函数*/
    int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
    /*摘要上下文结构复制函数*/
    int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
    /*清除摘要上下文函数*/
    int (*cleanup) (EVP_MD_CTX *ctx);
    int block_size;
    int ctx_size;               /* how big does the ctx->md_data need to be */
    /* control function */
    int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
} /* EVP_MD */ ;
///////////////////////////////////////////////
struct bio_method_st
{
    int type;
    const char *name;
    int (*bwrite)(BIO *, const char *, int);
    int (*bread)(BIO *, char *, int);
    int (*bputs)(BIO *, const char *);
    int (*bgets)(BIO *, char *, int);
    long (*ctrl)(BIO *, int, long, void *);
    int (*create)(BIO *);
    int (*destroy)(BIO *);
    long (*callback_ctrl)(BIO *, int, bio_info_cb *);
};
struct bio_st
{
     BIO_METHOD *method;
     /* bio, mode, argp, argi, argl, ret */
     long (*callback)(struct bio_st *,int,const char *,int, long,long);
     char *cb_arg; /* first argument for the callback */
     int init;
     int shutdown;
     int flags;  /* extra storage */
     int retry_reason;
     int num;
     void *ptr;
     struct bio_st *next_bio;  /* used by filter BIOs */
     struct bio_st *prev_bio; /* used by filter BIOs */
     int references;
     unsigned long num_read;
     unsigned long num_write;
     CRYPTO_EX_DATA ex_data;
};
///////////////////////////////////////////
struct X509_name_st
{
    STACK_OF(X509_NAME_ENTRY) *entries;
    int modified;    /* true if 'bytes' needs to be built */
#ifndef OPENSSL_NO_BUFFER
    BUF_MEM *bytes;
#else
    char *bytes;
#endif
    /*    unsigned long hash; Keep the hash around for lookups */
    unsigned char *canon_enc;
    int canon_enclen;
}/*X509_NAME*/;
struct x509_st
{
    X509_CINF *cert_info;
    X509_ALGOR *sig_alg;
    ASN1_BIT_STRING *signature;
    int valid;
    int references;
    char *name;
    CRYPTO_EX_DATA ex_data;
    /* These contain copies of various extension values */
    long ex_pathlen;
    long ex_pcpathlen;
    unsigned long ex_flags;
    unsigned long ex_kusage;
    unsigned long ex_xkusage;
    unsigned long ex_nscert;
    ASN1_OCTET_STRING *skid;
    AUTHORITY_KEYID *akid;
    X509_POLICY_CACHE *policy_cache;
    STACK_OF(DIST_POINT) *crldp;
    STACK_OF(GENERAL_NAME) *altname;
    NAME_CONSTRAINTS *nc;
#ifndef OPENSSL_NO_RFC3779
    STACK_OF(IPAddressFamily) *rfc3779_addr;
    struct ASIdentifiers_st *rfc3779_asid;
#endif
#ifndef OPENSSL_NO_SHA
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
#endif
    X509_CERT_AUX *aux;
} /* X509 */;
#endif

#endif  // WEBRTC_RTC_BASE_OPENSSL_H_
