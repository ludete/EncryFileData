/**
 * @file cert_openssl.c
 * @brief 利用openssl api处理证书
 * @author zy
 * @date 2014-10-11 modify
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/pkcs12.h>


#if 0

#define CONTEXT_MAX_NUM 7
#define SERIAL_RAND_BITS 64

/**
 * 描  述: 获取X509对象
 * 参  数: @param[IN] cert_file  证书
 * 返回值: X509对象
 */
X509* read_public_cert(const char* cert_file)
{
    X509 *x509 = NULL;

    FILE *fp = fopen (cert_file, "r");   
    if(!fp)
    {
        printf("read_public_cert, open cert failed!");
        return NULL; 
    }

    x509 = PEM_read_X509(fp, NULL, 0, NULL);

    if(x509 == NULL) 
    {  
        printf("read_public_cert, get x509 failed!");
        return NULL;   
    }

	if(fp)				fclose(fp);
    return x509;
}

/**
 * 描  述: 获取公钥
 * 参  数: @param[IN] cert_file  证书
 * 返回值: 公钥
 */
EVP_PKEY * read_public_key(const char* cert_file)
{
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;

    FILE *fp = fopen (cert_file, "r");   
    if(!fp)
    {
        printf("read_public_key, open cert failed!");
        return NULL;
    }

    x509 = PEM_read_X509(fp, NULL, 0, NULL);

    if(x509 == NULL) 
    {  
        printf("read_public_key, get x509 failed!");
        return NULL;   
    }

    fclose(fp);

    pkey = X509_extract_key(x509);
    X509_free(x509);

    if(pkey == NULL)
    {
        printf("read_public_key, get key failed!");
    }

    return pkey; 
}

/**
 * 描  述: 获取私钥
 * 参  数: @param[IN] key_file  证书
 * 返回值: 私钥
 */
EVP_PKEY *read_private_key(const char* key_file)
{
    EVP_PKEY *pkey = NULL;

    FILE *fp = fopen(key_file, "r");
    if(!fp)
    {
        printf("read_private_key, open key failed!");
        return NULL;
    }

    pkey = PEM_read_PrivateKey(fp, NULL, 0, NULL);

    fclose(fp);

    if (pkey == NULL)
    {
        printf("read_private_key, get key failed!");
    }

    return pkey;
}

/**
 * 描  述: 添加证书内容
 * 参  数: @param[IN] name  X509_NAME
 @param[IN] ctx   使用者信息
 @param[IN] num   ctx数组长度
 * 返回值: 1: 成功 0: 失败
 */
int add_cert_ctx(X509_NAME* name, char* ctx[], int num)
{
    int i = 0;
    int max = 0;

    int item[] = {NID_commonName, NID_countryName,
        NID_stateOrProvinceName, NID_localityName, 
        NID_organizationName, NID_organizationalUnitName,
        NID_pkcs9_emailAddress};

    max = sizeof(item)/sizeof(item[0]);
    max = max > num ? num : max;

    for(i=0; i<max; ++i)
    {
        if(!X509_NAME_add_entry_by_NID(name, item[i], MBSTRING_UTF8, ctx[i], -1, -1, 0))
        {
            printf("add_cert_ctx, add entry:%d to %s failed!", item[i], ctx[i]);
            return 0;
        }
    }

    return 1;
}

/**
 * 描  述: 创建证书密钥
 * 参  数: @param[OUT] pkey  EVP_PKEY
 @param[IN] bits   密钥长度
 * 返回值: 1: 成功 0: 失败
 */
int create_client_key(EVP_PKEY** pkey, int bits)
{
    RSA *rsa = NULL;
    EVP_PKEY *pk = NULL;

    if((pk = EVP_PKEY_new()) == NULL)
    {
        printf("create_client_key, gen new key failed!");
        goto err;
    }

    rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
    if(!EVP_PKEY_assign_RSA(pk, rsa))
    {
        printf("create_client_key, assign key failed!");
        EVP_PKEY_free(pk);
        goto err;
    }
    rsa = NULL;

    *pkey = pk;
    return 1;

err:
    return 0;
}

/**
 * 描  述: CA签发证书
 * 参  数: @param[OUT] x509p      EVP_PKEY
 @param[OUT] pkey       X509
 @param[IN] ca_file      CA
 @param[IN] ca_key_file   CA密钥
 @param[IN] serial      序列号
 @param[IN] days        过期时长
 * 返回值: 1: 成功 0: 失败
 */
int create_ca_signed_crt(X509** x509p, EVP_PKEY** pkey, 
                         const char* ca_file, const char* ca_key_file, const char* user, const int serial, const int days)
{
    X509* x = NULL;
    EVP_PKEY* pk = NULL;
    X509* xca = NULL;
    EVP_PKEY* xca_key = NULL;
    X509_NAME* name = NULL;
    char* ctx[] = {(char*)user, "bb", "cc", "dd", "ee", "ff", "ff@sf.com"};

    if(!create_client_key(&pk, 2048))
    {
        printf("create_ca_signed_crt, gen key failed!");
        goto err;
    }

    if((x = X509_new()) == NULL)
    {
        printf("create_ca_signed_crt, gen x509 failed!");
        goto err;
    }

    xca = read_public_cert(ca_file);
    xca_key = read_private_key(ca_key_file);
    if(!X509_check_private_key(xca, xca_key))
    {
        printf("create_ca_signed_crt, check ca %s and key %s failed!", ca_file, ca_key_file);
        goto err;
    }

    if(!X509_set_issuer_name(x, X509_get_subject_name(xca)))
    {
        printf("create_ca_signed_crt, set issuer failed!");
        goto err;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(x), serial);

    if(X509_gmtime_adj(X509_get_notBefore(x), 0L) == NULL)
    {
        printf("create_ca_signed_crt, set cert begin time failed!");
        goto err;
    }

    if(X509_gmtime_adj(X509_get_notAfter(x), (long)60*60*24*days) == NULL)
    {
        printf("create_ca_signed_crt, set cert expired time failed!");
        goto err;
    }

    if(!X509_set_pubkey(x, pk))
    {
        printf("create_ca_signed_crt, set pubkey failed!");
        goto err;
    }

    name = X509_get_subject_name(x);
    if(!add_cert_ctx(name, ctx, CONTEXT_MAX_NUM))
    {
        printf("create_ca_signed_crt, add entry failed!");
        goto err;
    }

    if(!X509_sign(x, xca_key, EVP_sha1()))
    {
        printf("create_ca_signed_crt, sign cert failed!");
        goto err;
    }

    *pkey = pk;
    *x509p = x;
    return 1;
err:
    if(x)
        X509_free(x);
    if(pk)
        EVP_PKEY_free(pk);

    return 0;
}

/**
 * 描  述: 创建P12证书
 * 参  数: 
 @param[IN] p12_file     p12
 @param[IN] p12_passwd   p12密码
 @param[IN] ca_file      CA证书
 @param[IN] ca_key_file  CA密钥
 @param[IN] serial       序列号
 @param[IN] days         过期时长
 * 返回值: 1: 成功 0: 失败
 */
int create_p12_cert(char* p12_file, char* p12_passwd, 
                    const char* ca_file, const char* ca_key_file, const char* user, const int serial, const int days)
{
    int ret = 0;
    PKCS12* p12 = NULL;
    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;
    FILE *fp = NULL;
    BIO *mem = NULL;
    char *mem_out = NULL;
    long len = 0;

    SSLeay_add_all_algorithms();

    if(!create_ca_signed_crt(&cert, &pkey, ca_file, ca_key_file, user, serial, days))
    {
        printf("create_p12_cert, create signed cert failed!");
        goto err;
    }

    p12 = PKCS12_create(p12_passwd, NULL, pkey, cert, NULL, 0,0,0,0,0);
    if(!p12)
    {
        printf("create_p12_cert, create p12 object failed!");
        goto err;
    }

   
    fp = fopen(p12_file, "wb");
    if(!fp)
    {
        printf("create_p12_cert, open/create p12 file failed!");
        goto err;
    }

    mem = BIO_new(BIO_s_mem());
    if(!mem)
    {
        printf("create_p12_cert, BIO_new failed!");
        goto err;
    }

    i2d_PKCS12_bio(mem, p12);
    len = BIO_get_mem_data(mem, &mem_out);
    fwrite(mem_out, sizeof(char), len, fp);

    ret = 1;
err:
    if(cert)
        X509_free(cert);
    if(pkey)
        EVP_PKEY_free(pkey);
    if (p12)
        PKCS12_free(p12);
    if (mem)
        BIO_free(mem);
    if(fp)
        fclose(fp);

    EVP_cleanup();
    return ret;
}

//openssl smime -sign -in unsign.mc -out signed.mc -signer ssl.crt -inkey ssl.key -certfile server.crt -outform der -nodetach
int sign_mobile_config(const char *inmc, int inlen, char **outmc, int *outlen,
                       char *certfile, char *signerfile, char *keyfile)
{
    X509 *signer = NULL;
    EVP_PKEY *key = NULL;
    PKCS7 *p7 = NULL;
    X509 *cert = NULL;

    BIO *in = NULL;
    BIO *out = NULL;
    STACK_OF(X509) * other = NULL;

    int mclen = 0;
    char *mc = NULL;
    char *tmp = NULL;

    SSLeay_add_all_algorithms();

    // in 
    in = BIO_new_mem_buf((char*)inmc, inlen); // BIO_write
    if (!in)
    {
        return -1;
    }

    cert = read_public_cert(certfile);

    other = sk_X509_new_null();
    sk_X509_push(other, cert);


    signer = read_public_cert(signerfile);
    key = read_private_key(keyfile);

    if (!X509_check_private_key(signer, key))
    {
        printf("x509 check failed!\n");
        return -1;
    }

    p7 = PKCS7_sign(signer, key, other, in, 0);
    if (!p7)
        goto end;

    // out
    out = BIO_new(BIO_s_mem());
    i2d_PKCS7_bio(out, p7);
    mclen = BIO_get_mem_data(out, &tmp);// BIO_read
    mc = (char*)malloc(mclen);
    memcpy(mc, tmp, mclen);
    *outmc = mc;
    *outlen = mclen;

end:
    sk_X509_pop_free(other, X509_free);
    X509_free(signer);
    EVP_PKEY_free(key);
    PKCS7_free(p7);
    BIO_free(in);
    BIO_free_all(out);

    return 0;
}
#endif

void testWriteRSA2PEM()
{
    //生成密钥对
    RSA *r = RSA_new();
    int bits = 2048;
    BIGNUM *e = BN_new();
    BN_set_word(e, 65537);
    RSA_generate_key_ex(r, bits, e, NULL);
    
    RSA_print_fp(stdout, r, 0);
    
    BIO *out;
    out = BIO_new_file("./opriv.pem","w");
    //这里生成的私钥没有加密，可选加密
    int ret = PEM_write_bio_RSAPrivateKey(out, r, NULL, NULL, 0, NULL, NULL);
    printf("writepri:%d\n",ret);
    BIO_flush(out);
    BIO_free(out);
    
    out = BIO_new_file("./opub.pem","w");
    ret = PEM_write_bio_RSAPublicKey(out, r);
    printf("writepub:%d\n",ret);
    BIO_flush(out);
    BIO_free(out);
    
    BN_free(e);
    RSA_free(r);

}





int main()
{
	testWriteRSA2PEM();

//    create_p12_cert("/root/out.p12", "1234", "/root/server_mdm.crt", "/root/server_mdm.key", "test", 0, 3650);
    return 0;
}

