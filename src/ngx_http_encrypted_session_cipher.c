
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_encrypted_session_cipher.h"
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <stdint.h>


static uint64_t ngx_http_encrypted_session_ntohll(uint64_t n);
static uint64_t ngx_http_encrypted_session_htonll(uint64_t n);


ngx_int_t
ngx_http_encrypted_session_aes_mac_encrypt(
    ngx_http_encrypted_session_main_conf_t *emcf, ngx_pool_t *pool,
    ngx_log_t *log, const u_char *iv, size_t iv_len, const u_char *key,
    size_t key_len, const u_char *in, size_t in_len, ngx_uint_t expires,
    u_char **dst, size_t *dst_len)
{
    const EVP_CIPHER        *cipher;
    u_char                  *p, *data;
    int                      ret;
    size_t                   block_size, buf_size, data_size;
    int                      len;
    uint64_t                 expires_time;
    time_t                   now;

    if (key_len != ngx_http_encrypted_session_key_length) {
        return NGX_ERROR;
    }

    if (emcf->session_ctx == NULL) {
        emcf->session_ctx = EVP_CIPHER_CTX_new();
        if (emcf->session_ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "encrypted_session: aes_mac_encrypt: no memory");

            return NGX_ERROR;
        }
    }

    cipher = EVP_aes_256_cbc();

    block_size = EVP_CIPHER_block_size(cipher);

    data_size = in_len + sizeof(expires_time);

    buf_size = MD5_DIGEST_LENGTH /* for the digest */
               + (data_size + block_size - 1) /* for EVP_EncryptUpdate */
               + block_size; /* for EVP_EncryptFinal */

    p = ngx_palloc(pool, buf_size + data_size);
    if (p == NULL) {
        goto evp_error;
    }

    *dst = p;

    data = p + buf_size;

    ngx_memcpy(data, in, in_len);

    if (expires == 0) {
        expires_time = 0;
    } else {
        now = time(NULL);
        if (now == -1) {
            goto evp_error;
        }

        expires_time = (uint64_t) now + (uint64_t) expires;
    }

    dd("expires before encryption: %lld", (long long) expires_time);

    expires_time = ngx_http_encrypted_session_htonll(expires_time);

    ngx_memcpy(data + in_len, (u_char *) &expires_time, sizeof(expires_time));

    MD5(data, data_size, p);

    p += MD5_DIGEST_LENGTH;

    ret = EVP_EncryptInit(emcf->session_ctx, cipher, key, iv);
    if (!ret) {
        goto evp_error;
    }

    /* encrypt the raw input data */

    ret = EVP_EncryptUpdate(emcf->session_ctx, p, &len, data, data_size);
    if (!ret) {
        goto evp_error;
    }

    p += len;

    ret = EVP_EncryptFinal(emcf->session_ctx, p, &len);

    emcf->reset_cipher_ctx(emcf->session_ctx);

    if (!ret) {
        return NGX_ERROR;
    }

    p += len;

    *dst_len = p - *dst;

    if (*dst_len > buf_size) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "encrypted_session: aes_mac_encrypt: buffer error");

        return NGX_ERROR;
    }

    return NGX_OK;

evp_error:

    emcf->reset_cipher_ctx(emcf->session_ctx);

    return NGX_ERROR;
}


ngx_int_t
ngx_http_encrypted_session_aes_mac_decrypt(
    ngx_http_encrypted_session_main_conf_t *emcf, ngx_pool_t *pool,
    ngx_log_t *log, const u_char *iv, size_t iv_len, const u_char *key,
    size_t key_len, const u_char *in, size_t in_len, u_char **dst,
    size_t *dst_len)
{
    const EVP_CIPHER        *cipher;
    int                      ret;
    size_t                   block_size, buf_size;
    int                      len;
    u_char                  *p;
    const u_char            *digest;
    uint64_t                 expires_time;
    time_t                   now;

    u_char new_digest[MD5_DIGEST_LENGTH];

    if (key_len != ngx_http_encrypted_session_key_length
        || in_len < MD5_DIGEST_LENGTH)
    {
        return NGX_ERROR;
    }

    digest = in;

    if (emcf->session_ctx == NULL) {
        emcf->session_ctx = EVP_CIPHER_CTX_new();
        if (emcf->session_ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "encrypted_session: aes_mac_encrypt: no memory");

            return NGX_ERROR;
        }
    }

    cipher = EVP_aes_256_cbc();

    ret = EVP_DecryptInit(emcf->session_ctx, cipher, key, iv);
    if (!ret) {
        goto evp_error;
    }

    block_size = EVP_CIPHER_block_size(cipher);

    buf_size = in_len + block_size /* for EVP_DecryptUpdate */
               + block_size; /* for EVP_DecryptFinal */

    p = ngx_palloc(pool, buf_size);
    if (p == NULL) {
        goto evp_error;
    }

    *dst = p;

    ret = EVP_DecryptUpdate(emcf->session_ctx, p, &len, in + MD5_DIGEST_LENGTH,
                            in_len - MD5_DIGEST_LENGTH);

    if (!ret) {
        dd("decrypt update failed");
        goto evp_error;
    }

    p += len;

    ret = EVP_DecryptFinal(emcf->session_ctx, p, &len);

    emcf->reset_cipher_ctx(emcf->session_ctx);

    if (!ret) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                       "failed to decrypt session: bad AES-256 digest");

        return NGX_ERROR;
    }

    p += len;

    *dst_len = p - *dst;

    if (*dst_len > buf_size) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "encrypted_session: aes_mac_decrypt: buffer error");

        return NGX_ERROR;
    }

    if (*dst_len < sizeof(expires_time)) {
        return NGX_ERROR;
    }

    MD5(*dst, *dst_len, new_digest);

    if (ngx_strncmp(digest, new_digest, MD5_DIGEST_LENGTH) != 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                       "failed to decrypt session: MD5 checksum mismatch");

        return NGX_ERROR;
    }

    *dst_len -= sizeof(expires_time);

    dd("dst len: %d", (int) *dst_len);
    dd("dst: %.*s", (int) *dst_len, *dst);

    p -= sizeof(expires_time);

    expires_time = ngx_http_encrypted_session_ntohll(*((uint64_t *) p));

    now = time(NULL);
    if (now == -1) {
        return NGX_ERROR;
    }

    dd("expires after decryption: %lld", (long long) expires_time);

    if (expires_time && expires_time <= (uint64_t) now) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "encrypted_session: session expired: %uL <= %T",
                       expires_time, now);
        return NGX_ERROR;
    }

    dd("decrypted successfully");

    return NGX_OK;

evp_error:

    emcf->reset_cipher_ctx(emcf->session_ctx);

    return NGX_ERROR;
}


static uint64_t
ngx_http_encrypted_session_ntohll(uint64_t n)
{
#ifdef ntohll
    return ntohll(n);
#else
    return ((uint64_t) ntohl((unsigned long) n) << 32)
           + ntohl((unsigned long) (n >> 32));
#endif
}


static uint64_t
ngx_http_encrypted_session_htonll(uint64_t n)
{
#ifdef htonll
    return htonll(n);
#else
    return ((uint64_t) htonl((unsigned long) n) << 32)
           + htonl((unsigned long) (n >> 32));
#endif
}
