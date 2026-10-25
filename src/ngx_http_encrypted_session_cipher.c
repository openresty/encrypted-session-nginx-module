
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_encrypted_session_cipher.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <stdint.h>


static uint64_t ngx_http_encrypted_session_ntohll(uint64_t n);
static uint64_t ngx_http_encrypted_session_htonll(uint64_t n);


/*
 * Version || unpredictable IV || AES-CBC ciphertext || HMAC-SHA256.
 * Authenticate the version and IV along with the ciphertext before decrypting.
 * The configured IV is retained in the API for configuration compatibility.
 */
#define SESSION_VERSION         1
#define SESSION_IV_SIZE         16
#define SESSION_BLOCK_SIZE      16
#define SESSION_HEADER_SIZE     (1 + SESSION_IV_SIZE)
#define SESSION_MAC_SIZE        ngx_http_encrypted_session_mac_length


ngx_int_t
ngx_http_encrypted_session_init_key(ngx_http_encrypted_session_key_t *key,
    const u_char *data, size_t len)
{
    static const u_char domain[] = "encrypted-session MAC v1";
    unsigned int        mac_key_len;

    if (len != ngx_http_encrypted_session_key_length) {
        return NGX_ERROR;
    }

    if (HMAC(EVP_sha256(), data, (int) len, domain, sizeof(domain) - 1,
             key->mac_key, &mac_key_len) == NULL
        || mac_key_len != SESSION_MAC_SIZE)
    {
        OPENSSL_cleanse(key, sizeof(*key));
        return NGX_ERROR;
    }

    ngx_memcpy(key->key, data, len);
    return NGX_OK;
}


ngx_int_t
ngx_http_encrypted_session_aes_mac_encrypt(
    ngx_http_encrypted_session_main_conf_t *emcf, ngx_pool_t *pool,
    ngx_log_t *log, const u_char *iv, size_t iv_len,
    const ngx_http_encrypted_session_key_t *key,
    const u_char *in, size_t in_len, ngx_uint_t expires,
    u_char **dst, size_t *dst_len)
{
    u_char         *token, *data;
    size_t          data_size, capacity, encrypted;
    int             len, tail;
    unsigned int    mac_len;
    uint64_t        expires_time;
    time_t          now;

    if (key == NULL
        || in_len > INT_MAX - sizeof(expires_time) - SESSION_BLOCK_SIZE)
    {
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

    data_size = in_len + sizeof(expires_time);
    capacity = SESSION_HEADER_SIZE + data_size + SESSION_BLOCK_SIZE
               + SESSION_MAC_SIZE;
    token = ngx_palloc(pool, capacity);
    data = ngx_palloc(pool, data_size);
    if (token == NULL || data == NULL) {
        return NGX_ERROR;
    }

    token[0] = SESSION_VERSION;
    if (RAND_bytes(token + 1, SESSION_IV_SIZE) != 1) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "encrypted_session: failed to generate session IV");

        return NGX_ERROR;
    }

    expires_time = 0;
    if (expires != 0) {
        now = time(NULL);
        if (now == -1) {
            return NGX_ERROR;
        }

        expires_time = (uint64_t) now + (uint64_t) expires;
    }

    expires_time = ngx_http_encrypted_session_htonll(expires_time);
    ngx_memcpy(data, in, in_len);
    ngx_memcpy(data + in_len, &expires_time, sizeof(expires_time));

    if (EVP_EncryptInit_ex(emcf->session_ctx, EVP_aes_256_cbc(), NULL,
                           key->key, token + 1) != 1
        || EVP_EncryptUpdate(emcf->session_ctx, token + SESSION_HEADER_SIZE,
                             &len, data, (int) data_size) != 1
        || EVP_EncryptFinal_ex(emcf->session_ctx,
                               token + SESSION_HEADER_SIZE + len, &tail) != 1)
    {
        emcf->reset_cipher_ctx(emcf->session_ctx);
        return NGX_ERROR;
    }

    emcf->reset_cipher_ctx(emcf->session_ctx);
    encrypted = SESSION_HEADER_SIZE + len + tail;
    if (HMAC(EVP_sha256(), key->mac_key, SESSION_MAC_SIZE, token, encrypted,
             token + encrypted, &mac_len) == NULL
        || mac_len != SESSION_MAC_SIZE)
    {
        return NGX_ERROR;
    }

    *dst = token;
    *dst_len = encrypted + SESSION_MAC_SIZE;
    return NGX_OK;
}


ngx_int_t
ngx_http_encrypted_session_aes_mac_decrypt(
    ngx_http_encrypted_session_main_conf_t *emcf, ngx_pool_t *pool,
    ngx_log_t *log, const u_char *iv, size_t iv_len,
    const ngx_http_encrypted_session_key_t *key,
    const u_char *in, size_t in_len, u_char **dst,
    size_t *dst_len)
{
    u_char          mac[SESSION_MAC_SIZE], *data;
    size_t          authenticated, encrypted;
    int             len, tail;
    unsigned int    mac_len;
    uint64_t        expires_time;
    time_t          now;

    if (key == NULL
        || in_len < SESSION_HEADER_SIZE + SESSION_BLOCK_SIZE + SESSION_MAC_SIZE
        || in[0] != SESSION_VERSION)
    {
        return NGX_ERROR;
    }

    authenticated = in_len - SESSION_MAC_SIZE;
    encrypted = authenticated - SESSION_HEADER_SIZE;
    if (encrypted > INT_MAX || encrypted % SESSION_BLOCK_SIZE != 0
        || HMAC(EVP_sha256(), key->mac_key, SESSION_MAC_SIZE, in, authenticated,
                mac, &mac_len) == NULL
        || mac_len != SESSION_MAC_SIZE
        || CRYPTO_memcmp(mac, in + authenticated, SESSION_MAC_SIZE) != 0)
    {
        return NGX_ERROR;
    }

    if (emcf->session_ctx == NULL) {
        emcf->session_ctx = EVP_CIPHER_CTX_new();
        if (emcf->session_ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "encrypted_session: aes_mac_decrypt: no memory");

            return NGX_ERROR;
        }
    }

    data = ngx_palloc(pool, encrypted);
    if (data == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DecryptInit_ex(emcf->session_ctx, EVP_aes_256_cbc(), NULL,
                           key->key, in + 1) != 1
        || EVP_DecryptUpdate(emcf->session_ctx, data, &len,
                             in + SESSION_HEADER_SIZE, (int) encrypted) != 1
        || EVP_DecryptFinal_ex(emcf->session_ctx, data + len, &tail) != 1)
    {
        emcf->reset_cipher_ctx(emcf->session_ctx);
        return NGX_ERROR;
    }

    emcf->reset_cipher_ctx(emcf->session_ctx);
    if ((size_t) (len + tail) < sizeof(expires_time)) {
        return NGX_ERROR;
    }

    *dst_len = len + tail - sizeof(expires_time);
    ngx_memcpy(&expires_time, data + *dst_len, sizeof(expires_time));
    expires_time = ngx_http_encrypted_session_ntohll(expires_time);
    now = time(NULL);
    if (now == -1) {
        return NGX_ERROR;
    }

    if (expires_time && expires_time <= (uint64_t) now) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "encrypted_session: session expired: %uL <= %T",
                       expires_time, now);
        return NGX_ERROR;
    }

    *dst = data;
    return NGX_OK;
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
