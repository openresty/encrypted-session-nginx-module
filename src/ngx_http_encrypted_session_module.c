
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include <ndk.h>
#include "ngx_http_encrypted_session_cipher.h"

#define ngx_http_encrypted_session_default_iv (u_char *) "deadbeefdeadbeef"

#define ngx_http_encrypted_session_default_expires 86400


typedef struct {
    u_char              *key;
    u_char              *iv;
    time_t               expires;

} ngx_http_encrypted_session_conf_t;


static ngx_int_t ngx_http_set_encode_encrypted_session(ngx_http_request_t *r,
    ngx_str_t *res, ngx_http_variable_value_t *v);

static ngx_int_t ngx_http_set_decode_encrypted_session(ngx_http_request_t *r,
    ngx_str_t *res, ngx_http_variable_value_t *v);

static ngx_int_t ngx_http_set_encode_encrypted_session_keyed(ngx_http_request_t *r,
    ngx_str_t *res, ngx_http_variable_value_t *v);

static ngx_int_t ngx_http_set_decode_encrypted_session_keyed(ngx_http_request_t *r,
    ngx_str_t *res, ngx_http_variable_value_t *v);

static void ngx_http_encrypted_session_free_cipher_ctx(void *data);

static char *ngx_http_encrypted_session_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_encrypted_session_iv(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_encrypted_session_expires(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


static ngx_int_t ngx_http_encrypted_session_init(ngx_conf_t *cf);
static void *ngx_http_encrypted_session_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_encrypted_session_init_main_conf(ngx_conf_t *cf,
    void *conf);

static void *ngx_http_encrypted_session_create_conf(ngx_conf_t *cf);

static char *ngx_http_encrypted_session_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);


static  ndk_set_var_t  ngx_http_set_encode_encrypted_session_filter = {
    NDK_SET_VAR_VALUE,
    (void *) ngx_http_set_encode_encrypted_session,
    1,
    NULL
};

static  ndk_set_var_t  ngx_http_set_decode_encrypted_session_filter = {
    NDK_SET_VAR_VALUE,
    (void *) ngx_http_set_decode_encrypted_session,
    1,
    NULL
};


static  ndk_set_var_t  ngx_http_set_encode_encrypted_session_keyed_filter = {
    NDK_SET_VAR_MULTI_VALUE,
    (void *) ngx_http_set_encode_encrypted_session_keyed,
    2,
    NULL
};

static  ndk_set_var_t  ngx_http_set_decode_encrypted_session_keyed_filter = {
    NDK_SET_VAR_MULTI_VALUE,
    (void *) ngx_http_set_decode_encrypted_session_keyed,
    2,
    NULL
};

static ngx_command_t  ngx_http_encrypted_session_commands[] = {
    {
        ngx_string("encrypted_session_key"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF
            |NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_http_encrypted_session_key,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("encrypted_session_iv"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF
            |NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_http_encrypted_session_iv,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("encrypted_session_expires"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF
            |NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_http_encrypted_session_expires,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("set_encrypt_session"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF
            |NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE12,
        ndk_set_var_value,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        &ngx_http_set_encode_encrypted_session_filter
    },
    {
        ngx_string("set_decrypt_session"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF
            |NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE12,
        ndk_set_var_value,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        &ngx_http_set_decode_encrypted_session_filter
    },
    {
        ngx_string("set_encrypt_session_keyed"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF
            |NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE3,
		ndk_set_var_multi_value,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        &ngx_http_set_encode_encrypted_session_keyed_filter
    },
    {
        ngx_string("set_decrypt_session_keyed"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF
            |NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE3,
		ndk_set_var_multi_value,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        &ngx_http_set_decode_encrypted_session_keyed_filter
    },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_encrypted_session_module_ctx = {
    NULL,                                    /* preconfiguration */
    ngx_http_encrypted_session_init,         /* postconfiguration */

    ngx_http_encrypted_session_create_main_conf, /* create main configuration */
    ngx_http_encrypted_session_init_main_conf,   /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */

    ngx_http_encrypted_session_create_conf,  /* create location configuration */
    ngx_http_encrypted_session_merge_conf,   /* merge location configuration */
};


ngx_module_t  ngx_http_encrypted_session_module = {
    NGX_MODULE_V1,
    &ngx_http_encrypted_session_module_ctx,  /* module context */
    ngx_http_encrypted_session_commands,     /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_set_encode_encrypted_session(ngx_http_request_t *r,
    ngx_str_t *res, ngx_http_variable_value_t *v)
{
    size_t                   len;
    u_char                  *dst;
    ngx_int_t                rc;

    ngx_http_encrypted_session_conf_t      *conf;
    ngx_http_encrypted_session_main_conf_t *emcf;

    emcf = ngx_http_get_module_main_conf(r, ngx_http_encrypted_session_module);
    conf = ngx_http_get_module_loc_conf(r, ngx_http_encrypted_session_module);

    if (conf->key == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "encrypted_session: a key is required to be "
                      "defined by the encrypted_session_key directive");

        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "encrypted_session: expires=%T", conf->expires);

    rc = ngx_http_encrypted_session_aes_mac_encrypt(emcf, r->pool,
            r->connection->log, conf->iv, ngx_http_encrypted_session_iv_length,
            conf->key, ngx_http_encrypted_session_key_length,
            v->data, v->len, (ngx_uint_t) conf->expires, &dst, &len);

    if (rc != NGX_OK) {
        dst = NULL;
        len = 0;

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "encrypted_session: failed to encrypt");
    }

    res->data = dst;
    res->len = len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_set_encode_encrypted_session_keyed(ngx_http_request_t *r,
    ngx_str_t *res, ngx_http_variable_value_t *v)
{
    size_t                   len;
    u_char                  *dst;
    ngx_int_t                rc;

    ngx_http_encrypted_session_conf_t      *conf;
    ngx_http_encrypted_session_main_conf_t *emcf;

    emcf = ngx_http_get_module_main_conf(r, ngx_http_encrypted_session_module);
    conf = ngx_http_get_module_loc_conf(r, ngx_http_encrypted_session_module);

    u_char *actualKey = NULL;
    if ((v+1)->len != ngx_http_encrypted_session_key_length) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "encrypted_session_keyed: specified key needs to be exactly %d characters long; got %d",
            ngx_http_encrypted_session_key_length, (v+1)->len);
        return NGX_ERROR;
    } else {
        actualKey = (v+1)->data;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "encrypted_session_keyed: expires=%T", conf->expires);

    rc = ngx_http_encrypted_session_aes_mac_encrypt(emcf, r->pool,
            r->connection->log, conf->iv, ngx_http_encrypted_session_iv_length,
            actualKey, ngx_http_encrypted_session_key_length,
            v->data, v->len, (ngx_uint_t) conf->expires, &dst, &len);

    if (rc != NGX_OK) {
        dst = NULL;
        len = 0;

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "encrypted_session_keyed: failed to encrypt");
    }

    res->data = dst;
    res->len = len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_set_decode_encrypted_session(ngx_http_request_t *r,
    ngx_str_t *res, ngx_http_variable_value_t *v)
{
    size_t                   len;
    u_char                  *dst;
    ngx_int_t                rc;

    ngx_http_encrypted_session_conf_t      *conf;
    ngx_http_encrypted_session_main_conf_t *emcf;

    emcf = ngx_http_get_module_main_conf(r, ngx_http_encrypted_session_module);
    conf = ngx_http_get_module_loc_conf(r, ngx_http_encrypted_session_module);

    if (conf->key == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "encrypted_session: a key is required to be "
                      "defined by the encrypted_session_key directive");

        return NGX_ERROR;
    }

    rc = ngx_http_encrypted_session_aes_mac_decrypt(emcf, r->pool,
            r->connection->log, conf->iv, ngx_http_encrypted_session_iv_length,
            conf->key, ngx_http_encrypted_session_key_length,
            v->data, v->len, &dst, &len);

    if (rc != NGX_OK) {
        dst = NULL;
        len = 0;
    }

    res->data = dst;
    res->len = len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_set_decode_encrypted_session_keyed(ngx_http_request_t *r,
    ngx_str_t *res, ngx_http_variable_value_t *v)
{
    size_t                   len;
    u_char                  *dst;
    ngx_int_t                rc;

    ngx_http_encrypted_session_conf_t      *conf;
    ngx_http_encrypted_session_main_conf_t *emcf;

    emcf = ngx_http_get_module_main_conf(r, ngx_http_encrypted_session_module);
    conf = ngx_http_get_module_loc_conf(r, ngx_http_encrypted_session_module);

    u_char *actualKey;
	if ((v+1)->len != ngx_http_encrypted_session_key_length) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"encrypted_session_keyed: specified key needs to be exactly %d characters long; got %d",
				ngx_http_encrypted_session_key_length, (v+1)->len);
		return NGX_ERROR;
	} else {
		actualKey = (v+1)->data;
	}

    rc = ngx_http_encrypted_session_aes_mac_decrypt(emcf, r->pool,
            r->connection->log, conf->iv, ngx_http_encrypted_session_iv_length,
            actualKey, ngx_http_encrypted_session_key_length,
            v->data, v->len, &dst, &len);

    if (rc != NGX_OK) {
        dst = NULL;
        len = 0;
    }

    res->data = dst;
    res->len = len;

    return NGX_OK;
}

static char *
ngx_http_encrypted_session_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t       *value;

    ngx_http_encrypted_session_conf_t      *llcf = conf;

    if (llcf->key != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len != ngx_http_encrypted_session_key_length) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "encrypted_session_key: the key must be of %d "
                           "bytes long",
                           ngx_http_encrypted_session_key_length);

        return NGX_CONF_ERROR;
    }

    llcf->key = value[1].data;

    return NGX_CONF_OK;
}


static char *
ngx_http_encrypted_session_iv(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t       *value;

    ngx_http_encrypted_session_conf_t  *llcf = conf;

    if (llcf->iv != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len > ngx_http_encrypted_session_iv_length) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "encrypted_session_iv: the init vector must NOT "
                           "be longer than %d bytes",
                ngx_http_encrypted_session_iv_length);

        return NGX_CONF_ERROR;
    }

    llcf->iv = ngx_pcalloc(cf->pool, ngx_http_encrypted_session_iv_length);

    if (llcf->iv == NULL) {
        return NGX_CONF_ERROR;
    }

    dd("XXX iv max len: %d", (int) ngx_http_encrypted_session_iv_length);
    dd("XXX iv actual len: %d", (int) value[1].len);

    if (value[1].len) {
        ngx_memcpy(llcf->iv, value[1].data, value[1].len);
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_encrypted_session_expires(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t                          *value;
    ngx_http_encrypted_session_conf_t  *llcf = conf;

    if (llcf->expires != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    llcf->expires = ngx_parse_time(&value[1], 1);

    if (llcf->expires == NGX_ERROR) {
        return "invalid value";
    }

    dd("expires: %d", (int) llcf->expires);

    return NGX_CONF_OK;
}


static void
ngx_http_encrypted_session_free_cipher_ctx(void *data)
{
    ngx_http_encrypted_session_main_conf_t      *emcf = data;

    if (emcf->session_ctx != NULL) {
        EVP_CIPHER_CTX_free(emcf->session_ctx);
        emcf->session_ctx = NULL;
    }
}


static ngx_int_t
ngx_http_encrypted_session_init(ngx_conf_t *cf)
{
    ngx_pool_cleanup_t                        *cln;
    ngx_http_encrypted_session_main_conf_t    *emcf;

    emcf =
        ngx_http_conf_get_module_main_conf(cf,
                                           ngx_http_encrypted_session_module);

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->data = emcf;
    cln->handler = ngx_http_encrypted_session_free_cipher_ctx;
    return NGX_OK;
}


static void *
ngx_http_encrypted_session_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_encrypted_session_main_conf_t    *emcf;

    emcf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_encrypted_session_main_conf_t));
    if (emcf == NULL) {
        return NULL;
    }

    return emcf;
}


static char *
ngx_http_encrypted_session_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_encrypted_session_main_conf_t *emcf = conf;

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    emcf->reset_cipher_ctx = EVP_CIPHER_CTX_reset;
#else
    emcf->reset_cipher_ctx = EVP_CIPHER_CTX_cleanup;
#endif

    return NGX_CONF_OK;
}


static void *
ngx_http_encrypted_session_create_conf(ngx_conf_t *cf)
{
    ngx_http_encrypted_session_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_encrypted_session_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->key     = NGX_CONF_UNSET_PTR;
    conf->iv      = NGX_CONF_UNSET_PTR;
    conf->expires = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_encrypted_session_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_encrypted_session_conf_t *prev = parent;
    ngx_http_encrypted_session_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->key, prev->key, NULL);

    ngx_conf_merge_ptr_value(conf->iv, prev->iv,
                             ngx_http_encrypted_session_default_iv);

    ngx_conf_merge_value(conf->expires, prev->expires,
                         ngx_http_encrypted_session_default_expires);

    return NGX_CONF_OK;
}
