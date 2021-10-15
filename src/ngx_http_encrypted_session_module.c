
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include <ndk.h>
#include <string.h>
#include "ngx_http_encrypted_session_cipher.h"

#define ngx_http_encrypted_session_default_iv (u_char *) "deadbeefdeadbeef"

#define ngx_http_encrypted_session_default_expires 86400

const size_t IV_LENGTH = 16;
const size_t SIGNATURE_LENGTH = 32;

typedef struct {
  u_char                                        *key;
    size_t                                      key_len;
    u_char                                      *iv;
    size_t                                      iv_len;
    time_t                                      expires;
    u_char                                      *expires_var;
    size_t                                      expires_var_len;
    ngx_flag_t                                  iv_in_content;
    enum ngx_http_encrypted_session_mode        encryption_mode;
} ngx_http_encrypted_session_conf_t;

static time_t ngx_http_encrypted_session_get_expires_from_conf(
    ngx_http_request_t *r,
    ngx_http_encrypted_session_conf_t *conf);

static ngx_int_t ngx_http_set_encode_encrypted_session(ngx_http_request_t *r,
    ngx_str_t *res, ngx_http_variable_value_t *v);

static ngx_int_t ngx_http_set_decode_encrypted_session(ngx_http_request_t *r,
    ngx_str_t *res, ngx_http_variable_value_t *v);

static void ngx_http_encrypted_session_free_cipher_ctx(void *data);

static char *ngx_http_encrypted_session_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_encrypted_session_iv(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_encrypted_session_mode_set(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static char *ngx_http_encrypted_session_expires(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static char *ngx_http_encrypted_iv_in_content(ngx_conf_t *cf,
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
        ngx_string("encrypted_session_mode"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF
        |NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_http_encrypted_session_mode_set,
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
    { ngx_string("encrypted_session_iv_in_content"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF
      |NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_NOARGS,
      ngx_http_encrypted_iv_in_content,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL
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

static ngx_str_t ngx_http_get_variable_by_name(ngx_http_request_t *r,
    unsigned char *name, size_t name_len, ngx_http_encrypted_session_conf_t *conf)
{
    ngx_http_variable_value_t  *v;
    ngx_str_t name_str;
    name_str.data = name;
    name_str.len = name_len;

    ngx_uint_t key = ngx_hash_strlow(name, name, name_len);
    v = ngx_http_get_variable(r, &name_str, key);

    if (v->not_found) {
        return name_str;
    }

    ngx_str_t var_value;
    var_value.len = v->len;
    var_value.data = v->data;
    return var_value;
}

static time_t ngx_http_encrypted_session_parse_expires(ngx_str_t* value)
{
  return ngx_parse_time(value, 1);
}

static time_t ngx_http_encrypted_session_get_expires_from_conf(
    ngx_http_request_t *r,
    ngx_http_encrypted_session_conf_t *conf)
{
    if (!conf->expires_var) {
        return conf->expires;
    }

    ngx_str_t expires = ngx_http_get_variable_by_name(
        r, conf->expires_var, conf->expires_var_len, conf);
    time_t expires_val = ngx_http_encrypted_session_parse_expires(&expires);
    if (expires_val == NGX_ERROR) {
        dd("expires %s has an invalid value.", conf->expires_var);
    }

    return expires_val;
}

static u_char*
ngx_http_encrypted_session_build_payload(ngx_http_request_t *r,
    ngx_str_t *content, ngx_str_t *iv, size_t *len)
{
    size_t new_len = iv->len + content->len;
    u_char *data = (u_char *)ngx_pcalloc(r->pool, new_len + 1);
    ngx_memcpy(data, iv->data, iv->len);
    ngx_memcpy(data + iv->len, content->data, content->len);
    *len = new_len;

    return data;
}

static ngx_str_t*
ngx_http_session_encrypted_compute_hmac(ngx_http_request_t *r,
    ngx_str_t *key, ngx_str_t *content)
{
    size_t signature_len;
    u_char* signature;

    ngx_http_encrypted_session_hmac(r->pool, key->data, key->len,
                                    content->data, content->len,
                                    &signature, &signature_len);

    ngx_str_t *result = (ngx_str_t*)ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    result->len = signature_len;
    result->data = (u_char*)ngx_pcalloc(r->pool, signature_len + 1);
    result->data = signature;
    return result;
}

static ngx_str_t*
ngx_http_session_generate_signature(ngx_http_request_t *r,
    ngx_str_t *iv, ngx_str_t *key, ngx_str_t *content,
    ngx_str_t *tag, enum ngx_http_encrypted_session_mode mode)
{
    size_t signature_content_len = iv->len + content->len;
    if (mode == ngx_http_encrypted_session_mode_gcm)
    {
      signature_content_len += tag->len;
    }

    u_char* signature_content = (u_char*)ngx_pcalloc(r->pool, signature_content_len + 1);
    ngx_memcpy(signature_content, iv->data, iv->len);

    if (mode == ngx_http_encrypted_session_mode_gcm)
    {
        ngx_memcpy(signature_content + iv->len, tag->data, tag->len);
        ngx_memcpy(signature_content + iv->len + tag->len,
                   content->data, content->len);
    }
    else
    {
        ngx_memcpy(signature_content + iv->len, content->data, content->len);
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "encrypted_session: signature content len=%d",
                  signature_content_len);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "encrypted_session: signature content=%s",
                  signature_content);

    ngx_str_t signature_input;
    signature_input.len = signature_content_len;
    signature_input.data = (u_char*)signature_content;
    ngx_str_t *signature = ngx_http_session_encrypted_compute_hmac(r, key,
        &signature_input);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                 "encrypted_session: signature=%s", signature->data);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                 "encrypted_session: signature len=%d", signature->len);

    return signature;
}

static ngx_str_t*
ngx_http_session_generate_response_with_iv(ngx_http_request_t *r,
    ngx_str_t *iv, ngx_str_t *key, ngx_str_t *content,
    ngx_str_t *tag, enum ngx_http_encrypted_session_mode mode)
{
    ngx_str_t *signature = ngx_http_session_generate_signature(r, iv, key,
        content, tag, mode);

    size_t new_len = iv->len + signature->len + content->len;

    if (mode == ngx_http_encrypted_session_mode_gcm)
    {
        new_len += tag->len;
    }

    u_char *new_content = (u_char*)ngx_pcalloc(r->pool, new_len + 1);
    ngx_memcpy(new_content, iv->data, iv->len);
    ngx_memcpy(new_content + iv->len, signature->data, signature->len);

    if (mode == ngx_http_encrypted_session_mode_gcm)
    {
        ngx_memcpy(new_content + iv->len + signature->len, tag->data, tag->len);
        ngx_memcpy(new_content + iv->len + signature->len + tag->len, content->data, content->len);
    }
    else
    {
        ngx_memcpy(new_content + iv->len + signature->len, content->data, content->len);
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "encrypted_session: encrypted data len=%d", content->len);

    ngx_str_t *payload = (ngx_str_t*)ngx_palloc(r->pool, sizeof(ngx_str_t));
    payload->len = new_len;
    payload->data = (u_char*)new_content;

    return payload;
}

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

    time_t expires_val = ngx_http_encrypted_session_get_expires_from_conf(r,
                                                                          conf);
    if (expires_val == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "encrypted_session: invalid session expires numeric value "
                    "defined by the encrypted_session_expires directive");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "encrypted_session: expires=%T", expires_val);

    ngx_str_t iv = ngx_http_get_variable_by_name(r, conf->iv, conf->iv_len,
                                                 conf);
    ngx_str_t key = ngx_http_get_variable_by_name(r, conf->key, conf->key_len,
                                                  conf);

    ngx_str_t content;
    content.data = (u_char*)ngx_pcalloc(r->pool, v->len + 1);
    ngx_memcpy(content.data, v->data, v->len);
    content.len = v->len;

    if (conf->iv_in_content) {
        size_t new_len;
        content.data = ngx_http_encrypted_session_build_payload(r,
            &content, &iv, &new_len);
        content.len = new_len;

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "encrypted_session: content to encrypt len=%d",
                      content.len);
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "encrypted_session: content to encrypt=%s",
                      content.data);
    }

    u_char *tag;
    rc = ngx_http_encrypted_session_aes_mac_encrypt(emcf, r->pool,
            r->connection->log, iv.data, iv.len, key.data, key.len,
            content.data, content.len,
            (ngx_uint_t) expires_val,
            conf->encryption_mode, &dst, &len, &tag);

    if (rc != NGX_OK) {
        res->data = NULL;
        res->len = 0;

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "encrypted_session: failed to encrypt");
        return NGX_OK;
    }

    if (conf->iv_in_content) {
        ngx_str_t encrypted_content;
        encrypted_content.len = len;
        encrypted_content.data = dst;

        ngx_str_t tag_content;
        tag_content.len = ngx_http_encrypted_session_aes_tag_size;
        tag_content.data = tag;

        ngx_str_t *result = ngx_http_session_generate_response_with_iv(r, &iv,
            &key, &encrypted_content, &tag_content, conf->encryption_mode);
        res->data = result->data;
        res->len = result->len;

    } else {
        res->data = dst;
        res->len = len;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "encrypted_session: full response len=%d",
                  res->len);

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

    ngx_str_t key = ngx_http_get_variable_by_name(r, conf->key, conf->key_len,
                                                  conf);

    ngx_str_t iv;
    ngx_str_t content;
    ngx_str_t tag;

    content.data = v->data;
    content.len = v->len;

    if (!conf->iv_in_content)
    {
        iv = ngx_http_get_variable_by_name(r, conf->iv, conf->iv_len, conf);
    }
    else
    {
        if (content.len < IV_LENGTH + SIGNATURE_LENGTH + 1) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "encrypted_session: input to decrypt is too short.");
            res->data = NULL;
            res->len = 0;

            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                     "encrypted_session: input to decrypt len=%d",
                     content.len);
        iv.len = IV_LENGTH;
        iv.data = (u_char*)ngx_pcalloc(r->pool, iv.len + 1);
        ngx_memcpy(iv.data, content.data, iv.len);

        u_char* signature = (u_char*)ngx_pcalloc(r->pool, SIGNATURE_LENGTH + 1);
        ngx_memcpy(signature, content.data + iv.len, SIGNATURE_LENGTH);

        if (conf->encryption_mode == ngx_http_encrypted_session_mode_gcm)
        {
            tag.len = ngx_http_encrypted_session_aes_tag_size;
            tag.data = (u_char*)ngx_pcalloc(r->pool, tag.len);
            ngx_memcpy(tag.data, content.data + iv.len + SIGNATURE_LENGTH, tag.len);
        }

        ngx_str_t encrypted_content;
        if (conf->encryption_mode == ngx_http_encrypted_session_mode_gcm)
        {
            encrypted_content.len = content.len - iv.len - SIGNATURE_LENGTH - tag.len;
            encrypted_content.data = (u_char*)ngx_pcalloc(r->pool, encrypted_content.len + 1);
            ngx_memcpy(encrypted_content.data,
                       v->data + iv.len + SIGNATURE_LENGTH + tag.len,
                       encrypted_content.len);
        }
        else
        {
            encrypted_content.len = content.len - iv.len - SIGNATURE_LENGTH;
            encrypted_content.data = (u_char*)ngx_pcalloc(r->pool, encrypted_content.len + 1);
            ngx_memcpy(encrypted_content.data, v->data + iv.len + SIGNATURE_LENGTH, encrypted_content.len);
        }

        content.data = encrypted_content.data;
        content.len = encrypted_content.len;

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "encrypted_session: data len=%d", content.len);

        ngx_str_t *computed_signature = ngx_http_session_generate_signature(r,
            &iv, &key, &encrypted_content, &tag, conf->encryption_mode);
        if (SIGNATURE_LENGTH != computed_signature->len ||
              ngx_memcmp(computed_signature->data, signature, SIGNATURE_LENGTH) != 0)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "encrypted_session: signatures do not match");
            res->data = NULL;
            res->len = 0;

            return NGX_OK;
        }
    }

    rc = ngx_http_encrypted_session_aes_mac_decrypt(emcf, r->pool,
            r->connection->log, iv.data, iv.len, key.data, key.len,
            content.data, content.len, conf->encryption_mode, tag.data,
            &dst, &len);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "encrypted_session: failed to decrypt");
        res->data = NULL;
        res->len = 0;

        return NGX_OK;
    }

    if (conf->iv_in_content) {
        size_t payload_len = len - iv.len;
        u_char *result = ngx_pcalloc(r->pool, payload_len + 1);
        ngx_memcpy(result, dst + iv.len, payload_len);
        dst = result;
        len = payload_len;
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "encrypted_session: decrypted content=%s",
                    dst);
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

    if (value[1].len > 1 && value[1].data[0] == '$') {
      llcf->key_len = value[1].len - 1;
      llcf->key = (u_char*)ngx_pcalloc(cf->pool, llcf->key_len);
      ngx_memcpy(llcf->key, value[1].data + 1, llcf->key_len);
      return NGX_CONF_OK;
    }

    if (value[1].len != ngx_http_encrypted_session_key_length) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "encrypted_session_key: the key must be of %d "
                           "bytes long",
                           ngx_http_encrypted_session_key_length);

        return NGX_CONF_ERROR;
    }

    llcf->key = value[1].data;
    llcf->key_len = value[1].len;

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

    if (value[1].len > 1 && value[1].data[0] == '$') {
      llcf->iv = &(value[1].data[1]);
      llcf->iv_len = value[1].len - 1;
      return NGX_CONF_OK;
    }

    if (value[1].len > ngx_http_encrypted_session_iv_length) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "encrypted_session_iv: the init vector must NOT "
                           "be longer than %d bytes",
                ngx_http_encrypted_session_iv_length);

        return NGX_CONF_ERROR;
    }

    llcf->iv = ngx_pcalloc(cf->pool, ngx_http_encrypted_session_iv_length);
    llcf->iv_len = ngx_http_encrypted_session_iv_length;

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
ngx_http_encrypted_session_mode_set(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_str_t       *value;
    ngx_http_encrypted_session_conf_t  *llcf = conf;

    value = cf->args->elts;
    if (value[1].len == 3 && strncmp("cbc", (char*)value[1].data, 3) == 0) {
        llcf->encryption_mode = ngx_http_encrypted_session_mode_cbc;
    }
    else if (value[1].len == 3 && strncmp("gcm", (char*)value[1].data, 3) == 0) {
        llcf->encryption_mode = ngx_http_encrypted_session_mode_gcm;
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

    if (value[1].len > 1 && value[1].data[0] == '$') {
        llcf->expires_var = &(value[1].data[1]);
        llcf->expires_var_len = value[1].len - 1;
        return NGX_CONF_OK;
    }

    llcf->expires = ngx_http_encrypted_session_parse_expires(&value[1]);

    if (llcf->expires == NGX_ERROR) {
        return "invalid value";
    }

    dd("expires: %d", (int) llcf->expires);

    return NGX_CONF_OK;
}

static char *ngx_http_encrypted_iv_in_content(ngx_conf_t *cf,
   ngx_command_t *cmd, void *conf)
{
   ngx_http_encrypted_session_conf_t  *llcf = conf;
   llcf->iv_in_content = 1;
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
    conf->key_len = NGX_CONF_UNSET;
    conf->iv      = NGX_CONF_UNSET_PTR;
    conf->iv_len  = NGX_CONF_UNSET;
    conf->expires = NGX_CONF_UNSET;
    conf->expires_var = NGX_CONF_UNSET_PTR;
    conf->expires_var_len = NGX_CONF_UNSET;
    conf->iv_in_content = NGX_CONF_UNSET;
    conf->encryption_mode = ngx_http_encrypted_session_mode_unknown;

    return conf;
}


static char *
ngx_http_encrypted_session_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_encrypted_session_conf_t *prev = parent;
    ngx_http_encrypted_session_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->key, prev->key, NULL);
    ngx_conf_merge_size_value(conf->key_len, prev->key_len,
                              (size_t)ngx_http_encrypted_session_key_length);

    ngx_conf_merge_ptr_value(conf->iv, prev->iv,
                             ngx_http_encrypted_session_default_iv);
    ngx_conf_merge_size_value(conf->iv_len, prev->iv_len,
                              (size_t)ngx_http_encrypted_session_iv_length);

    ngx_conf_merge_value(conf->expires, prev->expires,
                         ngx_http_encrypted_session_default_expires);
    ngx_conf_merge_size_value(conf->expires_var_len, prev->expires_var_len,
                            (size_t)0);
    ngx_conf_merge_ptr_value(conf->expires_var, prev->expires_var,
                             NULL);
    ngx_conf_merge_value(conf->iv_in_content, prev->iv_in_content, 0);

    if (conf->encryption_mode == ngx_http_encrypted_session_mode_unknown) {
        conf->encryption_mode = prev->encryption_mode;
    }

    if (conf->encryption_mode == ngx_http_encrypted_session_mode_unknown) {
        conf->encryption_mode = ngx_http_encrypted_session_mode_cbc;
    }

    return NGX_CONF_OK;
}
