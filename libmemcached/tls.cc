//
// Created by Shaul, Bar on 17/03/2022.
//
#if defined(USE_TLS) && USE_TLS

#include "tls.h"


int memcached_init_OpenSSL(void)
{
    SSL_library_init();
#ifdef HIREDIS_USE_CRYPTO_LOCKS
    initOpensslLocks();
#endif

    return MEMCACHED_SUCCESS;
}

context_funcs context_ssl_funcs = {
    .free_privctx = memcached_ssl_free,
    .read = memcached_ssl_read,
    .write = memcached_ssl_write
};

static void memcached_ssl_free(void *privctx){
    memcached_ssl *memc_ssl = privctx;

    if (!memc_ssl) return;
    if (memc_ssl->ssl) {
        SSL_free(memc_ssl->ssl);
        memc_ssl->ssl = NULL;
    }
    libmemcached_free(NULL, memc_ssl);
}

SSL_CTX *memcached_create_ssl_context(const char *cacert_filename, const char *capath,
                                       const char *cert_filename, const char *private_key_filename,
                                       memc_ssl_context_error *error)
{
    SSL_CTX *ctx;
    memset(ctx, 0, sizeof(*ctx));
    if (ctx == NULL)
        memcached_set_error(*server, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT, memcached_literal_param("Out of memory"));
        goto error;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
	SSL_load_error_strings();   /* Bring in and register error messages */

    ctx = SSL_CTX_new(TLS_client_method());
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ctx = SSL_CTX_new(TLS_client_method());
#else
    ctx = SSL_CTX_new(TLSv1_client_method())
#endif
    if (!ctx) {
        if (error) *error = MEMCACHED_SSL_CTX_CREATE_FAILED;
        goto error;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if ((cert_filename != NULL && private_key_filename == NULL) ||
        (private_key_filename != NULL && cert_filename == NULL)) {
        if (error) *error = MEMCACHED_SSL_CTX_CERT_KEY_REQUIRED;
        goto error;
    }

    if (capath || cacert_filename) {
        if (!SSL_CTX_load_verify_locations(ctx, cacert_filename, capath)) {
            if (error) *error = MEMCACHED_SSL_CTX_CA_CERT_LOAD_FAILED;
            goto error;
        }
    }

    if (cert_filename) {
        if (!SSL_CTX_use_certificate_chain_file(ctx, cert_filename)) {
            if (error) *error = MEMCACHED_SSL_CTX_CLIENT_CERT_LOAD_FAILED;
            goto error;
        }
        if (!SSL_CTX_use_PrivateKey_file(ctx, private_key_filename, SSL_FILETYPE_PEM)) {
            if (error) *error = MEMCACHED_SSL_CTX_PRIVATE_KEY_LOAD_FAILED;
            goto error;
        }
    }

    return ctx;

    error:
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    return NULL;
}

const char *memcached_ssl_context_get_error(memc_ssl_context_error error)
{
    switch (error) {
        case MEMCACHED_SSL_CTX_NONE:
            return "No Error";
        case MEMCACHED_SSL_CTX_CREATE_FAILED:
            return "Failed to create OpenSSL SSL_CTX";
        case MEMCACHED_SSL_CTX_CERT_KEY_REQUIRED:
            return "Client cert and key must both be specified or skipped";
        case MEMCACHED_SSL_CTX_CA_CERT_LOAD_FAILED:
            return "Failed to load CA Certificate or CA Path";
        case MEMCACHED_SSL_CTX_CLIENT_CERT_LOAD_FAILED:
            return "Failed to load client certificate";
        case MEMCACHED_SSL_CTX_PRIVATE_KEY_LOAD_FAILED:
            return "Failed to load private key";
        default:
            return "Unknown error code";
    }
}

int memc_initiate_ssl_with_context(memcached_instance_st *server, SSL_CTX *ssl_ctx)
{
    if (!server || !ssl_ctx)
        return MEMCACHED_ERROR;

    /* We want to verify that memcached_ssl_connect() won't fail on this, as it will
     * not own the SSL object in that case and we'll end up leaking.
     */
    if (server->privctx)
        return MEMCACHED_ERROR;

    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        memcached_set_error(*server, MEMCACHED_TLS_ERROR, MEMCACHED_AT, memcached_literal_param("Couldn't create new SSL instance"));
        goto error;
    }

    return memcached_ssl_connect(server, ssl);

error:
    if (ssl)
        SSL_free(ssl);
    return MEMCACHED_ERROR;
}

/**
 * SSL Connection initialization.
 */
static int memcached_ssl_connect(memcached_instance_st *server, SSL *ssl) {
    if (server->privctx) {
        memcached_set_error(*server, MEMCACHED_TLS_ERROR, MEMCACHED_AT, memcached_literal_param("The server was already associated with SSL context"));
        return MEMCACHED_ERROR;
    }

    memcached_ssl *memc_ssl;
    memset(memc_ssl, 0, sizeof(*memc_ssl));
    if (memc_ssl == NULL) {
        memcached_set_error(*server, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT, memcached_literal_param("Out of memory"));
        return MEMCACHED_ERROR;
    }

    server->io_funcs = &context_ssl_funcs;
    memc_ssl->ssl = ssl;

    SSL_set_mode(memc_ssl->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_set_fd(memc_ssl->ssl, server->fd);
    SSL_set_connect_state(memc_ssl->ssl);

    ERR_clear_error();
    int rv = SSL_connect(memc_ssl->ssl);
    if (rv == 1) {
        server->privctx = memc_ssl;
        return MEMCACHED_SUCCESS;
    }

    rv = SSL_get_error(memc_ssl->ssl, rv);
    if ((server->root->flags.no_block) &&
        (rv == SSL_ERROR_WANT_READ || rv == SSL_ERROR_WANT_WRITE)) {
        server->privctx = memc_ssl;
        return MEMCACHED_SUCCESS;
    }


    char err[512];
    if (rv == SSL_ERROR_SYSCALL)
        snprintf(err,sizeof(err)-1,"SSL_connect failed: %s",strerror(errno));
    else {
        unsigned long e = ERR_peek_last_error();
        snprintf(err,sizeof(err)-1,"SSL_connect failed: %s",
                ERR_reason_error_string(e));
    }
    memcached_set_error(*server, MEMCACHED_TLS_ERROR, MEMCACHED_AT, err);

    libmemcached_free(NULL, memc_ssl);
    return MEMCACHED_ERROR;
}

#endif //USE_TLS