//
// Created by Shaul, Bar on 17/03/2022.
//
#if defined(USE_TLS) && USE_TLS

#include "libmemcached/tls.h"
#include <libmemcached/common.h>
#include <libmemcached/virtual_bucket.h>

int memcached_init_OpenSSL(void)
{
    SSL_library_init();
#ifdef HIREDIS_USE_CRYPTO_LOCKS
    initOpensslLocks();
#endif

    return MEMCACHED_SUCCESS;
}

static context_funcs context_ssl_funcs = {
    .free_privctx = memcached_ssl_free,
    .read = memcached_ssl_read,
    .write = memcached_ssl_write
};

void memcached_ssl_free(void *privctx){
    memcached_ssl *memc_ssl = (memcached_ssl*)privctx;

    if (!memc_ssl) return;
    if (memc_ssl->ssl) {
        SSL_free(memc_ssl->ssl);
        memc_ssl->ssl = NULL;
    }
    libmemcached_free(NULL, memc_ssl);
}

/* Callback for passing a keyfile password stored as an sds to OpenSSL */
static int ssl_set_password_callback(char *buf, int size, int rwflag, void *u) {
    UNUSED(rwflag);

    const char *pass = (const char *)u;
    size_t pass_len;

    if (!pass) return -1;
    pass_len = strlen(pass);
    if (pass_len > (size_t) size) return -1;
    memcpy(buf, pass, pass_len);

    return (int) pass_len;
}

memc_SSL_CTX *memcached_create_ssl_context(const memcached_st *ptr, memcached_ssl_context_config *ctx_config, memc_ssl_context_error *error)
{
    memc_SSL_CTX *ssl_ctx;
    if (ptr != NULL) {
       ssl_ctx = (memc_SSL_CTX *)libmemcached_calloc(ptr, 1, sizeof(memc_SSL_CTX));
    } else {
        // Use std::calloc by default
        ssl_ctx = (memc_SSL_CTX *)calloc(1, sizeof(memc_SSL_CTX));
    }
    if (ssl_ctx == NULL) {
        if (error) *error = MEMCACHED_SSL_MEMORY_ALLOCATION_FAILURE;
        goto error;
    }

    ssl_ctx->ctx = init_ctx();

    if (!ssl_ctx->ctx) {
        if (error) *error = MEMCACHED_SSL_CTX_CREATE_FAILED;
        goto error;
    }

    SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif

#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ssl_ctx->ctx, SSL_OP_NO_COMPRESSION);
#endif

    SSL_CTX_set_mode(ssl_ctx->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    if (!ctx_config->skip_cert_verify) {
        SSL_CTX_set_verify(ssl_ctx->ctx, SSL_VERIFY_PEER, NULL);
    }

    SSL_CTX_set_default_passwd_cb(ssl_ctx->ctx, ssl_set_password_callback);
    SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx->ctx, (void *) ctx_config->key_file_pass);

    /* load certificates */
    if ((ctx_config->cert_file != NULL && ctx_config->key_file == NULL) ||
        (ctx_config->key_file != NULL && ctx_config->cert_file == NULL)) {
        if (error) *error = MEMCACHED_SSL_CTX_CERT_KEY_REQUIRED;
        goto error;
    }

    if (ctx_config->ca_cert_dir || ctx_config->ca_cert_file) {
        if (SSL_CTX_load_verify_locations(ssl_ctx->ctx, ctx_config->ca_cert_file, ctx_config->ca_cert_dir) <= 0) {
            if (error) *error = MEMCACHED_SSL_CTX_CA_CERT_LOAD_FAILED;
            goto error;
        }
    }

    if (ctx_config->cert_file) {
        if (SSL_CTX_use_certificate_file(ssl_ctx->ctx, ctx_config->cert_file, SSL_FILETYPE_PEM) <= 0) {
            if (error) *error = MEMCACHED_SSL_CTX_CLIENT_CERT_LOAD_FAILED;
            goto error;
        }
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx->ctx, ctx_config->key_file, SSL_FILETYPE_PEM) <= 0) {
            if (error) *error = MEMCACHED_SSL_CTX_PRIVATE_KEY_LOAD_FAILED;
            goto error;
        }
    }

    if (ctx_config->ciphers && !SSL_CTX_set_cipher_list(ssl_ctx->ctx, ctx_config->ciphers)) {
        if (error) *error = MEMCACHED_SSL_CTX_CIPHERS_LOAD_FAILED;
        goto error;
    }

#ifdef TLS1_3_VERSION
    if (ctx_config->ciphersuites && !SSL_CTX_set_ciphersuites(ssl_ctx->ctx, ctx_config->ciphersuites)) {
        if (error) *error = MEMCACHED_SSL_CTX_CIPHERSUITES_LOAD_FAILED;
        goto error;
    }
#endif

    return ssl_ctx;

    error:
    memc_free_SSL_ctx(ssl_ctx);
    return NULL;
}

const char *memcached_ssl_context_get_error(memc_ssl_context_error error)
{
    switch (error) {
        case MEMCACHED_SSL_CTX_NONE:
            return "No Error";
        case MEMCACHED_SSL_MEMORY_ALLOCATION_FAILURE:
            return "Out of memory";
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
        case MEMCACHED_SSL_CTX_CIPHERS_LOAD_FAILED:
            return "Failed to configure ciphers";
        case MEMCACHED_SSL_CTX_PRIVATE_KEY_MISMATCH:
            return "Private key does not match the public certificate";
        default:
            return "Unknown error code";
    }
}

memcached_return_t memc_initiate_ssl(memcached_instance_st *server)
{
    memcached_return_t rc;
    memc_SSL_CTX *memc_ssl_ctx;
    SSL_CTX *ssl_ctx;
    SSL *ssl;

    if (server == NULL)
    {
      server->reset_socket();
      return MEMCACHED_INVALID_ARGUMENTS;
    }

    /* We want to verify that memcached_ssl_connect() won't fail on this, as it will
     * not own the SSL object in that case and we'll end up leaking.
     */
    if (server->privctx != NULL) {
        rc = memcached_set_error(*(server->root), MEMCACHED_TLS_ERROR, MEMCACHED_AT, memcached_literal_param("SSL was already initated for this server"));
        goto error;
    }

    memc_ssl_ctx = (memc_SSL_CTX*)server->root->ssl_ctx;
    if (memc_ssl_ctx == NULL) {
        rc = memcached_set_error(*(server->root), MEMCACHED_TLS_ERROR, MEMCACHED_AT, memcached_literal_param("SSL context needs to be set with memcached_set_ssl_context()"));
        goto error;
    }

    ssl_ctx = memc_ssl_ctx->ctx;
    if (ssl_ctx == NULL) {
        rc = memcached_set_error(*(server->root), MEMCACHED_TLS_ERROR, MEMCACHED_AT, memcached_literal_param("SSL context needs to be set with memcached_set_ssl_context()"));
        goto error;
    }
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
         rc = memcached_set_error(*(server->root), MEMCACHED_TLS_ERROR, MEMCACHED_AT, memcached_literal_param("Couldn't create new SSL instance"));
         goto error;
    }

    rc = memcached_ssl_connect(server, ssl);
    if (rc == MEMCACHED_SUCCESS) {
        server->state= MEMCACHED_SERVER_STATE_CONNECTED;
        return rc;
    } else {
        goto error;
    }

    error:
    if (ssl) {
        SSL_free(ssl);
    }
    server->reset_socket();
    return rc;
}

/**
 * SSL Connection initialization.
 */
memcached_return_t memcached_ssl_connect(memcached_instance_st *server, SSL *ssl) {
    if (server->privctx) {
        return memcached_set_error(*(server->root), MEMCACHED_TLS_ERROR, MEMCACHED_AT, memcached_literal_param("The server was already associated with SSL context"));
    }

    memcached_ssl *memc_ssl = (memcached_ssl*)calloc(1, sizeof(memcached_ssl));
    if (memc_ssl == NULL) {
        return memcached_set_error(*server, MEMCACHED_MEMORY_ALLOCATION_FAILURE, MEMCACHED_AT, memcached_literal_param("Out of memory"));
    }

    server->io_funcs = &context_ssl_funcs;

    SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    WATCHPOINT_ASSERT(server->fd != INVALID_SOCKET);
    SSL_set_fd(ssl, server->fd);
    SSL_set_connect_state(ssl);
    memc_ssl->ssl = ssl;

    ERR_clear_error();

    int rv = SSL_connect(ssl);
    if (rv == 1) {
        goto connection_success;
    }

    rv = SSL_get_error(ssl, rv);
    if ((server->root->flags.no_block) &&
        (rv == SSL_ERROR_WANT_READ || rv == SSL_ERROR_WANT_WRITE)) {
        goto connection_success;
    }


    char err[512];
    if (rv == SSL_ERROR_SYSCALL)
        snprintf(err,sizeof(err)-1,"SSL_connect failed: %s",strerror(errno));
    else {
        unsigned long e = ERR_peek_last_error();
        const char * e_reason = ERR_reason_error_string(e);
        if (e_reason == NULL) {
                int type= server->address_info_next->ai_socktype;
                if (SOCK_CLOEXEC)
                {
                  type|= SOCK_CLOEXEC;
                }

                if (SOCK_NONBLOCK)
                {
                  type|= SOCK_NONBLOCK;
                }
            snprintf(err, sizeof(err) - 1, "AI_FAMILY= %d, TYPE= %d, PROTOCOL=%d\n", server->address_info_next->ai_family,
                 type, server->address_info_next->ai_protocol);
            return memcached_set_error(*(server->root), MEMCACHED_TLS_CONNECTION_ERROR, MEMCACHED_AT, memcached_literal_param(err));
        }
        snprintf(err,sizeof(err)-1,"SSL_connect failed: %s", e_reason);
    }

    libmemcached_free(NULL, memc_ssl);

    return memcached_set_error(*(server->root), MEMCACHED_TLS_ERROR, MEMCACHED_AT, memcached_literal_param(err));

    connection_success:
    // Check if we need to set the server's file descriptor to non-blocking mode
    /*
    if (SOCK_NONBLOCK && (fcntl(server->fd, F_SETFL, SOCK_NONBLOCK) == -1)) {
        return memcached_set_error(*(server->root), MEMCACHED_TLS_ERROR, MEMCACHED_AT, memcached_literal_param("Could not switch to non-blocking.\n"));
    } */
    server->privctx = memc_ssl;
    return MEMCACHED_SUCCESS;
}


memcached_return_t memcached_set_ssl_context(memcached_st *ptr, memc_SSL_CTX *ssl_ctx) {
  //Memcached* ptr= memcached2Memcached(shell);
  if (ptr == NULL || ssl_ctx == NULL || ssl_ctx->ctx == NULL)
  {
    return MEMCACHED_INVALID_ARGUMENTS;
  }
  ptr->ssl_ctx = ssl_ctx;
  return memcached_behavior_set(ptr, MEMCACHED_BEHAVIOR_USE_TLS, 1);
}

void memc_free_SSL_ctx(memc_SSL_CTX *ssl_ctx)
{
    if (!ssl_ctx)
        return;

    if (ssl_ctx->server_name) {
        libmemcached_free(NULL, ssl_ctx->server_name);
        ssl_ctx->server_name = NULL;
    }

    if (ssl_ctx->ctx) {
        SSL_CTX_free(ssl_ctx->ctx);
        ssl_ctx->ctx = NULL;
    }

    libmemcached_free(NULL, ssl_ctx);
}

static int check_want(memcached_ssl *mssl, int rv) {
    /**
     * If the error is WANT_READ or WANT_WRITE, the appropriate flags are set
     * and true is returned. False is returned otherwise
     */
    if (rv == SSL_ERROR_WANT_READ) {
        mssl->want_read = 1;
        return 1;
    } else if (rv == SSL_ERROR_WANT_WRITE) {
        mssl->pending_write = 1;
        return 1;
    } else {
        return 0;
    }
}

ssize_t memcached_ssl_read(memcached_instance_st* instance,
             char* input_buf,
             size_t buffer_length,
             int flags){
    memcached_ssl *memc_ssl = (memcached_ssl*)instance->privctx;
    SSL *ssl = memc_ssl->ssl;

    int nread = SSL_read(ssl, input_buf, buffer_length);
    if (nread >= 0) {
        return nread;
    } else {
        int err = SSL_get_error(ssl, nread);
        if (memcached_is_no_block(instance->root)) {
            /**
             * In blocking mode, we should never end up in a situation where
             * we get an error without it being an actual error, except
             * in the case of EINTR, which can be spuriously received from
             * debuggers or whatever.
             */
            if (errno == EINTR) {
                return 0;
            } else {
                const char *msg = NULL;
                if (errno == EAGAIN) {
                    msg = "Resource temporarily unavailable";
                }
                memcached_set_error(*instance, MEMCACHED_READ_FAILURE, MEMCACHED_AT, memcached_literal_param(msg));
                return -1;
            }
        }

        /**
         * We can very well get an EWOULDBLOCK/EAGAIN, however
         */
        if (check_want(memc_ssl, err)) {
            return 0;
        } else {
            memcached_set_error(*instance, MEMCACHED_READ_FAILURE, MEMCACHED_AT);
            return -1;
        }
    }
}

ssize_t memcached_ssl_write(memcached_instance_st* instance,
             char* local_write_ptr,
             size_t write_length,
             int flags){
    memcached_ssl *memc_ssl = (memcached_ssl*)instance->privctx;
    SSL *ssl = memc_ssl->ssl;
    size_t len = memc_ssl->last_len ? memc_ssl->last_len : write_length;
    int rv = SSL_write(ssl, local_write_ptr, len);

    if (rv > 0) {
        memc_ssl->last_len = 0;
    } else if (rv < 0) {
        memc_ssl->last_len = len;

        int err = SSL_get_error(ssl, rv);
        if (memcached_is_no_block(instance->root) && check_want(memc_ssl, err)) {
            return 0;
        } else {
            memcached_set_error(*instance, MEMCACHED_WRITE_FAILURE, MEMCACHED_AT);
            return -1;
        }
    }
    return rv;
}

SSL_CTX* init_ctx(void)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
	SSL_load_error_strings();   /* Bring in and register error messages */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    method = TLS_client_method();
#else
    method = TLSv1_2_client_method();
#endif

	ctx = SSL_CTX_new(method);   /* Create new context */
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

memcached_return_t memcached_ssl_get_server_certs(memcached_instance_st * instance, char ** output)
{
    SSL* ssl;
    X509 *cert;
    char *line;
    if (instance->privctx == NULL) {
        return memcached_set_error(*instance, MEMCACHED_TLS_ERROR, MEMCACHED_AT, memcached_literal_param("The instance doesn't have SSL context\n"));
    }
    ssl = ((memcached_ssl *)instance->privctx)->ssl;
    if (ssl == NULL) {
        return memcached_set_error(*instance, MEMCACHED_TLS_ERROR, MEMCACHED_AT, memcached_literal_param("SSL connection wasn't yet established for this server\n"));
    }
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        char * certs_msg = (char *)libmemcached_malloc(instance->root, 100);
        snprintf(certs_msg,sizeof(certs_msg)-1,"Server certificates:\n Subject: %s\n Issuer: %s\n",
                 X509_NAME_oneline(X509_get_subject_name(cert), 0, 0),
                 X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0));
        *output = certs_msg;
    }
    else
        return memcached_set_error(*instance, MEMCACHED_TLS_ERROR, MEMCACHED_AT, memcached_literal_param("No certificates.\n"));
}

#endif //USE_TLS