#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/x509.h>

#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>
#include <event2/listener.h>

#include "openssl_hostname_validation.h"

#include "evtssl.h"

enum EVT_SSL_STATE {
	SSL_STATE_PREPARING,
	SSL_STATE_CONNECTING,
	SSL_STATE_CONNECTED,
	SSL_STATE_ERROR
};

// includes the terminating null byte
#define RFC_1035_NAME_MAX (255)

struct evt_ssl {
	char hostname[RFC_1035_NAME_MAX];
	int port;

	int family;

	bool dont_ssl;

	//TODO maybe heap is better w/ realloc
	char error[2048];
	size_t errorlen;
	evt_ssl_error_cb_t errorcb;
	enum EVT_SSL_STATE state;

	evt_ssl_info_cb_t infocb;

	evt_ssl_accept_cb_t accept_cb;

	SSL_CTX *ssl_ctx;

	// TODO dirty hack to find which bev a DNS lookup was for.. fix!
	struct bufferevent *bev;

	struct evconnlistener *evl;
	int listen_fd;

	void *ctx;
	struct evdns_base *dns_base;
	struct event_base *base;
};

static int ex_data_index;

const char *evt_ssl_get_hostname(evt_ssl_t *essl)
{
	return essl->hostname;
}

unsigned short evt_ssl_get_port(evt_ssl_t *essl)
{
	return essl->port;
}

void evt_ssl_set_info_cb(evt_ssl_t *essl, evt_ssl_info_cb_t infocb)
{
	essl->infocb = infocb;
}

void evt_ssl_dont_really_ssl(evt_ssl_t *essl)
{
	essl->dont_ssl = true;
}

static void evt_ssl_collectSSLerr(evt_ssl_t *essl, const char *prefix);
static void evt_ssl_call_errorcb(evt_ssl_t *essl, evt_ssl_error_t error);
static int cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg);

static void ssl_dns_callback(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
	evt_ssl_t *essl = ptr;

	if (errcode) {
		essl->errorlen = snprintf(essl->error, sizeof(essl->error), "couldn't resolve");
		evt_ssl_call_errorcb(essl, SSL_ERROR_DNS);
		essl->state = SSL_STATE_ERROR;
	}
	else {
		if (addr->ai_family == AF_INET) {
			((struct sockaddr_in *) addr->ai_addr)->sin_port = htons(essl->port);
		}
		else if (addr->ai_family == AF_INET6) {
			((struct sockaddr_in6 *) addr->ai_addr)->sin6_port = htons(essl->port);
		}
		else {
			essl->errorlen = snprintf(essl->error, sizeof(essl->error), "unknown ai_family: %d", addr->ai_family);
			evt_ssl_call_errorcb(essl, SSL_ERROR_DNS);
			goto end;
		}

		//add the port and - voila
		bufferevent_socket_connect(essl->bev, addr->ai_addr, addr->ai_addrlen);
	end:
		evutil_freeaddrinfo(addr);
		essl->state = SSL_STATE_CONNECTED;
	}

	evdns_base_free(essl->dns_base, 0);
	essl->dns_base = NULL;
	essl->bev = NULL;
}

static void default_ssl_error_handler(evt_ssl_t *essl, evt_ssl_error_t error)
{
	fprintf(stderr, "ERROR: ");

	switch (error) {
	case SSL_ERROR_INIT:
		fprintf(stderr, "SSL_INIT");
		break;
	case SSL_ERROR_CONFIG:
		fprintf(stderr, "SSL_INIT");
		break;
	case SSL_ERROR_DNS:
		fprintf(stderr, "SSL_INIT");
		break;
	case SSL_ERROR_ALERT:
		fprintf(stderr, "SSL_INIT");
		break;
	case SSL_ERROR_CONNECTION:
		fprintf(stderr, "SSL_CONNECTION");
		break;
	default:
		fprintf(stderr, "unknown error!!");
	}

	fprintf(stderr, " %s\n", evt_ssl_get_error_str(essl));
}

static void handle_openssl_error(const SSL *ssl, int type, int val)
{
	evt_ssl_t *essl = SSL_get_ex_data(ssl, ex_data_index);

	if (!essl->infocb) {
		return;
	}

	const char *str;

	int w;

	w = type & ~SSL_ST_MASK;

	if (w & SSL_ST_CONNECT) {
		str = "SSL_connect";
	}
	else if (w & SSL_ST_ACCEPT) {
		str = "SSL_accept";
	}
	else {
		str = "undefined";
	}

	size_t infolen;
	char info[1024];

	if (type & SSL_CB_LOOP) {
		infolen = snprintf(info, sizeof(info) - 1, "%s: %s", str, SSL_state_string_long(ssl));
		info[sizeof(info) - 1] = '\0';
		essl->infocb(essl, info, infolen);
	}
	else if (type & SSL_CB_ALERT) {
		str = (type & SSL_CB_READ) ? "read" : "write";
		infolen = snprintf(info, sizeof(info) - 1, "SSL3 alert %s: %s:%s\n",
			   str,
			   SSL_alert_type_string_long(val),
			   SSL_alert_desc_string_long(val));
		info[sizeof(info) - 1] = '\0';
		essl->infocb(essl, info, infolen);
	}
	else if (type & SSL_CB_EXIT) {
		if (val == 0) {
			infolen = snprintf(info, sizeof(info) - 1, "%s: failed in %s\n",
				   str, SSL_state_string_long(ssl));
			info[sizeof(info) - 1] = '\0';
			essl->infocb(essl, info, infolen);
		}
		else if (val < 0) {
			infolen = snprintf(info, sizeof(info) - 1, "%s: error in %s\n",
				   str, SSL_state_string_long(ssl));
			info[sizeof(info) - 1] = '\0';
			essl->infocb(essl, info, infolen);
		}

	}
}

static SSL *new_ssl(evt_ssl_t *essl)
{
	SSL *ssl = SSL_new(essl->ssl_ctx);
	if (!ssl) {
		evt_ssl_collectSSLerr(essl, "SSL_new");
		evt_ssl_call_errorcb(essl, SSL_ERROR_INIT);
		return NULL;
	}

	SSL_set_ex_data(ssl, ex_data_index, essl);
	return ssl;
}

static void acceptcb(
                     struct evconnlistener *listener,
                     int fd,
                     struct sockaddr *addr, int addrlen,
                     void *arg
                    )
{
	(void) listener;

	evt_ssl_t *essl = arg;

	// TODO nagle?
	//const int one = 1;
	//setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &one, sizeof(one));

	struct bufferevent *bev;
	if (essl->dont_ssl) {
		bev = bufferevent_socket_new(essl->base, fd, BEV_OPT_CLOSE_ON_FREE);
	} else {
		SSL *ssl = new_ssl(essl);
		if (!ssl)
			return;

		bev = bufferevent_openssl_socket_new(
		                                     essl->base, fd, ssl,
		                                     BUFFEREVENT_SSL_ACCEPTING,
		                                     BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS
		                                    );

		if (bev == NULL) {
			essl->errorlen = snprintf(essl->error, sizeof(essl->error), "couldn't accept ssl connection");
			evt_ssl_call_errorcb(essl, SSL_ERROR_CONNECTION);
			return;
		}

		bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);
	}

	essl->accept_cb(essl, bev, addr, addrlen);
}

int evt_ssl_listen(evt_ssl_t *essl, evt_ssl_accept_cb_t cb)
{
	essl->accept_cb = cb;

	if (essl->evl) {
		// TODO what do when already listening? that listener could be broken
		return -1;
	}

	essl->listen_fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (essl->listen_fd == -1) {
		essl->errorlen = snprintf(essl->error, sizeof(essl->error), "socket: %s", strerror(errno));
		evt_ssl_call_errorcb(essl, SSL_ERROR_INIT);
		return -1;
	}

	struct sockaddr_in6 sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin6_family = AF_INET6;
	sin.sin6_port = htons(essl->port);
	sin.sin6_addr = in6addr_any;

	// TODO if hostname != NULL set sin6_addr and maybe even check for ipv4?
	if (bind(essl->listen_fd, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
		essl->errorlen = snprintf(essl->error, sizeof(essl->error), "bind: %s", strerror(errno));
		evt_ssl_call_errorcb(essl, SSL_ERROR_INIT);
		goto cleanup_sock;
	}

	essl->evl = evconnlistener_new(
	                        essl->base, acceptcb, essl,
	                        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
	                        // TODO this might need to be configurable
	                        -1,
	                        essl->listen_fd
	                       );

	// this is not very helpful:
	//evconnlistener_set_error_cb(essl->evl, listener_error_cb);

	return evconnlistener_get_fd(essl->evl);

cleanup_sock:
	close(essl->listen_fd);
	essl->listen_fd = -1;
	return -1;
}

struct bufferevent *evt_ssl_new_filter(evt_ssl_t *essl, struct bufferevent *bev, enum bufferevent_ssl_state state)
{
	if (essl->dont_ssl)
		return bev;

	SSL *ssl = new_ssl(essl);
	if (!ssl)
		return NULL;

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	// Set hostname for SNI extension - TODO only do this for connecting?
	SSL_set_tlsext_host_name(ssl, essl->hostname);
#endif

	struct bufferevent *new = bufferevent_openssl_filter_new(essl->base, bev, ssl,
				state,
				BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

	bufferevent_openssl_set_allow_dirty_shutdown(new, 1);

	return new;
}

struct bufferevent *evt_ssl_new_bev(evt_ssl_t *essl)
{
	if (essl->hostname[0] == '\0') {
		essl->errorlen = snprintf(essl->error, sizeof(essl->error), "empty hostname");
		evt_ssl_call_errorcb(essl, SSL_ERROR_CONNECTION);
		return NULL;
	}

	if (essl->dont_ssl) {
		return bufferevent_socket_new(essl->base, -1, BEV_OPT_CLOSE_ON_FREE);
	}

	SSL *ssl = new_ssl(essl);
	if (!ssl)
		return NULL;

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	// Set hostname for SNI extension
	SSL_set_tlsext_host_name(ssl, essl->hostname);
#endif

	struct bufferevent *bev = bufferevent_openssl_socket_new(essl->base, -1, ssl,
				BUFFEREVENT_SSL_CONNECTING,
				BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

	bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);

	return bev;
}

struct bufferevent *evt_ssl_connect(evt_ssl_t *essl)
{
	if (essl->bev) {
		return NULL;
	}

	if (essl->port == 0) {
		essl->errorlen = snprintf(essl->error, sizeof(essl->error), "port is zero");
		evt_ssl_call_errorcb(essl, SSL_ERROR_INIT);
		return NULL;
	}

	essl->state = SSL_STATE_CONNECTING;
	// spawn dns-lookup
	essl->dns_base = evdns_base_new(essl->base, EVDNS_BASE_INITIALIZE_NAMESERVERS);

	struct evutil_addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = essl->family;
	hints.ai_flags = EVUTIL_AI_CANONNAME;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// essl->bev could be reset by the DNS callback
	essl->bev = evt_ssl_new_bev(essl);

	struct bufferevent *res = essl->bev;
	evdns_getaddrinfo(essl->dns_base, essl->hostname, NULL,
		  &hints, ssl_dns_callback, essl);

	return res;
}

void evt_ssl_set_family(evt_ssl_t *essl, int family)
{
	essl->family = family;
}

bool evt_ssl_reconfigure(evt_ssl_t *essl, evt_ssl_ssl_ctx_config_cb_t cb, void *ctx)
{
	if (essl->ssl_ctx)
		SSL_CTX_free(essl->ssl_ctx);

	essl->ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!essl->ssl_ctx) {
		evt_ssl_collectSSLerr(essl, "CTX_new");

		evt_ssl_call_errorcb(essl, SSL_ERROR_INIT);
		evt_ssl_free(essl);
		return false;
	}

	SSL_CTX_set_info_callback(essl->ssl_ctx, handle_openssl_error);

	/*
	 * This does default checks AND checks whether the certificate
	 * is actually for the host we're connecting to.
	 */
	SSL_CTX_set_cert_verify_callback(essl->ssl_ctx, cert_verify_callback, essl);

	SSL_CTX_set_default_verify_paths(essl->ssl_ctx);

	if (!cb)
		return true;

	const char *err = cb(essl, essl->ssl_ctx, ctx);
	if (err) {
		evt_ssl_collectSSLerr(essl, err);
		evt_ssl_call_errorcb(essl, SSL_ERROR_CONFIG);
		return false;
	}

	return true;
}

evt_ssl_t *evt_ssl_create(
	struct event_base *base,
	const char *hostname,
	const int port,
	void *ctx,
	evt_ssl_error_cb_t errorcb
)
{
	evt_ssl_lib_init();

	evt_ssl_t *essl = malloc(sizeof(evt_ssl_t));
	essl->base = base;
	essl->errorlen = 0;
	essl->state = SSL_STATE_PREPARING;
	essl->dont_ssl = false;
	essl->listen_fd = -1;
	essl->family = AF_UNSPEC;

	if (errorcb) {
		essl->errorcb = errorcb;
	}
	else {
		essl->errorcb = default_ssl_error_handler;
	}

	essl->infocb = NULL;

	if (hostname != NULL) {
		// TODO truncates silently
		strncpy(essl->hostname, hostname, sizeof(essl->hostname) - 1);
		essl->hostname[sizeof(essl->hostname) - 1] = '\0';
	}
	else {
		essl->hostname[0] = '\0';
	}
	essl->port = port;

	essl->ssl_ctx = NULL;
	essl->bev = NULL;
	essl->evl = NULL;
	essl->ctx = ctx;

	essl->dns_base = NULL;

	evt_ssl_reconfigure(essl, NULL, NULL);

	return essl;
}

static int cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg)
{
	evt_ssl_t *essl = (evt_ssl_t *) arg;
	HostnameValidationResult res = Error;

	X509 *server_cert = NULL;

	const char *res_str = NULL;

	if (X509_verify_cert(x509_ctx) <= 0) {
		res_str = X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx));
	}

	server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	if (!server_cert) {
		if (!res_str) {
			res_str = "current cert NULL!";
		}

		goto leave;
	}

	char cert_str[512];

	X509_NAME_oneline(X509_get_subject_name(server_cert), cert_str,
		  sizeof(cert_str));

	if (res_str) {
		goto leave;
	}


	res = validate_hostname(essl->hostname, server_cert);

	switch (res) {
		case MatchFound:
			break;

		case MatchNotFound:
			res_str = "MatchNotFound";
			break;

		case NoSANPresent:
			res_str = "NoSANPresent";
			break;

		case MalformedCertificate:
			res_str = "MalformedCertificate";
			break;

		case Error:
			res_str = "Error";
			break;

		default:
			res_str = "WTF!";
			break;
	}


	if (res == MatchFound) {
		return 1;
	}

leave:
	essl->errorlen = snprintf(essl->error, sizeof(essl->error) - 1,
		          "validating '%s' failed at '%s': '%s'", essl->hostname, server_cert ? cert_str : "", res_str);
	essl->error[sizeof(essl->error) - 1] = '\0';

	if (essl->errorcb) {
		essl->errorcb(essl, SSL_ERROR_INIT);
	}

	return 0;
}

static void evt_ssl_call_errorcb(evt_ssl_t *essl, evt_ssl_error_t error)
{
	if (essl->errorcb) {
		essl->errorcb(essl, error);
	}
}

void evt_ssl_free(evt_ssl_t *essl)
{
	if (!essl) {
		return;
	}

	if (essl->evl) {
		evconnlistener_free(essl->evl);
	}

	if (essl->listen_fd != -1) {
		close(essl->listen_fd);
	}

	if (essl->dns_base) {
		evdns_base_free(essl->dns_base, 0);
	}

	/*
	 * This will probably be done already by the bufferevent-destructor
	 * if (essl->ssl) {
	 *     SSL_shutdown(essl->ssl);
	 *     SSL_free(essl->ssl);
	 * }
	 */

	if (essl->ssl_ctx) {
		SSL_CTX_free(essl->ssl_ctx);
	}

	free(essl);

	evt_ssl_lib_cleanup();
}

static int libevent_ssl_SSL_error_cb(const char *str, size_t len, void *u)
{
	evt_ssl_t *essl = (evt_ssl_t *) u;

	if ((essl->errorlen + len) >= sizeof(essl->error)) {
		len = sizeof(essl->error) - essl->errorlen - 1;
	}

	if (len != 0) {
		strncpy(&essl->error[essl->errorlen], str, len);
		essl->errorlen += len;
	}

	return len;
}

static void evt_ssl_collectSSLerr(evt_ssl_t *essl, const char *prefix)
{
	if ((sizeof(essl->error) - essl->errorlen) <= strlen(prefix)) {
		essl->errorlen = sizeof(essl->error) - 1;
	}
	else {
		essl->errorlen = strlen(prefix);
	}

	if (essl->errorlen != 0) {
		strncpy(&essl->error[0], prefix, essl->errorlen);
	}

	ERR_print_errors_cb(libevent_ssl_SSL_error_cb, essl);
	essl->error[essl->errorlen] = '\0';
}

void *evt_ssl_get_ctx(evt_ssl_t *essl)
{
	return essl->ctx;
}

char *evt_ssl_get_error_str(evt_ssl_t *essl)
{
#if 0
	int errcode = EVUTIL_SOCKET_ERROR();

	/* Print out the OpenSSL error queue that libevent
	 * squirreled away for us, if any. */
	while ((oslerr = bufferevent_get_openssl_error(bev))) {
		ERR_error_string_n(oslerr, buffer, sizeof(buffer));
		fprintf(stderr, "%s\n", buffer);
		printed_err = 1;
	}

	/* If the OpenSSL error queue was empty, maybe it was a
	 * socket error; let's try printing that. */
	if (! printed_err)
		fprintf(stderr, "socket error = %s (%d)\n",
		        evutil_socket_error_to_string(errcode),
		        errcode);

	return;
#endif
	return essl->error;
}

static size_t lib_users = 0;

void evt_ssl_lib_init(void)
{
	lib_users++;

	if (lib_users > 1) {
		return;
	}

	// Initialize OpenSSL
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	ex_data_index = SSL_get_ex_new_index(0, "evt_ssl", NULL, NULL, NULL);
}

void evt_ssl_lib_cleanup(void)
{
	lib_users--;

	if (lib_users > 0) {
		return;
	}

	//CONF_modules_free();
	//ENGINE_cleanup();
	//CONF_modules_unload(1);
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}
