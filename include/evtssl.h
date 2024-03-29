#ifndef __EVT_SSL_H
#define __EVT_SSL_H

#include <stdbool.h>

#include <openssl/ssl.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>


struct evt_ssl;
typedef struct evt_ssl evt_ssl_t;

typedef enum {
	// errorstr
	SSL_ERROR_INIT,
	SSL_ERROR_CONFIG,
	SSL_ERROR_DNS,
	SSL_ERROR_ALERT,
	SSL_ERROR_CONNECTION
} evt_ssl_error_t;

typedef void (*evt_ssl_error_cb_t)(evt_ssl_t *essl, evt_ssl_error_t error);

evt_ssl_t *evt_ssl_create(
	struct event_base *base,
	const char *hostname,
	const int port,
	void *userptr,
	evt_ssl_error_cb_t errorcb
);
void evt_ssl_free(evt_ssl_t *essl);

/* Return NULL if everything went ok or a string containing an error */
typedef const char *(*evt_ssl_ssl_ctx_config_cb_t)(evt_ssl_t *essl, SSL_CTX *ssl_ctx, void *ctx);
bool evt_ssl_reconfigure(evt_ssl_t *essl, evt_ssl_ssl_ctx_config_cb_t cb, void *ctx);

typedef void (*evt_ssl_info_cb_t)(evt_ssl_t *ess, char *msg, size_t msglen);
void evt_ssl_set_info_cb(evt_ssl_t *essl, evt_ssl_info_cb_t infocb);

const char *evt_ssl_get_error_str(evt_ssl_t *essl);
void evt_ssl_dont_really_ssl(evt_ssl_t *essl);

void evt_ssl_set_family(evt_ssl_t *essl, int family);

typedef void (*evt_ssl_accept_cb_t)(evt_ssl_t *essl, struct bufferevent *bev, struct sockaddr *addr, int addrlen);
// TODO returns the FD that is being listened on
int evt_ssl_listen(evt_ssl_t *essl, evt_ssl_accept_cb_t cb);

struct bufferevent *evt_ssl_connect(evt_ssl_t *essl);
/*
 * yields a configured - unconnected - bufferevent
 * use with bufferevent_setfd, bufferevent_socket_connect, or evhttp_connection_base_bufferevent_new
 */
struct bufferevent *evt_ssl_new_bev(evt_ssl_t *essl, int fd, bool accepting);

struct bufferevent *evt_ssl_new_filter(evt_ssl_t *essl, struct bufferevent *bev, bool accepting);

const char *evt_ssl_get_hostname(evt_ssl_t *essl);
unsigned short evt_ssl_get_port(evt_ssl_t *essl);
void *evt_ssl_get_ctx(evt_ssl_t *essl);

/*
 * init openssl and add an index for evt_ssl
 * after _init has been called n times, the n-th call to _cleanup will cleanup openssl
 * evt_ssl will call those automatically
 * (-> will annoy you horribly when you use openssl elsewhere)
 */
void evt_ssl_lib_init(void);
void evt_ssl_lib_cleanup(void);

#endif
