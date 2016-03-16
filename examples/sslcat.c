#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

#include "evtssl.h"

typedef struct {
	const char *host;
	unsigned long port;
	const char *cafile;
	const char *cadir;
	const char *key;
	const char *cert;
	bool nossl;
	bool listen;
} nc_opts_t;

typedef struct {
	struct event_base *base;
	struct event *sig_event;

	evt_ssl_t *essl;

	struct event *evt_in;
	struct event *evt_out;
	struct bufferevent *ssl;

	nc_opts_t no;
} sslcat_t;

#define wnjb(a) (a & ~(EAGAIN | EWOULDBLOCK))

static void stdout_cb(evutil_socket_t fd, short events, void *ctx)
{
	sslcat_t *sc = ctx;

	ssize_t rlen;
	uint8_t buf[512];
	if (events & EV_READ) {
		rlen = read(fd, buf, sizeof(buf));
		// so, from time to time this callback just runs EAGAIN
		// sometimes there's even data!! wtf? bricks where shat
		if (rlen == 0) {
			fprintf(stderr, "stdout was closed\n");
			goto ouch_fd;
		}
		else if ((rlen == -1) && wnjb(errno)) {
			fprintf(stderr, "stdout ouched (%zd,%d): %s\n", rlen, errno, strerror(errno));
			goto ouch_fd;
		}
	}

	ssize_t wlen;
	struct evbuffer *evb = bufferevent_get_input(sc->ssl);
	while ((rlen = evbuffer_copyout(evb, buf, sizeof(buf))) > 0) {
		wlen = write(fd, buf, rlen);
		if (wlen == -1) {
			if (!wnjb(errno)) {
				break;
			}
			else {
				fprintf(stderr, "stdout had an accident: %s\n", strerror(errno));
				goto ouch;
			}
		}
		evbuffer_drain(evb, wlen);
	}

	if (evbuffer_get_length(evb) > 0)
		event_add(sc->evt_out, NULL);

	return;
ouch_fd:
	close(fd);

ouch:
	event_free(sc->evt_in);
	sc->evt_in = NULL;

	if (!sc->evt_out)
		event_base_loopbreak(sc->base);
}

static void stdin_cb(evutil_socket_t fd, short events, void *ctx)
{
	(void) events;

	sslcat_t *sc = ctx;

	char buf[512];
	ssize_t len;
	while ((len = read(fd, buf, sizeof(buf))) > 0) {
		bufferevent_write(sc->ssl, buf, len);
	}

	if (len == 0) {
		fprintf(stderr, "stdin was closed\n");
		close(STDIN_FILENO);
		goto ouch;
	}
	else if ((len == -1) && wnjb(errno)) {
		fprintf(stderr, "stdin had an accident: %s\n", strerror(errno));
		goto ouch;
	}

	return;
ouch:
	event_free(sc->evt_in);
	sc->evt_in = NULL;

	if (!sc->evt_out)
		event_base_loopbreak(sc->base);
}

static void ssleventcb(struct bufferevent *bev, short events, void *ctx)
{
	(void) bev;

	sslcat_t *sc = ctx;

	if (events & BEV_EVENT_CONNECTED) {
		event_add(sc->evt_in, NULL);
	}
	else if (events & BEV_EVENT_ERROR) {
		fprintf(stderr, "connection had an accident: %d\n", EVUTIL_SOCKET_ERROR());
	}
	else if (events & BEV_EVENT_TIMEOUT) {
		fprintf(stderr, "connection timed out\n");
	}
	else if (events & BEV_EVENT_EOF) {
		fprintf(stderr, "connection was closed: %d\n", events);
		event_base_loopbreak(sc->base);
	}
}

static void sslreadcb(struct bufferevent *bev, void *ctx)
{
	(void) bev;

	sslcat_t *sc = ctx;

	if (sc->evt_out) {
		event_add(sc->evt_out, NULL);
	}
	else{
		fprintf(stderr, "stdout closed\n");
		event_base_loopbreak(sc->base);
	}
}

static void handle_interrupt(int fd, short events, void *arg)
{
	(void) fd;
	(void) events;

	sslcat_t *sc = arg;

	event_base_loopbreak(sc->base);
}

static struct event_base *get_fd_rdy_event_base(void)
{
  struct event_config *evcfg = event_config_new();
  event_config_require_features(evcfg, EV_FEATURE_FDS);
  struct event_base *base = event_base_new_with_config(evcfg);
  event_config_free(evcfg);
  return base;
}

static bool ssl_error_cb(evt_ssl_t *essl, evt_ssl_error_t error)
{
	sslcat_t *sc = evt_ssl_get_ctx(essl);

	fprintf(stderr, "ssl error(%d): %s\n", error, evt_ssl_get_error_str(essl));

	event_base_loopbreak(sc->base);

	return false;
}

static void set_ssl_bev(sslcat_t *sc, struct bufferevent *bev)
{
	sc->ssl = bev;
	bufferevent_setcb(bev, sslreadcb, NULL, ssleventcb, sc);
	bufferevent_enable(bev, EV_READ | EV_WRITE);
}

static void accept_cb(evt_ssl_t *essl, struct bufferevent *bev, struct sockaddr *addr, int addrlen)
{
	(void) addr;
	(void) addrlen;

	sslcat_t *sc = evt_ssl_get_ctx(essl);

	set_ssl_bev(sc, bev);
}

enum option_repr {
	opt_host = 1,
	opt_port,
	opt_cafile,
	opt_cadir,
	opt_key,
	opt_cert,
	opt_nossl,
	opt_listen,
};
static struct option options[] = {
	{ "host", 1, NULL, opt_host },
	{ "port", 1, NULL, opt_port },
	{ "cafile", 1, NULL, opt_cafile },
	{ "cadir", 1, NULL, opt_cadir },
	{ "key", 1, NULL, opt_key },
	{ "cert", 1, NULL, opt_cert },
	{ "nossl", 0, NULL, opt_nossl },
	{ "listen", 0, NULL, opt_listen },
	{ NULL, 0, NULL, 0 }
};

static void print_help(void)
{
	struct option *opt = &options[0];
	while (opt->name) {
		fputs("--", stdout);
		fputs(opt->name, stdout);
		if (opt->has_arg > 0) {
			fputs(" ", stdout);
			if (opt->has_arg > 1)
				fputs("[", stdout);
			fputs("arg", stdout);
			if (opt->has_arg > 1)
				fputs("]", stdout);
		}
		puts("");
		opt++;
	}
}

// TODO option, arg, param... naming?

static bool parse_args(nc_opts_t *no, int argc, char *argv[])
{
	int c;
	memset(no, 0, sizeof(nc_opts_t));

	while ((c = getopt_long(argc, argv, "", options, NULL)) != -1) {
		if ((c == '?') || (c == ':')) {
			fprintf(stderr, "getopt failed (%c)\n", c);
			break;
		}

		switch (c) {
		case opt_host:
			no->host = optarg;
			break;
		case opt_port:
			errno = 0;
			no->port = strtoul(optarg, NULL, 0);
			if (errno != 0) {
				fprintf(stderr, "can't convert port: %s\n", strerror(errno));
				return false;
			}
			break;
		case opt_cafile:
			no->cafile = optarg;
			break;
		case opt_cadir:
			no->cadir = optarg;
			break;
		case opt_key:
			no->key = optarg;
			break;
		case opt_cert:
			no->cert = optarg;
			break;
		case opt_nossl:
			no->nossl = true;
			break;
		case opt_listen:
			no->listen = true;
			break;
		default:
			fprintf(stderr, "getopt_long huh? (%d)\n", c);
			break;
		}
	}

	return true;
}

static const char *config_ssl(evt_ssl_t *essl, SSL_CTX *ssl_ctx)
{
	sslcat_t *sc = evt_ssl_get_ctx(essl);

	if (sc->no.cafile || sc->no.cadir) {
		if (SSL_CTX_load_verify_locations(ssl_ctx, sc->no.cafile, sc->no.cadir) < 1) {
			return "ca-error!";
		}
	}

	if (sc->no.cert) {
		if (SSL_CTX_use_certificate_file(ssl_ctx, sc->no.cert, SSL_FILETYPE_PEM) < 1) {
			return "couldn't set certificate!";
		}
	}

	if (sc->no.key) {
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx, sc->no.key, SSL_FILETYPE_PEM) < 1) {
			return "couldn't set private key!";
		}

		if (SSL_CTX_check_private_key(ssl_ctx) < 1) {
		  return "invalid private key!";
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	if (argc == 1) {
		print_help();
		return EXIT_SUCCESS;
	}

	sslcat_t sc;
	sc.base = get_fd_rdy_event_base();

	if (!sc.base) {
		fprintf(stderr, "no evbase.. aborting\n");
		return -1;
	}

	if (!parse_args(&sc.no, argc, argv))
		return EXIT_FAILURE;

	sc.essl = evt_ssl_create(
	       	sc.base,
	       	sc.no.host,
	       	sc.no.port,
	       	&sc,
	       	config_ssl,
	       	ssl_error_cb
	       );

	if (!sc.essl) {
		fprintf(stderr, "failed to init essl\n");
		return -1;
	}

	if (sc.no.nossl)
		evt_ssl_dont_really_ssl(sc.essl);

	evutil_make_socket_nonblocking(STDIN_FILENO);
	sc.evt_in = event_new(sc.base, STDIN_FILENO, EV_READ | EV_PERSIST, stdin_cb, &sc);

	evutil_make_socket_nonblocking(STDOUT_FILENO);
	// EV_READ is in order to receive close-events
	sc.evt_out = event_new(sc.base, STDOUT_FILENO, EV_READ | EV_WRITE | EV_PERSIST, stdout_cb, &sc);

	if (sc.no.listen) {
		evt_ssl_listen(sc.essl, accept_cb);
	}
	else {
		set_ssl_bev(&sc, evt_ssl_connect(sc.essl));
	}

	sc.sig_event = evsignal_new(sc.base, SIGINT, handle_interrupt, sc.essl);

	event_add(sc.sig_event, NULL);
	event_base_dispatch(sc.base);
	event_free(sc.sig_event);

	bufferevent_free(sc.ssl);

	event_free(sc.evt_out);
	event_free(sc.evt_in);

	evt_ssl_free(sc.essl);

	event_base_free(sc.base);

	return EXIT_SUCCESS;
}
