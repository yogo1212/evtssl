# how to

```
// create an object that creates/configures bufferevents
evt_ssl_t *factory = evt_ssl_create(evbase, "xkcd.com", 443, NULL, NULL);

// if you want to do anything special with SSL use evt_ssl_reconfigure

// evt_ssl_new_bev (fd = -1) returns an unconnected bufferevent that can
// be used with bufferevent_setfd, bufferevent_socket_connect,
// or evhttp_connection_base_bufferevent_new

// evt_ssl_listen and evt_ssl_connect are helpers for the creation of ready-to-use
// bufferevents.
// evt_ssl_listen uses an evconnlistener internally and binds to a single port.

// evt_ssl_connect starts a DNS lookup and returns the bufferevent immediately.
// the factory needs to stay alive until BEV_EVENT_CONNECTED event is triggered.
struct bufferevent *bev = evt_ssl_connect(factory);

// created bufferevents to need the factory anymore (except for those created
// using _connect that haven't had the BEV_EVENT_CONNECTED event be triggered)
evt_ssl_free(factory);
```


# problem

evtssl offers factory that 'produces' bufferevents.
The factory takes care of DNS and SSL and it's products don't depend on it's existence once a successful connection has been established.

The reasoning behind that is: Upon a connection loss, one will wan't to reset the transport layer. When using TLS, that's horribly complicated - even more when it's supposed to happen asynchronously.

Or: I didn't want to write this code twice. If you are dealing with SSL and libevent, feel free to use this library or steal some of the code ;-)
If you see something that should or could be done better, feel free to file a complaint or open a pull-request.
