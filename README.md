# concept

evtssl offers factory that 'produces' bufferevents.
The factory takes care of DNS and SSL and it's products don't depend on it's existence once a successful connection has been established.

The reasoning behind that is: Upon a connection loss, one will wan't to reset the transport layer. When using TLS, that's horribly complicated - even more when it's supposed to happen asynchronously.

Or: I didn't want to write this code twice. If you are dealing with SSL and libevent, feel free to use this library or steal some of the code ;-)
If you see something that should or could be done better, feel free to file a complaint or open a pull-request.
