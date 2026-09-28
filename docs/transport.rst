Transport modes
===============

SIPp has several transport modes. The default transport mode is "UDP
mono socket".


UDP mono socket
```````````````

In UDP mono socket mode (-t u1 command line parameter), one IP/UDP
socket is opened between SIPp and the remote. All calls are placed
using this socket.

This mode is generally used for emulating a relation between 2 SIP
servers.


UDP multi socket
````````````````

In UDP multi socket mode (-t un command line parameter), one IP/UDP
socket is opened for each new call between SIPp and the remote.

This mode is generally used for emulating user agents calling a SIP
server.


UDP with one socket per IP address
``````````````````````````````````

In UDP with one socket per IP address mode (-t ui command line
parameter), one IP/UDP socket is opened for each IP address given in
the inf file.

In addition to the "-t ui" command line parameter, one must indicate
which field in the inf file is to be used as local IP address for this
given call. Use "-ip_field <nb>" to provide the field number.

There are two distinct cases to use this feature:


+ Client side: when using -t ui for a client, SIPp will originate each
  call with a different IP address, as provided in the inf file. In this
  case, when your IP addresses are in field X of the inject file, then
  you have to use [fieldX] instead of [local_ip] in your UAC XML
  scenario file.
+ Server side: when using -t ui for a server, SIPp will bind itself to
  all the IP addresses listed in the inf file instead of using 0.0.0.0.
  This will have the effect SIPp will answer the request on the same IP
  on which it received the request. In order to have proper Contact and
  Via fields, a keyword [server_ip] can be used and provides the IP
  address on which a request was received. So when using this, you have
  to replace the [local_ip] in your UAS XML scenario file by
  [server_ip].


In the following diagram, the command line for a client scenario will
look like: ./sipp -sf myscenario.xml -t ui -inf database.csv -ip_field
2 192.168.1.1
By doing so, each new call will come sequentially from IP 192.168.0.1,
192.168.0.2, 192.168.0.3, 192.168.0.1, ...



This mode is generally used for emulating user agents, using on IP
address per user agent and calling a SIP server.


TCP mono socket
```````````````

In TCP mono socket mode (-t t1 command line parameter), one IP/TCP
socket is opened between SIPp and the remote. All calls are placed
using this socket.

This mode is generally used for emulating a relation between 2 SIP
servers.


TCP multi socket
````````````````

In TCP multi socket mode (-t tn command line parameter), one IP/TCP
socket is opened for each new call between SIPp and the remote.

This mode is generally used for emulating user agents calling a SIP
server.


TCP reconnections
`````````````````

SIPp handles TCP reconnections. In case the TCP socket is lost, SIPp
will try to reconnect. The following parameters on the command line
control this behaviour:


+ -max_reconnect : Set the maximum number of reconnection attempts.
+ -reconnect_close true/false : Should calls be closed on reconnect?
+ -reconnect_sleep int : How long to sleep (in milliseconds) between
  the close and reconnect?



TLS mono socket
```````````````

In TLS mono socket mode (-t l1 command line parameter), one secured
TLS (Transport Layer Security) socket is opened between SIPp and the
remote. All calls are placed using this socket.

This mode is generally used for emulating a relation between 2 SIP
servers.

.. warning::
  When using TLS transport, SIPp will expect to have two files in the
  current directory: a certificate (cacert.pem) and a key (cakey.pem),
  or the ones -tls_cert and -tls_key name.
  If one is protected with a password, SIPp will ask for it.
  A client (UAC) may go without them: when neither -tls_cert nor
  -tls_key is given and neither default file exists, it connects
  without a certificate, and TLS connections made to it fail. A file
  that -tls_cert or -tls_key names must exist.
  The certificate file (-tls_cert) may also hold the intermediate CA
  certificates, after the end-entity one; SIPp sends them to the peer.

SIPp supports X509's CRL (Certificate Revocation List). The CRL is
read and used if -tls_crl command line specifies a CRL file to read.

A TLS handshake may take up to -tls_handshake_timeout (10 seconds by
default, 0 for no limit); SIPp handles nothing else meanwhile. A handshake that fails
or times out drops its connection: SIPp keeps serving the others.


TLS multi socket
````````````````

In TLS multi socket mode (-t ln command line parameter), one secured
TLS (Transport Layer Security) socket is opened for each new call
between SIPp and the remote.

This mode is generally used for emulating user agents calling a SIP
server.


WebSocket
`````````

SIPp carries SIP over WebSocket (RFC 7118), as WebRTC user agents and
the servers they connect to do:

+ -t w1 and -t wn: WebSocket (WS) over TCP, with one socket, or with one
  socket per call.
+ -t x1 and -t xn: secure WebSocket (WSS) over TLS, with one socket, or
  with one socket per call. The certificate files and the -tls_* options
  are those of TLS.

A client connects, and asks for the sip subprotocol in its WebSocket
handshake, on the -ws_path path ("/" by default); its SIP messages wait
until the server accepts it. A server takes the handshake of any path.
Each SIP message goes in a WebSocket message of its own: a text frame,
or a binary frame if it is not UTF-8. The [transport] keyword is WS or
WSS, as the Via transport should be.

The following example runs a UAS over WSS on port 5061, and a UAC that
checks its certificate and asks for the /ws path:

::

    ./sipp -sn uas -t x1 -tls_cert cert.pem -tls_key key.pem -p 5061
    ./sipp -sn uac -t x1 -tls_ca cert.pem -ws_path /ws 127.0.0.1:5061

A WebSocket connection is lost, and reconnected, as a TCP one is. Its
handshake may take up to -ws_handshake_timeout (10 seconds by default,
0 for no limit): a client that gets no answer in time drops the
connection, and makes it again if -max_reconnect allows, or stops; a
server drops a connection whose client sends no handshake request.
Until the handshake is done, a client holds up to 16 times the largest
message size of messages for it; past that, it sends no more (as when
the connection is full) and warns.


SCTP mono socket
````````````````

In SCTP mono socket mode (-t s1 command line parameter), one SCTP
(Stream Transmission Control Protocol) socket is opened between SIPp
and the remote. All calls are placed using this socket.

This mode is generally used for emulating a relation between 2 SIP
servers.

The -multihome, -heartbeat, -assocmaxret, -pathmaxret, -pmtu and
-gracefulclose command-line arguments allow control over specific
features of the SCTP protocol, but are usually not necessary.


SCTP multi socket
`````````````````

In SCTP multi socket mode (-t sn command line parameter), one SCTP
socket is opened for each new call between SIPp and the remote.

This mode is generally used for emulating user agents calling a SIP
server.


IPv6 support
````````````

SIPp includes IPv6 support. To use IPv6, just specify the local IP
address (-i command line parameter) to be an IPv6 IP address.

The following example launches a UAS server listening on port 5063 and
a UAC client sending IPv6 traffic to that port.

::

    ./sipp -sn uas -i [fe80::204:75ff:fe4d:19d9] -p 5063
    ./sipp -sn uac -i [fe80::204:75ff:fe4d:19d9] [fe80::204:75ff:fe4d:19d9]:5063

A host name (the remote host, -rsa or setdest) that resolves to several
addresses prefers one in the family of the -i address: with -i
127.0.0.1, localhost is 127.0.0.1 even where it is ::1 first.


Multi-socket limit
``````````````````

When using one of the "multi-socket" transports, the maximum number of
sockets that can be opened (which corresponds to the number of
simultaneous calls) will be determined by the system (see how to
increase file descriptors section to modify those limits). You can
also limit the number of socket used by using the -max_socket command
line option. It counts the call sockets only, not the main, control
(-cp) or stdin sockets. Once the maximum number of opened sockets is
reached, the traffic will be distributed over the sockets already
opened.
