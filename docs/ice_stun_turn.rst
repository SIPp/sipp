ICE, STUN and TURN probes
=========================

``tools/sipp_ice.py`` provides small protocol probes for WebRTC-facing SIPp
tests. It uses only the Python standard library and is intended to complement
SIPp's SIP-over-WebSocket support with media-path diagnostics.

This work is related to `SIPp issue #339 <https://github.com/SIPp/sipp/issues/339>`_:
it exercises outbound STUN, ICE connectivity checks and TURN reachability
around SIPp scenarios. It is not the ICE-lite responder described in that
issue. In particular, it does not make SIPp answer browser Binding requests on
an RTP socket, so it does not by itself complete the browser-to-SIPp WebRTC
media path.

STUN binding
------------

Discover the server-reflexive address seen by a STUN server::

    python3 tools/sipp_ice.py stun stun.example.net:3478

Hostnames are resolved through the system resolver and both IPv4 and IPv6 UDP
addresses are supported. Literal IPv6 endpoints must use bracket notation, for
example ``[2001:db8::20]:3478``.

UDP requests follow the RFC 8489 retransmission schedule: an initial RTO of
500 ms doubled after each request, at most seven requests (Rc=7), and a final
wait of 16 × RTO (Rm=16) after the last one. ``--timeout`` (3 seconds by
default) is one overall deadline: it covers all retransmissions and all
resolved addresses of the server. For ``turn-allocate``, the allocation
transactions (the challenge, the authenticated Allocate and a 438 retry)
share one such deadline, and the release (its Refresh and a 438 retry) gets
its own deadline of the same length, so a slow Allocate cannot leave the
release without time; the command can therefore take up to twice
``--timeout``. When a host name resolves to several addresses, the remaining
time is split between the addresses still to be tried.

Malformed, unrelated, wrong-source and wrong-transaction datagrams, and
responses whose FINGERPRINT does not verify, are dropped and the probe keeps
waiting for a valid response until the deadline expires.

ICE connectivity checks
-----------------------

Send an authenticated ICE connectivity check to a remote candidate::

    python3 tools/sipp_ice.py ice-check 203.0.113.20:50000 \
      --local-ufrag local1 \
      --remote-ufrag remote1 \
      --remote-password-file /run/secrets/ice-password \
      --bind 192.0.2.10:40000 \
      --use-candidate

``--bind HOST:PORT`` makes the check originate from the source address and port
that a SIPp RTP/SDP candidate is expected to use. ``--bind HOST:0`` pins the
source address (for example a particular interface) while letting the
operating system choose the port. Without ``--bind`` the operating system
chooses both, so the command only checks that the peer candidate responds to
an authenticated STUN request.

The probe opens its own socket, so ``--bind`` fails with ``EADDRINUSE``
(``Address already in use``) on a port that SIPp, or any other process,
already holds. Run the check while the port is free, for example before SIPp
starts or after it exits.

The request contains USERNAME, PRIORITY, ICE-CONTROLLING or ICE-CONTROLLED,
MESSAGE-INTEGRITY and FINGERPRINT. ``--use-candidate`` is valid only for the
controlling role; using it with ``--controlled`` is rejected. A 487 response
is reported explicitly as an ICE role conflict.

The response MESSAGE-INTEGRITY is verified with the short-term ICE credential
before its mapped address is accepted. Protocol tests include the RFC 5769
short-term (section 2.1) and long-term (section 2.4) MESSAGE-INTEGRITY
vectors, and IPv4 and IPv6 loopback UDP round trips for ``stun``,
``ice-check`` and ``turn-allocate`` against mock servers.

ICE passwords may be supplied directly with ``--remote-password``, read from a
file with ``--remote-password-file``, or read from an environment variable
named by ``--remote-password-env``. File or environment input avoids placing
the secret directly in the process argument list.

TURN allocation
---------------

Allocate a UDP relay using TURN long-term credentials::

    python3 tools/sipp_ice.py turn-allocate turn.example.net:3478 \
      --username loadtest \
      --password-file /run/secrets/turn-password

The helper performs the initial unauthenticated Allocate request, consumes the
401/438 REALM and NONCE challenge, derives the long-term key and retries with
MESSAGE-INTEGRITY. The authenticated request is pinned to the same resolved
server address that returned the challenge. If it receives a 438 Stale Nonce,
the helper consumes the fresh nonce and retries exactly once. Any other error
response to the first request is reported as an allocation failure.

Every transaction with the server address that answered, including the
release, goes through one UDP socket and so comes from the same client address
and port. A TURN server identifies an allocation by this 5-tuple and answers a
Refresh from any other source with 437 Allocation Mismatch.

If the server accepts the first, unauthenticated Allocate, the allocation is
reported with an ``unauthenticated`` marker and a warning on stderr, and it is
released with an unauthenticated Refresh like any other allocation.

Usernames and passwords are processed with SASLprep before the TURN long-term
key is derived. Passwords may be supplied with ``--password``, read from a
file with ``--password-file``, or read from an environment variable named by
``--password-env``.

By default, a successful allocation is immediately released with an
authenticated Refresh request carrying ``LIFETIME=0`` (a 438 Stale Nonce on the
Refresh is retried once with the fresh nonce). This prevents repeated
diagnostic runs from consuming relay quota for the server's default lifetime.
Use ``--keep`` only when a caller intentionally needs the allocation to remain
active after the probe exits.

If an Allocate success response is unusable (its XOR-RELAYED-ADDRESS is missing
or malformed, or its MESSAGE-INTEGRITY does not verify), the command fails,
but unless ``--keep`` is given the helper still makes a best-effort release in
case the server did create the allocation.

Successful allocation output includes the relayed address and the lifetime
reported by the Allocate response, followed by ``released``, ``kept`` or
``release-failed``. ``release-failed`` means the allocation succeeded but the
release Refresh failed or ran out of time; the relay address is still
printed, a warning with the reason goes to stderr, the exit status stays 0,
and the allocation remains on the server until its lifetime expires.

Endpoint parsing
----------------

The companion probes share ``tools/sipp_endpoint.py`` for strict
``HOST:PORT`` parsing. IPv6 literals must be bracketed. For example,
``[::1]:3478`` is accepted while ``::1:3478`` is rejected as ambiguous.
Printed addresses use the same notation.

Scope
-----

This probe helps with the STUN/TURN reachability and outbound
connectivity-check part of the media work discussed in
`SIPp issue #339 <https://github.com/SIPp/sipp/issues/339>`_. It does not
implement the ICE-lite responder a browser needs before sending media to SIPp,
a complete ICE state machine, TURN permission/channel lifecycle, consent
freshness, trickle ICE, DTLS-SRTP, or integration with SIPp's native RTP
stream.

Those pieces can be layered separately without changing SIPp's call scheduler.
