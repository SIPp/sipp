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

UDP requests use an RFC 8489-style retransmission loop with a 500 ms initial
RTO. Malformed, unrelated, wrong-source and wrong-transaction responses are
ignored until the overall ``--timeout`` deadline expires. The response
FINGERPRINT, when present, is validated before ``XOR-MAPPED-ADDRESS`` is
returned.

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
that a SIPp RTP/SDP candidate is expected to use. Without ``--bind`` the
operating system chooses an ephemeral source port, so the command only checks
that the peer candidate responds to an authenticated STUN request.

The request contains USERNAME, PRIORITY, ICE-CONTROLLING or ICE-CONTROLLED,
MESSAGE-INTEGRITY and FINGERPRINT. ``--use-candidate`` is valid only for the
controlling role; using it with ``--controlled`` is rejected. A 487 response
is reported explicitly as an ICE role conflict.

The response MESSAGE-INTEGRITY is verified with the short-term ICE credential
before its mapped address is accepted. Protocol tests include the RFC 5769
MESSAGE-INTEGRITY and FINGERPRINT vector plus IPv4 and IPv6 loopback UDP round
trips.

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
the helper consumes the fresh nonce and retries exactly once.

Usernames and passwords are processed with SASLprep before the TURN long-term
key is derived. Passwords may be supplied with ``--password``, read from a
file with ``--password-file``, or read from an environment variable named by
``--password-env``.

By default, a successful allocation is immediately released with an
authenticated Refresh request carrying ``LIFETIME=0``. This prevents repeated
diagnostic runs from consuming relay quota for the server's default lifetime.
Use ``--keep`` only when a caller intentionally needs the allocation to remain
active after the probe exits.

Successful allocation output includes the relayed address and the lifetime
reported by the Allocate response, followed by ``released`` or ``kept``.

Endpoint parsing
----------------

The companion probes share ``tools/sipp_endpoint.py`` for strict
``HOST:PORT`` parsing. IPv6 literals must be bracketed. For example,
``[::1]:3478`` is accepted while ``::1:3478`` is rejected as ambiguous.

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
