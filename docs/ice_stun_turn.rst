ICE, STUN and TURN probes
=========================

``tools/sipp_ice.py`` provides small protocol probes for WebRTC-facing SIPp
tests. It uses only the Python standard library and is intended to complement
SIPp's SIP-over-WebSocket support with media-path diagnostics.

STUN binding
------------

Discover the server-reflexive address seen by a STUN server::

    python3 tools/sipp_ice.py stun stun.example.net:3478

Hostnames are resolved through the system resolver and both IPv4 and IPv6 UDP
addresses are supported. Literal IPv6 endpoints use bracket notation, for
example ``[2001:db8::20]:3478``.

The response transaction ID and FINGERPRINT, when present, are validated before
``XOR-MAPPED-ADDRESS`` is returned.

ICE connectivity checks
-----------------------

Send an authenticated ICE connectivity check to a remote candidate::

    python3 tools/sipp_ice.py ice-check 203.0.113.20:50000 \
      --local-ufrag local1 \
      --remote-ufrag remote1 \
      --remote-password 'candidate-password' \
      --use-candidate

The request contains USERNAME, PRIORITY, ICE-CONTROLLING or ICE-CONTROLLED,
MESSAGE-INTEGRITY and FINGERPRINT. The response MESSAGE-INTEGRITY is verified
with the short-term ICE credential before its mapped address is accepted.
Protocol tests include the RFC 5769 MESSAGE-INTEGRITY and FINGERPRINT vector.

TURN allocation
---------------

Allocate a UDP relay using TURN long-term credentials::

    python3 tools/sipp_ice.py turn-allocate turn.example.net:3478 \
      --username loadtest \
      --password 'secret'

The helper performs the initial unauthenticated Allocate request, consumes the
401/438 REALM and NONCE challenge, derives the long-term key and retries with
MESSAGE-INTEGRITY. If the authenticated request receives a 438 Stale Nonce,
the helper consumes the fresh nonce and retries exactly once. Successful
allocation output includes the relayed address and LIFETIME when supplied by
the server.

Scope
-----

This stage covers IPv4/IPv6 STUN address decoding and transport resolution,
ICE connectivity checks and UDP TURN allocation. It does not implement a
complete ICE state machine, TURN permission/channel lifecycle, consent
freshness or trickle ICE. Those pieces can be layered on the same STUN codec
without changing SIPp's call scheduler.

Credential values are intentionally required on the command line for a simple
probe interface. On shared systems, wrap the tool so secrets are read from a
protected source rather than exposing them in process listings or shell
history.
