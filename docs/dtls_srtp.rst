DTLS-SRTP handshake probe
=========================

``tools/sipp_dtls_srtp.py`` performs a DTLS 1.2 handshake with an RTP peer,
negotiates an SRTP protection profile and extracts the RFC 5764 keying
material. It is intended for WebRTC interoperability tests around SIPp rather
than as a replacement for SIPp's native media engine.

The helper delegates the DTLS record layer and certificate processing to the
local ``openssl s_client`` command. OpenSSL must support DTLS 1.2, ``-use_srtp``
and TLS exporter output.

Basic use
---------

A client certificate and private key are required::

    python3 tools/sipp_dtls_srtp.py 203.0.113.20:50000 \
      --cert client.crt \
      --key client.key

IPv6 endpoints use bracket notation, for example ``[2001:db8::20]:50000``.

The default SRTP profile is ``SRTP_AES128_CM_SHA1_80``. The
``SRTP_AES128_CM_SHA1_32`` profile is also supported::

    python3 tools/sipp_dtls_srtp.py 203.0.113.20:50000 \
      --cert client.crt --key client.key \
      --profile SRTP_AES128_CM_SHA1_32

The exporter label is ``EXTRACTOR-dtls_srtp``. For the AES-128 profiles the
60 exported bytes are split in RFC 5764 order:

#. client master key (16 bytes)
#. server master key (16 bytes)
#. client master salt (14 bytes)
#. server master salt (14 bytes)

Certificate fingerprint verification
------------------------------------

For WebRTC tests, pass the fingerprint advertised in SDP::

    python3 tools/sipp_dtls_srtp.py 203.0.113.20:50000 \
      --cert client.crt --key client.key \
      --peer-fingerprint \
      'sha-256 AA:BB:CC:DD:...'

The helper computes SHA-256 over the peer certificate in DER form and fails
the handshake result if it does not match the expected SDP fingerprint. When
no expected fingerprint is supplied, the result reports
``peer_authenticated: false`` and is diagnostic only.

Sensitive key output
--------------------

By default the JSON result includes only the negotiated SRTP profile, the peer
certificate fingerprint and whether the peer was authenticated. Exported SRTP
keys are deliberately redacted.

``--show-keys`` is accepted only together with ``--peer-fingerprint``. This
prevents key material from being consumed after an unauthenticated DTLS
handshake::

    python3 tools/sipp_dtls_srtp.py 203.0.113.20:50000 \
      --cert client.crt --key client.key \
      --peer-fingerprint 'sha-256 AA:BB:CC:DD:...' \
      --show-keys

Use key output only in an isolated test environment and do not store it in
shared CI logs.

Scope
-----

This stage establishes DTLS-SRTP negotiation, certificate fingerprint
verification and RFC 5764 key export. It does not yet inject the exported keys
into SIPp's C++ RTP stream or implement a DTLS server role. That integration
can be layered separately after the transport/keying behavior is accepted and
tested independently.
