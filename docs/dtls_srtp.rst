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
the handshake result if it does not match the expected SDP fingerprint.

Sensitive key output
--------------------

By default the JSON result includes only the negotiated SRTP profile and the
peer certificate fingerprint. Exported SRTP keys are deliberately redacted.
Use ``--show-keys`` only in an isolated test environment when the actual
master key/salt values are required::

    python3 tools/sipp_dtls_srtp.py 203.0.113.20:50000 \
      --cert client.crt --key client.key --show-keys

Do not store this output in shared CI logs.

Scope
-----

This stage establishes DTLS-SRTP negotiation, certificate fingerprint
verification and RFC 5764 key export. It does not yet inject the exported keys
into SIPp's C++ RTP stream or implement a DTLS server role. That integration
can be layered separately after the transport/keying behavior is accepted and
tested independently.
