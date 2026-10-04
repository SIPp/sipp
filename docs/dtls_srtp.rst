DTLS-SRTP diagnostic handshake probe
====================================

``tools/sipp_dtls_srtp.py`` performs a DTLS 1.2 handshake with an RTP peer,
negotiates an SRTP protection profile and inspects the RFC 5764 exporter
material. It is a diagnostic/interoperability probe for SIPp WebRTC tests,
not a transport implementation and not a replacement for SIPp's native media
engine.

The helper delegates the DTLS record layer and certificate processing to the
local ``openssl s_client`` command. OpenSSL must support DTLS 1.2,
``-use_srtp`` and TLS exporter output. The parser intentionally consumes only
OpenSSL's handshake/export section and therefore still depends on the
human-readable ``s_client`` output format.

Important transport limitation
------------------------------

The helper supplies EOF to ``s_client`` once the handshake/export completes.
OpenSSL then closes the DTLS association. Many peers tear down the associated
SRTP transport after ``close_notify``. Consequently, exported values from this
helper are useful only for diagnostics, interoperability checks and test
assertions. They are not live SRTP keys that SIPp can keep using after the
helper exits.

There is currently no runtime consumer of these keys in SIPp's C++ RTP path.
This PR intentionally remains diagnostic-only. Native DTLS-SRTP media support,
if pursued separately, must own a persistent DTLS association and integrate
DTLS client/server state with SIPp's native RTP/SRTP path rather than reusing
this probe's exported snapshot.

This work relates to the WebRTC discussion in
https://github.com/SIPp/sipp/issues/339, where ICE and DTLS-SRTP were identified
as missing media pieces. This probe helps interoperability testing around that
area, but it does not provide the native DTLS-SRTP media path described there.

Basic use
---------

A client certificate and an unencrypted private key are required::

    python3 tools/sipp_dtls_srtp.py 203.0.113.20:50000 \
      --cert client.crt \
      --key client.key

Encrypted private keys are intentionally unsupported. The helper passes an
empty password source to OpenSSL so an encrypted ``--key`` fails immediately
instead of prompting on a terminal until ``--timeout``.

IPv6 endpoints use bracket notation, for example ``[2001:db8::20]:50000``.

By default the probe offers these profiles, in preference order:

#. ``SRTP_AEAD_AES_128_GCM``
#. ``SRTP_AES128_CM_SHA1_80``
#. ``SRTP_AES128_CM_SHA1_32``

A custom colon-separated preference list can be passed with ``--profile``::

    python3 tools/sipp_dtls_srtp.py 203.0.113.20:50000 \
      --cert client.crt --key client.key \
      --profile SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32

The exporter label is ``EXTRACTOR-dtls_srtp``. Exporter bytes are split in RFC
5764 order: client master key, server master key, client master salt, then
server master salt. AES-CM uses 16-byte keys and 14-byte salts; AEAD AES-128-GCM
uses 16-byte keys and 12-byte salts.

Certificate fingerprint verification
------------------------------------

For WebRTC tests, pass the SHA-256 fingerprint advertised in SDP using the
standard algorithm token and 32 colon-separated hex pairs::

    python3 tools/sipp_dtls_srtp.py 203.0.113.20:50000 \
      --cert client.crt --key client.key \
      --peer-fingerprint \
      'sha-256 AA:BB:CC:DD:...'

The helper computes SHA-256 over the peer certificate in DER form and fails
the probe if it does not match the expected fingerprint. Compact digests,
other hash algorithms, empty values and malformed hex are rejected rather than
normalized or treated as if verification were disabled.

``peer_authenticated: true`` means only that the certificate matched the
fingerprint supplied to this command. Authentication is only meaningful when
that expected fingerprint came from a trusted source, for example authenticated
signaling or another trusted test fixture. A fingerprint copied from an
untrusted channel does not by itself authenticate the peer.

When no expected fingerprint is supplied, the result reports
``peer_authenticated: false`` and is diagnostic only.

Sensitive key output
--------------------

By default the JSON result includes only the negotiated SRTP profile, the peer
certificate fingerprint and whether the supplied fingerprint matched. Exported
SRTP material is not returned. OpenSSL diagnostic error output is truncated
before sensitive session/export material such as ``Master-Key:``, TLS session
tickets or ``Keying material:`` so those values are not echoed to stderr on
failure or timeout paths.

``--show-keys`` is accepted only together with ``--peer-fingerprint``::

    python3 tools/sipp_dtls_srtp.py 203.0.113.20:50000 \
      --cert client.crt --key client.key \
      --peer-fingerprint 'sha-256 AA:BB:CC:DD:...' \
      --show-keys

Use this output only in an isolated test environment and do not store it in
shared CI logs.

Scope
-----

This stage provides a diagnostic DTLS-SRTP negotiation/fingerprint probe and
RFC 5764 exporter inspection. It does not keep the DTLS association alive,
inject keys into SIPp's C++ RTP stream, or implement a DTLS server role. The
native media work discussed in issue #339 remains outside this PR.
