RTCP/SRTCP media quality analysis
=================================

``tools/sipp_rtcp_qos.py`` decodes RTCP sender/receiver reports and emits
JSON media-quality measurements. It is designed as a companion for SIPp media
tests, so analysis can evolve without adding work to SIPp's packet scheduler.

Plain RTCP
----------

Decode one compound RTCP datagram::

    python3 tools/sipp_rtcp_qos.py --hex 81c90007...

Or listen for RTCP datagrams on UDP::

    python3 tools/sipp_rtcp_qos.py --listen 127.0.0.1:9001 --clock-rate 8000

IPv6 listen endpoints use bracket notation, for example
``[2001:db8::10]:9001``.

For each SR/RR report block the output includes:

* interval packet-loss percentage from ``fraction lost``
* cumulative packet loss
* RTP interarrival jitter converted to milliseconds
* RTT when LSR/DLSR data is available
* an R-factor and listening-quality MOS estimate

The MOS calculation is deliberately labelled as an estimate. It uses a
G.711-style E-model approximation and is useful for test thresholds and trend
comparison; it is not a codec-aware replacement for a full ITU-T G.107 model.

SRTCP
-----

AES-CM SRTCP packets can be authenticated and decrypted when the SDP SDES
``inline:`` master material is known::

    python3 tools/sipp_rtcp_qos.py \
      --listen 127.0.0.1:9001 \
      --srtcp-inline '<base64-master-key-and-salt>'

SRTCP support in this stage is deliberately narrow: SDES
``AES_CM_128_HMAC_SHA1_80`` with a 16-byte master key, 14-byte master salt and
80-bit authentication tag. The inline value must decode to exactly 30 bytes.
Other SRTCP suites and 32-bit authentication tags are rejected rather than
silently interpreted with the wrong profile.

SRTCP AES support uses the optional Python ``cryptography`` package. Plain
RTCP parsing and QoS/MOS calculations require only the Python standard
library. The tests include independent SRTCP KDF vectors in addition to a
round-trip authentication/decryption test.

Security notes
--------------

The SDES inline value contains key material. Avoid putting it in shell history,
logs, CI output or process listings on shared systems. Prefer a protected
wrapper or ephemeral test environment when analyzing encrypted media.

The parser rejects malformed packet lengths, unsupported RTCP versions and
SRTCP packets with failed authentication before attempting to decrypt them.
