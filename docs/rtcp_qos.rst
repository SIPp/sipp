RTCP/SRTCP media quality analysis
=================================

``tools/sipp_rtcp_qos.py`` decodes RTCP sender/receiver reports and emits JSON
media-quality measurements. It is a companion analyzer for SIPp media tests;
it does not replace SIPp's RTCP socket handling.

Plain RTCP
----------

Decode one compound RTCP datagram::

    python3 tools/sipp_rtcp_qos.py --hex 81c90007...

Or listen for RTCP datagrams on UDP::

    python3 tools/sipp_rtcp_qos.py \
      --listen 127.0.0.1:9001 \
      --clock-rate 8000 \
      --peer 203.0.113.20:9001

IPv6 endpoints use bracket notation, for example
``[2001:db8::10]:9001``. Unbracketed IPv6 literals are rejected.

The listener accepts ``--peer HOST:PORT`` to ignore unrelated datagrams and
limits JSON output to 50 lines per second by default. Use ``--rate-limit 0``
to disable the output limit.

SIPp currently drains packets received on its own RTCP socket; this standalone
listener does not see those packets automatically. Point the remote RTCP peer
at the analyzer port, mirror/forward the RTCP datagrams, or feed captured
packets to ``--hex`` when analyzing a SIPp call.

Loss, RTT and MOS semantics
---------------------------

For each SR/RR report block the output includes:

* ``interval_loss_percent`` from RTCP ``fraction lost``;
* the raw ``cumulative_lost`` packet count;
* ``mos_loss_percent`` and ``mos_loss_source``;
* RTP interarrival jitter converted to milliseconds;
* RTT when it can be tied to a known local sender report; and
* a conversational-quality ``mos_cq`` estimate and R-factor.

The listener keeps a baseline per reported SSRC. The first report uses the
RTCP interval loss value; subsequent reports use the cumulative lost-packet
and extended-sequence deltas observed since that baseline. The JSON field
``mos_loss_source`` says whether the sample used ``interval`` or
``observed-cumulative`` loss. A one-shot ``--hex`` decode has no earlier
baseline, so it necessarily uses the interval value.

RTT from LSR/DLSR is meaningful only when the analyzer is co-located with, or
shares the clock context of, the endpoint that sent the SR referenced by LSR.
Pass every such local RTP SSRC explicitly::

    --local-ssrc 0x11223344

Reports for other SSRCs return ``rtt_ms: null``. RTT samples above 10 seconds
are rejected by default as implausible; ``--max-rtt-ms`` changes that limit.
SIPp itself does not currently originate RTCP SR/RR, so a SIPp-only peer will
normally produce ``rtt_ms: null``. When RTT is unavailable, ``r_factor`` and
``mos_cq`` are also null instead of assuming zero delay.

The MOS calculation is a simplified conversational G.107-style estimate. It
uses the packet-loss equipment impairment term::

    Ie_eff = Ie + (95 - Ie) * Ppl / (Ppl + Bpl)

The defaults ``Ie=0`` and ``Bpl=25.1`` model G.711-like media with PLC.
Different codecs can supply their own ``--ie`` and ``--bpl`` values. The delay
term uses one half of measured RTT only. Jitter is reported separately rather
than being converted into an assumed playout delay, because that would require
codec, packetization-time and jitter-buffer information the analyzer does not
observe.

SRTCP
-----

AES-CM SRTCP packets can be authenticated and decrypted when the SDP SDES
master material is known. ``inline:`` prefixes are accepted. SDES lifetime
and MKI parameters are rejected explicitly because this probe does not
implement them.

Avoid exposing key material in process listings. Prefer a protected file::

    python3 tools/sipp_rtcp_qos.py \
      --listen 127.0.0.1:9001 \
      --srtcp-inline-file /run/secrets/srtcp.key

or an environment-variable name::

    SIPP_SRTCP_KEY='inline:...' \
      python3 tools/sipp_rtcp_qos.py \
      --listen 127.0.0.1:9001 \
      --srtcp-inline-env SIPP_SRTCP_KEY

``--srtcp-inline`` remains available for small isolated tests but exposes the
secret through argv/process listings.

Both ``AES_CM_128_HMAC_SHA1_80`` and the SRTP ``_32`` profile use an 80-bit
SRTCP authentication tag. This probe supports that AES-CM SRTCP construction
with a 16-byte master key and 14-byte master salt. Session keys are derived
once when the analyzer starts, and a 64-packet replay window is tracked per
SRTCP SSRC.

SRTCP AES support requires the Python ``cryptography`` package. CI installs it
and executes the RTCP/SRTCP test module. The tests include RFC 3711 SRTCP KDF
known values plus a fixed encrypted/authenticated packet vector generated
independently with OpenSSL, instead of relying only on a self-consistent
round-trip helper.

Security and scope
------------------

The parser rejects malformed RTCP lengths, invalid padding, unsupported RTCP
versions and failed SRTCP authentication. Authenticated SRTCP packets are also
checked for replay before decryption output is accepted.

This remains an analysis layer. It does not inject RTCP generation, SRTCP
processing or MOS decisions into SIPp's C++ RTP stream.
