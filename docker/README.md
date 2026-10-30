# SIPp

SIPp is a free, open-source test tool and traffic generator for the SIP
protocol. It ships with basic user agent scenarios (UAC and UAS), runs
custom XML scenarios from simple to very complex call flows, shows live
statistics, and can send RTP media. It is used to test SIP equipment such
as proxies, B2BUAs, SBCs, media servers and IP-PBXs, and to load them
with thousands of calls.

- Source and issues: https://github.com/SIPp/sipp
- Documentation: https://sipp3.readthedocs.io/en/latest/
- Releases and changelog: https://github.com/SIPp/sipp/releases

## Tags

| Tag | Meaning |
| --- | --- |
| `latest` | Latest stable release |
| `3.8`, `3.7`, ... | Latest patch release of that minor version |
| `3.8.0`, ... | Exact release |

Images are built for `linux/amd64` and `linux/arm64`, on Alpine Linux, from
the [Dockerfile](https://github.com/SIPp/sipp/blob/master/docker/Dockerfile)
in the repository. The `sipp` binary is statically linked, with TLS
(OpenSSL), PCAP media playback and GSL distributions. SCTP is not
included.

## Usage

The image's command is `sipp`, so arguments go after a repeated `sipp`:

```sh
docker run --rm -it sipp/sipp sipp -v
```

Host networking is recommended. SIP and RTP carry IP addresses and ports
inside the messages, which Docker's NAT does not rewrite:

```sh
# UAS: answer calls on port 5060
docker run --rm -it --network host sipp/sipp sipp -sn uas

# UAC: place 10 calls per second to 192.0.2.10
docker run --rm -it --network host sipp/sipp sipp -sn uac -r 10 192.0.2.10
```

`-it` gives you SIPp's interactive statistics screen. For unattended runs,
drop it and use `-m` to stop after a number of calls, plus `-trace_stat`
or `-trace_err` to write logs:

```sh
docker run --rm --network host sipp/sipp sipp -sn uac -m 100 192.0.2.10
```

### Custom scenarios and files

Mount the directory holding your scenarios, CSV injection files and PCAP
files, and run from it. Log and trace files are written there too:

```sh
docker run --rm -it --network host \
  -v "$PWD:/work" -w /work \
  sipp/sipp sipp -sf my_scenario.xml -inf users.csv 192.0.2.10
```

Dump a built-in scenario to start from:

```sh
docker run --rm sipp/sipp sipp -sd uac > uac.xml
```

### Without host networking

Publishing the SIP port works for simple signaling tests:

```sh
docker run --rm -it -p 5060:5060/udp sipp/sipp sipp -sn uas
```

SIPp then advertises the container's address in its messages, and RTP
needs ports of its own, so use host networking when the far end must
reach SIPp back or you need media.

## License

SIPp is licensed under the GNU General Public License, version 2 or any
later version. See
[LICENSE.txt](https://github.com/SIPp/sipp/blob/master/LICENSE.txt).
