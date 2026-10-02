Observability exporters
=======================

SIPp can write periodic statistics with ``-trace_stat``.  The helper tools
in ``tools/`` turn the latest complete statistics row into live monitoring
signals without changing SIPp's call-processing path.

Prometheus and JSON
-------------------

Start SIPp with a periodic statistics report, for example::

   sipp 192.0.2.10 -sf uac.xml -trace_stat -fd 1s

Then point the exporter at the generated statistics file::

   python3 tools/sipp_metrics.py --stat-file uac_1234.csv --serve --listen 0.0.0.0 --port 9876

The HTTP server provides:

* ``/metrics`` - Prometheus text exposition format.
* ``/v1/metrics`` - the same snapshot as JSON.
* ``/healthz`` - HTTP 200 while the statistics file can be read, otherwise 503.

Every numeric SIPp statistics column is exported as a gauge.  Column names are
normalised to the ``sipp_`` metric namespace.  Non-numeric columns, including
timestamps formatted as text, are kept out of the Prometheus series.

OpenTelemetry OTLP/HTTP
-----------------------

``sipp_otlp.py`` sends the same numeric snapshot as OTLP/HTTP JSON gauges::

   python3 tools/sipp_otlp.py \
       --stat-file uac_1234.csv \
       --endpoint http://otel-collector:4318/v1/metrics \
       --service-name sipp-loadtest

Custom HTTP headers can be added with repeated ``--header NAME=VALUE`` options.
Use ``--once`` in CI or scripts that want one export and a meaningful exit
status.  The exporter uses only the Python standard library.

Security
--------

The Prometheus listener defaults to ``127.0.0.1``.  Binding it to a public
interface exposes test statistics without authentication; use a firewall or
reverse proxy when remote scraping is required.  OTLP endpoints may carry
credentials through ``--header``; do not put secrets directly in shared shell
history or public process arguments.

Tests
-----

The parser and OTLP encoder have dependency-free unit tests::

   python3 -m unittest tests/test_sipp_metrics.py
