CI thresholds and reports
=========================

``tools/sipp_report.py`` turns the final row of a ``-trace_stat`` CSV file into
CI assertions.  A failed assertion exits with status 1; invalid input exits
with status 2.

Thresholds
----------

Threshold expressions use an exact statistics column name followed by one of
``<``, ``<=``, ``>``, ``>=``, ``==`` or ``!=`` and a numeric target::

   python3 tools/sipp_report.py uac_1234.csv \
       --threshold 'SuccessfulCall(C)>=10000' \
       --threshold 'FailedCall(C)==0' \
       --threshold 'CallRate(C)>=500'

Thresholds may also be stored in JSON::

   {
     "SuccessfulCall(C)": ">=10000",
     "FailedCall(C)": "==0"
   }

and loaded with ``--threshold-file thresholds.json``.

Reports
-------

Use ``--json-out report.json`` for a machine-readable summary and
``--junit-out report.xml`` for JUnit-compatible test results.  Most CI systems
can publish the JUnit file without a SIPp-specific plugin.

Example GitHub Actions step::

   - name: Assert SIP load test
     run: |
       python3 tools/sipp_report.py artifacts/uac_stats.csv \
         --threshold-file ci/sipp-thresholds.json \
         --junit-out artifacts/sipp-junit.xml \
         --json-out artifacts/sipp-summary.json

Tests
-----

The threshold parser and report renderers use only the standard library::

   python3 -m unittest tests/test_sipp_report.py
