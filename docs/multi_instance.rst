Multi-instance launcher
=======================

SIPp can launch several SIPp processes from one CSV configuration file.  This
is useful when a test needs matching groups of UAC and UAS instances.

Use ``-multi`` with a CSV file:

.. code-block:: bash

   ./sipp -multi multi.csv -multi_base_port 5060

The CSV format is:

.. code-block:: text

   role,count,args
   uas,2,"-sn uas -p {instance_port} -nostdin"
   uac,2,"-sn uac 127.0.0.1:{instance_port} -m 100 -nostdin"

Each row creates ``count`` child processes.  The ``args`` field is split like
command-line arguments and passed to each child ``sipp`` process.

The following placeholders are expanded in the ``args`` field:

* ``{role}``: the role column value.
* ``{instance}``: the zero-based instance number within that role.
* ``{base_port}``: the value passed with ``-multi_base_port``.
* ``{instance_port}``: ``base_port + instance``.  Use this to pair UAC and UAS
  rows by instance number.
* ``{port}``: a globally increasing port number for every child process.

The launcher waits until all children exit and returns the first non-zero child
exit code.  If all children exit successfully, the launcher exits with zero.
