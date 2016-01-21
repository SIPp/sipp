Features added in 3.5.0-rc3
===========================

* `<exec play_pcap_audio="..."/>` and friends:
  - If the argument is not an absolute path, the pcap is searched next
    to the scenario, before falling back to checking the current
    working directory.
  - The argument may be enclosed in brackets, in which case it is
    interpreted as a keyword value; set through the `-key` command line
    option. Example: `<exec play_pcap_audio="[file1]"/>` with option
    `-key file1 /path/to/pcap`.

* Various...


Bugs fixed in 3.5.0-rc3
=======================

* A few...
