Python 3 script for storing pmacct flow data in InfluxDB.
Assumed use case is to display graphs in Grafana for ASN's with highest traffic.

* Requirements

 - pmacct daemon to be run in 'print' JSON mode and aggregating just by 'dst_as' 
 - InfluxDB API access and created database

Script is watching pmacct output file using inotify and searches for IN_CLOSE_WRITE events. On each one, data from file is parsed and written to InfluxDB. CYMRU whois server is used to translate AS numbers into more detailed string e.g. "AS57811 ATMSOFTWARE (PL)".

Everyday script refreshes _TOP_TALKERS_MEASUREMENT, that is used by Grafana for templating by ASN field.