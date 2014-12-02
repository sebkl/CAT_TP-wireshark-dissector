CAT\_TP-wireshark-dissector 
======
CAT\_TP-wireshark-dissector is a wireshark plugin that allows to dissect CAT\_TP packages from a network stream.

##Specification:

This implementation has been built based on the  [ETSI TS 102 127 v6.13.0 (2009-04) specification](http://www.etsi.org/deliver/etsi_ts/102100_102199/102127/06.13.00_60/ts_102127v061300p.pdf).

## Documentation:

#### Build requirements and dependencies

For debian based environments the following packages are needed to manually build this plugin:

 * wireshark-dev
 * libwireshark-dev

The wireshark source tree from :

##Development

Source code formatting is done using :
```
astyle -A3 < packet-cattp.c
```

[Official wireshark git repo](https://code.wireshark.org/review/p/wireshark.git) or the [Github repository](https://github.com/wireshark/wireshark)

## TODO
 * Splitup PDU type dissecting into seperate functions.
 * Splitup ICCID segments
 * check how to represent a session/connection
 * add build infrastructure (Makefile templates from example module)
 * add test dump (PCAP)
