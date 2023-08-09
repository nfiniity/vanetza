# Security

This is the security module of Vanetza. It implements the ETSI C-ITS security extension of the GeoNetworking protocol based on [ETSI TS 103 097 v1.2.1](http://www.etsi.org/deliver/etsi_ts/103000_103099/103097/01.02.01_60/ts_103097v010201p.pdf).

## Implemented Features

Most features are implemented, including:

 - Security profiles including the CAM and DENM profile
 - Certificate requests for unknown certificates of other stations
 - Certificate validation for incoming messages
 - Revocation checks for certificate authorities
 - Certificate requests

## Missing Features

There are a few missing features, but the overall implementation is in a working state to send and receive secured messages.
It has been verified to work correctly by interoperability tests with other implementations.

 - Region checks for polygonal and identified regions<br>
   There are `TODO` notes in the code of `region.cpp` within the `is_within()` functions. Implementing these checks is non-trivial.

 - Region consistency checks for regions other than circular and none region restrictions<br>
   There are `TODO` notes in the code of `region.cpp` within the `is_within()` functions. Implementing these checks is non-trivial.
