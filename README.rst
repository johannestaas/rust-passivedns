rust-passivedns
===============

rust-passivedns is a rust implementation of a passive DNS response monitor.

This tool is useful for aggregating passive dns data for analysis, for sec ops, threat analysts and data science purposes. One might combine this tool with other threat analyst tools to track which machines may have been connecting to malicious or blacklisted hosts.

This parses DNS responses and outputs comma-separated values in the format:

SOURCE_IP,DEST_IP,NAME,RECORD_TYPE,RECORD_CLASS,TTL,RDATA
    
Example::

    8.8.4.4,192.168.1.100,google.com.,A,IN,195,216.58.194.174
    8.8.4.4,192.168.1.100,google.com.,A,IN,62,216.58.218.110
    8.8.4.4,192.168.1.100,google.com.,AAAA,IN,274,2607:F8B0:4005:0804:0000:0000:0000:200E
    8.8.4.4,192.168.1.100,google.com.,MX,IN,599,alt3.aspmx.l.google.com.
    8.8.4.4,192.168.1.100,google.com.,MX,IN,599,aspmx.l.google.com.
    8.8.4.4,192.168.1.100,google.com.,MX,IN,599,alt2.aspmx.l.google.com.
    8.8.4.4,192.168.1.100,google.com.,MX,IN,599,alt1.aspmx.l.google.com.
    8.8.4.4,192.168.1.100,google.com.,MX,IN,599,alt4.aspmx.l.google.com.

It will parse and output A, AAAA, MX and CNAME records or otherwise the raw RDATA as a u8 array.

An alternative C implementation available is gamelinux's passivedns available here:
https://github.com/gamelinux/passivedns

The benefit to the rust implementation is mainly that it is memory-safe, and probably all you need for most pdns use cases.

There is no deduping and timestamps must be manually implied to be the time the row is printed.

Installation
------------

First, you must install rust which will include the cargo packaging utility:
https://www.rust-lang.org/downloads.html

From the project root directory::

    $ cargo build

Usage
-----

passivedns must be run as root to sniff packets in promiscuous mode.

    $ sudo ./target/debug/passivedns
    # ./target/debug/passivedns

Release Notes
-------------

:0.0.1:
    Project created
