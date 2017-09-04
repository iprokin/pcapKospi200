# Parser of UDP packets in pcap file

This program parses quote messages from a Kospi market data feed broadcasted via UDP and captured in pcap file.
Sample data can be downloaded from <http://www.tsurucapital.com/en/code-sample.html>.

# Usage

Compile:

`stack build`

Use:

`./pcapKospi200 /path/to/file.pcap`

to reorder by packet accept time:

`./pcapKospi200 -r /path/to/file.pcap`

to run infinite test cycling over file data:

`./pcapKospi200 -t /path/to/file.pcap`

# References

* pcap format description
    - <https://wiki.wireshark.org/Development/LibpcapFileFormat#File_Format>
    - <https://delog.wordpress.com/2010/12/13/information-in-a-pcap-file-with-a-single-udp-packet/>
    - <https://www.elvidence.com.au/understanding-time-stamps-in-packet-capture-data-pcap-files/>
* UDP description
    - <https://en.wikipedia.org/wiki/User_Datagram_Protocol>
    - <https://en.wikibooks.org/wiki/Communication_Networks/TCP_and_UDP_Protocols>
* Reading pcap
    - <https://serverfault.com/questions/38626/how-can-i-read-pcap-files-in-a-friendly-format>
    - `tcpdump -qns 0 -X -r file.pcap | less`
    - Wireshark-gtk
* Dealing with Binary in Haskell
    - <https://wiki.haskell.org/Dealing_with_binary_data>
    - <https://hackage.haskell.org/package/binary-0.9.0.0/docs/Data-Binary-Get.html>
    - <http://hackage.haskell.org/package/binary-0.8.5.1/docs/src/Data.Binary.Get.html#runGetIncremental>
