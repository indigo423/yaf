% Indexing Packet Capture Files (PCAP) with YAF

This tutorial describes how to use YAF's features that support use of packet
capture (PCAP) files. It will discuss the various approaches to indexing
PCAP and isolating PCAP for a particular flow. This tutorial makes use of
two additional tools that are installed with YAF,
[**yafMeta2Pcap**][yafMeta2Pcap] and [**getFlowKeyHash**][getFlowKeyHash]. A
companion tutorial, [Rolling Packet Capture (PCAP) Export with
YAF][yaf_pcap2], will discuss how to enable YAF to create a rolling buffer
of PCAPs and index the PCAPs by flows. Both tutorials assume you are using
the most recent release of YAF.

These features allow YAF to support a variety of analyses that move from
analysis of network flow records and drill down into the packets that are
generated from those flows. Specific packet-by-packet detail provides more
evidence and more surety of analysis results. Starting from network flow
records allows the analyst to more closely focus the examination of packets,
and to improve the efficiency of analysis. In some cases, the packet
analysis may yield further conditions to pull other network flow records,
completing an iterative cycle.

The sections of this tutorial include:

-   [Overview](#yp_overview) - comments regarding the tutorial and the tools
    used in it;

-   [Single File Example](#yp_single) - discussion of the principle example,
    presenting a process for just one capture file, and the several
    variations presented in the tutorial

    -   [Index with Capture Meta File](#yp_index1) - the first alternative,
        using several tools but often producing faster response

    -   [Use **getFlowKeyHash** and YAF](#yp_getkeyhash) - the second
        alternative, not as fast as the first, but using fewer tools

    -   [Using a Berkeley Packet Filter (BPF)](#yp_bpf) - the third
        alternative, using YAF only, but producing results that may not be
        precise

    -   [Packet-per-flow](#yp_pcap-per-flow) - the fourth alternative,
        working with each packet individually, which is often much slower

-   [Multiple File Example](#yp_multiple) - the second example, which
    integrates results across several capture files

The following sections show several options for the same analysis task,
isolating packets corresponding to a specific Yahoo Messenger interaction.
This multiplicity of options emphasize the flexibility of the NetSA tool
suite, which provides the analyst several possible choices of tools to use,
depending on their tasking and their analysis environment.

# [Overview](#yp_overview) {#yp_overview}

Often analysis of very large PCAP files can be difficult due to lack of
tools for effectively reading and slicing large PCAP files. YAF provides a
couple options for performing analysis over one or more large PCAP files.
Additionally, these features can be used on live traffic. However, the
pcap-per-flow option is not recommended for networks with high data speeds.

The following tutorial uses YAF and the tools that are installed with YAF.
It also uses [SiLK][] for some basic flow analysis. In addition, this
example uses [**capinfos**][capinfos], a program installed with
[Wireshark][], that provides statistics of PCAP files.

>   **Note**: YAF must be configured with application labeling in order to
>   perform the analysis described below. However, application labeling is
>   not essential for packet operations.

# [Single Large PCAP Example](#yp_single) {#yp_single}

Let's assume we have one large PCAP that we would like to analyze. First, we
create flow records by **yaf** from the PCAP file `/data/big.pcap`, with
additional parameters that add application labeling, avoid packet truncation
by employing a generous packet size restriction, and output records
compatible with SiLK conversion onto standard output, which pass to
[**rwipfix2silk**][rwipfix2silk] to generate the restricted record format
used by SiLK, including VLAN tags, into the file `/tmp/yaf2flow.rw`:

    $ yaf --in=/data/big.pcap --out=- \
              --applabel --max-payload=1500 --silk \
          | rwipfix2silk --silk-output=/tmp/yaf2flow.rw \
              --interface-values=vlan

In this example, we are examining Yahoo messaging traffic in the flow data
we created. The following example uses [**rwstats**][rwstats], a tool for
summarizing SiLK flow records and sorting the results, to view the top 20
application protocols used in the flow file, finding that about 97% of the
flow records are DNS (53), unlabeled (0), or web (80, 443), but there are a
tiny component that are Yahoo messaging (5050):

    $ rwstats --fields=application --top --count=20 /tmp/yaf2flow.rw
    INPUT: 64510 Records for 24 Bins and 64510 Total Records
    OUTPUT: Top 20 Bins by Records
    appli|   Records|  %Records|   cumul_%|
       53|     27302| 42.322121| 42.322121|
        0|     24383| 37.797241| 80.119361|
       80|      5675|  8.797086| 88.916447|
      443|      5416|  8.395598| 97.312045|
      137|       778|  1.206015| 98.518059|
      161|       391|  0.606108| 99.124167|
       67|       344|  0.533251| 99.657417|
       22|        42|  0.065106| 99.722524|
     2223|        30|  0.046504| 99.769028|
     5222|        24|  0.037204| 99.806232|
     5004|        21|  0.032553| 99.838785|
     5190|        18|  0.027903| 99.866687|
      143|        14|  0.021702| 99.888389|
      902|        12|  0.018602| 99.906991|
       25|        12|  0.018602| 99.925593|
     1723|        12|  0.018602| 99.944195|
      194|        12|  0.018602| 99.962796|
      110|         6|  0.009301| 99.972097|
     1863|         4|  0.006201| 99.978298|
     5050|         4|  0.006201| 99.984499|

Let us focus on the 4 records labeled as application 5050, Yahoo Messenger.
A list of application labels can be found on the [**applabel**][applabel]
man page. The packet-level analysis of this traffic is not included in this
tutorial, but only the process of isolating the packets corresponding to two
of these flow records.

We\'ll use SiLK\'s [**rwfilter**][rwfilter] and [**rwcut**][rwcut] tools to
show more details about the flows labeled as 5050, details needed to isolate
the packets. **rwfilter** selects these flow records, while **rwcut**
translates the flow record to human-readable format, printing the flow key
fields (1-5), the count of packets per flow, the start time, and the VLAN
tag.

    $ rwfilter --application=5050 --pass-dest=stdout /tmp/yaf2flow.rw \
          | rwcut --fields=1-5,packets,stime,in
              sIP|          dIP|sPort|dPort|pro|packets|                  sTime| in|
      10.10.0.208|98.136.48.106|50997| 5050|  6|     23|2011/01/28T21:53:05.607|900|
    98.136.48.106|  10.10.0.208| 5050|50997|  6|     18|2011/01/28T21:53:05.685|900|
      10.10.0.208| 98.136.48.48|51094| 5050|  6|     29|2011/01/28T21:53:26.219|900|
     98.136.48.48|  10.10.0.208| 5050|51094|  6|     24|2011/01/28T21:53:26.296|900|

**rwfilter** returns the 4 flow records, or 2 bidirectional flow (biflow)
records. We will look at the first biflow and would like to perform a deeper
analysis of this particular flow by looking at the 41 packets corresponding
to this biflow in the PCAP file.

There are four ways to isolate these packets using YAF and related tools:

1.  [Indexing with Capture Meta File](#yp_index1) - using several tools but
    often producing faster response

2.  [Using **getFlowKeyHash** and YAF](#yp_getkeyhash) - not as fast as the
    first, but using fewer tools

3.  [Using a Berkeley Packet Filter](#yp_bpf) - using YAF only, but producing
    results that may not be precise

4.  [Using the pcap-per-flow option](#yp_pcap-per-flow) - working with each
    packet individually, which is often much slower

## [Indexing the PCAP file using the Capture Meta File](#yp_index1) {#yp_index1}

The first way is to index the PCAP file using the capture meta file created
by **yaf**. This file holds a hash of the flow key information elements from
each packet, the flow start time in milliseconds since the epoch, and the
PCAP file name. It is generated by **yaf** using the **--pcap-meta-file**
parameter, as in the following command. In this command, we use the
**--no-output** parameter because we are only interested in the capture meta
file. We use the **--index-pcap** parameter to generate a meta file entry
for each packet, rather than the default which is for each flow. We also use
the **--verbose** parameter to print messages describing **yaf**'s
processing of the packets.

    $ yaf --in=/data/big.pcap                  \
          --no-output --index-pcap             \
          --pcap-meta-file=/tmp/yaf_ --verbose
    [2014-12-23 14:16:00] yaf starting
    [2014-12-23 14:16:00] Reading packets from /data/big.pcap
    [2014-12-23 14:16:00] Opening Pcap Meta File /tmp/yaf_20141223141600_00000.meta
    [2014-12-23 14:16:07] Processed 5921725 packets into 42096 flows:
    [2014-12-23 14:16:07]   Mean flow rate 6688.29/s.
    [2014-12-23 14:16:07]   Mean packet rate 940854.79/s.
    [2014-12-23 14:16:07]   Virtual bandwidth 3366.3978 Mbps.
    [2014-12-23 14:16:07]   Maximum flow table size 10742.
    [2014-12-23 14:16:07]   181 flush events.
    [2014-12-23 14:16:07]   19580 asymmetric/unidirectional flows detected (46.51%)
    [2014-12-23 14:16:07] YAF read 6140871 total packets
    [2014-12-23 14:16:07] Assembled 33328 fragments into 15414 packets:
    [2014-12-23 14:16:07]   Expired 552 incomplete fragmented packets. (0.01%)
    [2014-12-23 14:16:07]   Maximum fragment table size 41.
    [2014-12-23 14:16:07] Rejected 201232 packets during decode: (3.17%)
    [2014-12-23 14:16:07]   201232 due to unsupported/rejected packet type: (3.17%)
    [2014-12-23 14:16:07]     201232 unsupported/rejected Layer 3 headers. (3.17%)
    [2014-12-23 14:16:07]     196465 ARP packets. (3.10%)
    [2014-12-23 14:16:07] yaf Exported 1 stats records.
    [2014-12-23 14:16:07] yaf terminating
    $ wc -l /tmp/yaf_20141223141600_00000.meta
     5922318 /tmp/yaf_20141223141600_00000.meta

You can see from the **wc** output compared to **yaf**'s message reporting
\"Processed 5921725 packets into 42096 flows\" that the PCAP metadata file
contains at least one line for each packet in the PCAP file. The additional
lines are to speed up processing of this file. We will need the flow key
hash and the start time in milliseconds for the flow we are interested in,
which is provided to us by the **getFlowKeyHash** tool. The flow key hash is
used by YAF as a unique identifier for a flow. The flow key hash is a hash
of the 5-tuple (source and destination IP addresses, source and destination
ports, and transport protocol) and the VLAN tag. For this example, this is
why we used the **--interface-values** option with **rwipfix2silk** when the
SiLK format flows were generated as above. If your PCAP does not contain
VLAN tags, then it is not necessary.

We could list the flow information from the **rwcut** output on the command
line for **getFlowKeyHash**:

    $ getFlowKeyHash --sip4=10.10.0.208 --dip4=98.136.48.106 \
              --sport=50997 --dport=5050 \
              --protocol=6 --vlan=900 \
              --date=2011-01-28 --time=21:53:05.607
            sIP|          dIP|sPort|dPort|pro|vlan|      hash|            ms
    10.10.0.208|98.136.48.106|50997| 5050|  6| 900|2549564224| 1296251585607
    FILE PATH: 607/2549564224-201112821535_0.pcap

Since we have the flow file already, we can alternatively pipe **rwfilter**
output to [**rwsilk2ipfix**][rwsilk2ipfix] with **getFlowKeyHash**.
**rwsilk2ipfix** converts a stream of SiLK flow records (the output of
**rwfilter**) to IPFIX flow records (the input of **getFlowKeyHash**).

    $ rwfilter --application=5050 --pass-dest=stdout /tmp/yaf2flow.rw \
          | rwsilk2ipfix \
          | getFlowKeyHash
              sIP|          dIP|sPort|dPort|pro| vlan|      hash|            ms
      10.10.0.208|98.136.48.106|50997| 5050|  6|  900|2549564224| 1296251585607
    98.136.48.106|  10.10.0.208| 5050|50997|  6|  900|1131976655| 1296251585607
      10.10.0.208| 98.136.48.48|51094| 5050|  6|  900|2538881818| 1296251606219
     98.136.48.48|  10.10.0.208| 5050|51094|  6|  900|1131976502| 1296251606219

To match the packet metadata, we need the \"hash\" and \"ms\" values. The
FILE PATH will be used in the fourth approach.

Using the key hash, milliseconds, along with the original PCAP, and the PCAP
metadata file, the [**yafMeta2Pcap**][yafMeta2Pcap] tool will create the
PCAP we are looking for:

    $ yafMeta2Pcap --pcap=/data/big.pcap \
              --pcap-meta-file=/tmp/yaf_20141223141600_00000.meta \
              --out=/tmp/YMSG.pcap \
              --hash=2549564224 \
              --time=1296251585607 --verbose
    Looking for hash: 2549564224 at start time: 1296251585607
    Opening PCAP Meta File: /tmp/yaf_20141223141600_00000.meta
    Opening PCAP File /data/big.pcap
    Opening output file /tmp/YMSG.pcap
    Found 41 packets that match criteria.
    $ capinfos -c /tmp/YMSG.pcap
    File name:           /tmp/YMSG.pcap
    Number of packets:   41

You can do this in a single step by sending the output of **getFlowKeyHash**
directly to **yafMeta2Pcap**, using the **--ipfix** parameter so that
**getFlowKeyHash** provides the input format expected by **yafMeta2Pcap**:

    $ rwfilter --application=5050 --pass-dest=stdout /tmp/yaf2flow.rw \
          | rwsilk2ipfix \
          | getFlowKeyHash --ipfix \
          | yafMeta2Pcap --pcap=/data/big.pcap \
                --pcap-meta-file=/tmp/yaf_meta_pcap.txt \
                --out=/tmp/YMSG.pcap
    Looking for hash: 2549564224 at start time: 1296251585607
    Opening PCAP Meta File: /tmp/yaf_20141223141600_00000.meta
    Opening PCAP File: /data/big.pcap
    Opening output PCAP file /tmp/YMSG.pcap
    Found 41 packets that match criteria

## [Using getFlowKeyHash and YAF](#yp_getkeyhash) {#yp_getkeyhash}

The second approach for pulling the packets is to calculate the flow key
hash using **getFlowKeyHash** and generate a PCAP file with YAF for only the
flow you are searching for. This approach works well if you know which PCAP
file the flow is contained in. Assuming we have already run YAF and
rwipfix2silk, we can search for a particular flow using **rwfilter** and
pipe it to **getFlowKeyHash** to generate the hash for the particular flow:

    $ rwfilter --application=5050 --pass-dest=stdout /tmp/yaf2flow.rw \
               | rwsilk2ipfix | getFlowKeyHash
                sIP|            dIP|sPort|dPort|pro| vlan|      hash|                  ms
        10.10.0.208|  98.136.48.106|50997| 5050|  6|  900|2549564224|       1296251585607
      98.136.48.106|    10.10.0.208| 5050|50997|  6|  900|1131976655|       1296251585607
        10.10.0.208|   98.136.48.48|51094| 5050|  6|  900|2538881818|       1296251606219
       98.136.48.48|    10.10.0.208| 5050|51094|  6|  900|1131976502|       1296251606219

Now that we have the flow key hash and start time, we can run **yaf** as
follows:

    $ yaf --in=/data/big.pcap --no-output --pcap=/tmp/YMSG.pcap \
          --hash=2549564224 --stime=1296251585607 --max-payload=2000
    $ capinfos -c /tmp/YMSG.pcap
    File name:           /tmp/YMSG.pcap
    Number of packets:   41

The **--max-payload** option is required for this approach and it should be
set to something larger than the typical MTU to ensure you get the full
packet. You can think of max-payload as snaplen. If you set it to something
small, all your packets will be truncated to that length, but large values
will not introduce padding beyond the actual packet length.

## [Using a BPF Filter](#yp_bpf) {#yp_bpf}

The third approach is to use a [Berkeley Packet Filter (BPF)
language][pcap_filter] filter. The BPF language is large, and sometimes it
can be a bit difficult to format the filter string correctly (especially
when there are VLAN tags). The filter string may not weed out all of the
data we don't want. While the BPF language lacks time primitives, the
following filter string should suffice:

    $ yaf --in=/data/big.pcap --out=/tmp/5050.yaf --pcap=/tmp/YMSG_ \
          --filter="port 50997 or (vlan and port 50997) and host 98.136.48.106" \
          --verbose
    [2014-01-27 20:46:44] yaf starting
    [2014-01-27 20:46:44] Reading packets from /data/big.pcap
    [2014-01-27 20:46:46] Processed 44 packets into 4 flows:
    [2014-01-27 20:46:46]   Mean flow rate 2.20/s.
    [2014-01-27 20:46:46]   Mean packet rate 24.21/s.
    [2014-01-27 20:46:46]   Virtual bandwidth 0.0292 Mbps.
    [2014-01-27 20:46:46]   Maximum flow table size 1.
    [2014-01-27 20:46:46]   3 flush events.
    [2014-01-27 20:46:46]   3 asymmetric/unidirectional flows detected
    [2014-01-27 20:46:46] Assembled 0 fragments into 0 packets:
    [2014-01-27 20:46:46]   Expired 0 incomplete fragmented packets.
    [2014-01-27 20:46:46]   Maximum fragment table size 0.
    [2014-01-27 20:46:46] yaf Exported 1 stats records.
    [2014-01-27 20:46:46] yaf terminating

As you can see, YAF generated 4 flows from 44 packets matching the filter
string. You could use [**yafscii**][yafscii] to view the flows:

    $ yafscii --in=/tmp/5050.yaf --out=stdout
    2011-01-28 21:53:05.607 - 21:53:27.568 (21.961 sec) tcp 10.10.0.208:50997 => 98.136.48.106:5050 452bc00b:65e6c66b S/APRS:AS/APSF vlan 384:384 (23/3250 <-> 18/3264) rtt 78 ms
    2011-01-28 21:53:27.568 tcp 10.10.0.208:50997 => 98.136.48.106:5050 452bc409 R/0 vlan 384 (1/40 ->)
    2011-01-28 21:53:27.688 tcp 10.10.0.208:50997 => 98.136.48.106:5050 452bc409 R/0 vlan 384 (1/40 ->)
    2011-01-28 21:53:27.688 tcp 10.10.0.208:50997 => 98.136.48.106:5050 452bc409 R/0 vlan 384 (1/40 ->)
    $ capinfos -c /tmp/YMSG_20140127204003_00000.pcap
    File name:           /tmp/YMSG_20140127204003_00000.pcap
    Number of packets:   44

Using the filter string with YAF captured 3 extra packets that were not
technically apart of this flow. However, now that we have a smaller PCAP, we
can use [Wireshark][] or a similar tool to view the payload and perform a
deeper analysis of the data. You could also use the filter string and the
**--pcap-per-flow** option (described in the following section) to ensure
you only get the packets associated with a flow.

## [Using pcap-per-flow](#yp_pcap-per-flow) {#yp_pcap-per-flow}

The fourth way to isolate packets is to use the **--pcap-per-flow**
parameter to **yaf**. The **--pcap-per-flow** parameter will cause **yaf**
to create at least one PCAP file for each flow in the input PCAP file. It is
not advisable to use this option in cases where many flows are present
(which is most often), but when combined with other options (such as a
filter string) to restrict the number of PCAP files generated, it is useful.

First create a temporary directory to place all the small PCAP files, to
prevent YAF from turning off PCAP export, and then run YAF as follows:

    $ mkdir /tmp/pcap
    $ yaf --in=/data/big.pcap --out=/tmp/5050.yaf \
              --pcap=/tmp/pcap --pcap-per-flow \
              --max-payload=2000 --verbose

The **--max-payload** parameter is required with the **--pcap-per-flow**
parameter and it should be set to something larger than the typical MTU to
ensure you get the full packet. You can think of max-payload as snaplen. If
you set it to something small, all your packets will be truncated to that
length. Use of **--pcap-per-flow** causes the argument to the **--pcap**
parameter to be interpreted as a directory, rather than a filename prefix.

In `/tmp/pcap` you will see a large amount (depending on how large and
diverse your PCAP file is) of file directories that are 3 digit numbers. YAF
uses the last three digits of the start time (in milliseconds) as the file
directory, and the flow key hash, start time, and serial number (to prevent
clashing file names) as the filename. Depending on how large the flow is,
YAF may have created multiple PCAP files for that flow. The default size is
25 MB, and can be modified by using the **--max-pcap** parameter to **yaf**.

To quickly determine which PCAP corresponds to the Yahoo messaging flow,
we can use the **getFlowKeyHash** program again:

    $ getFlowKeyHash --sip4=10.10.0.208 --dip4=98.136.48.106 \
              --sport=50997 --dport=5050 --protocol=6 --vlan=900 \
              --date=2011-01-28 --time=21:53:05.607
                sIP|            dIP|sPort|dPort|pro| vlan|      hash|                  ms
        10.10.0.208|  98.136.48.106|50997| 5050|  6|  900|2549564224|       1296251585607
    FILE PATH: 607/2549564224-201112821535_0.pcap

The last line of the output provides the file path to the PCAP file:

    $ capinfos -c /tmp/pcap/607/2549564224-20110128215305_0.pcap
    File name:           /tmp/pcap/607/2549564224-20110128215305_0.pcap
    Number of packets:   41

# [Multiple Input Files](#yp_multiple) {#yp_multiple}

This tutorial has presented four different ways to slice a large, single
PCAP for a given flow. This same process can be used over multiple PCAP
files as well. Often PCAP is captured using **tcpdump**, rolling files when
they reach a particular size or for a given time period. YAF can read
multiple files at a time. You could run YAF on each PCAP file, but flows
will be closed each time YAF finishes reading a file. It is best to use the
**--caplist** option with YAF so that it uses the same flow table to process
all the PCAPs. When providing the **--caplist** option to YAF, the argument
to **--in** must be an ordered, newline-delimited list of pathnames to the
PCAP files. Blank lines and lines beginning with the character `#` are
ignored. The files must be listed in ascending time order, as YAF rejects
out-of-order packets.

    $ ls -d -1 -rt /tmp/pcap/*.* > /tmp/yaf_cap_file.txt
    $ cat /tmp/yaf_cap_file.txt
    /tmp/pcap/pcap1.pcap
    /tmp/pcap/pcap2.pcap
    /tmp/pcap/pcap3.pcap
    /tmp/pcap/pcap4.pcap
    /tmp/pcap/pcap5.pcap
    /tmp/pcap/pcap6.pcap
    /tmp/pcap/pcap7.pcap
    /tmp/pcap/pcap8.pcap
    /tmp/pcap/pcap9.pcap
    /tmp/pcap/pcap10.pcap
    $ yaf --in=/tmp/yaf_cap_file.txt --caplist \
              --noerror --no-output \
              --pcap-meta-file=/tmp/yaf_meta_pcap.txt

Processing multiple files often will use the **--noerror** parameter, which
will ensure that YAF continues to process the files even if it runs into an
error with one of the PCAP files. Sometimes there can be a truncated packet
at the end of a PCAP.

>    **Note:** The PCAP metadata file will rotate if it reaches the maximum
>    file size for your operating system.

The **yafMeta2Pcap** program can take the same caplist file used as the
argument to **--in** for YAF.

    $ yafMeta2Pcap --caplist=/tmp/yaf_cap_file.txt \
              --pcap-meta-file=/tmp/yaf_meta_pcap.txt \
              --out=/tmp/YMSG.pcap --hash=2549564224 \
              --time=1296251585607

>   **Note:** **yafMeta2Pcap** will only open the PCAP files that contain
>   the flow of interest.

Next: [Rolling Packet Capture (PCAP) Export with YAF][yaf_pcap2]


[Wireshark]:        http://www.wireshark.org/
[capinfos]:         http://www.wireshark.org/docs/man-pages/capinfos.html
[pcap_filter]:      https://www.tcpdump.org/manpages/pcap-filter.7.html

[SiLK]:             /silk/index.html
[rwcut]:            /silk/rwcut.html
[rwfilter]:         /silk/rwfilter.html
[rwipfix2silk]:     /silk/rwipfix2silk.html
[rwsilk2ipfix]:     /silk/rwsilk2ipfix.html
[rwstats]:          /silk/rwstats.html

[applabel]:         applabeling.html
[getFlowKeyHash]:   getFlowKeyHash.html
[yafMeta2Pcap]:     yafMeta2Pcap.html
[yaf_pcap2]:        yaf_pcap2.html
[yafscii]:          yafscii.html


[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
