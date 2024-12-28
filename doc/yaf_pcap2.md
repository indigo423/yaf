% Rolling Packet Capture (PCAP) Export with YAF

This tutorial will explain how YAF can create rolling packet capture (PCAP)
files and indexes to quickly find a flow within the PCAP repository. The
tutorial [Indexing Packet Capture Files (PCAP) with YAF][yaf_pcap] described
how to use YAF to index PCAP files and create new files using flow
information from previously existing PCAP files.

# [Overview](#yp2_overview) {#yp2_overview}

In many environments, PCAP and flow generation are separate processes,
making it difficult to construct analyses that employ both kinds of data.
The results of analysis with flow data may require further examination with
packet data. In many cases, analysts have developed custom scripts to
retrieve packets that match characteristics for a particular flow, often
time, IP addresses. ports, transport protocol, and VLAN tags. This can be
difficult when a flow spans multiple PCAP files and it is hard to determine
which PCAP files they should be analyzing. For examine, an analysis may be
done that is searching for a specific attachment in email being received by
an organization. The flow data analysis would allow the analyst to isolate
traffic by time, by application protocol (SMTP, in this case) and by
byte-size ranges. The attachments and their content are not part of the flow
records, so confirming whether the goal attachment is present among the
isolated email traffic would require examining the packet data collected.
Without some correspondence between packets and the isolated flows, matching
the data may take impractical amounts of time.

YAF can capture and write rolling PCAP files as well as generate the flow
data and provide an index (using flow characteristics) into the PCAP files
for quick and easy retrieval of a particular stream. Since network traffic
can be quite high volume, storing a series of PCAP is required, instead of a
single immense one. The series of generated PCAP files is governed by either
file size via YAF's **--max-pcap** parameter or by packet time via YAF's
**--pcap-timer** parameter. We'll refer to elements of this series of files
as "rolling PCAP files". The index takes to form of a hash of the key
characteristics for each flow, timing information, and location information
within the rolling PCAP files.

There are two approaches for indexing the rolling PCAP files with YAF. Both
will be discussed here, as the flexibility of the NetSA tool suite is a
primary goal in its design, to accommodate a variety of work flows. Using
the first approach, YAF will write one line to the index (packet capture
meta-file) for each flow record per output PCAP file . For example, if the
packets corresponding to a generated flow span three generated PCAP files,
the capture meta-file will contain 3 rows for the flow, one naming each
generated PCAP file. The second approach configures YAF to write one line in
the capture meta-file for each packet in the generated PCAP files, with
location information that names the rolling PCAP file, offset in the file,
and packet length. This requires more storage up front, but provides very
quick retrieval of the packets.

This example will configure YAF to export to an instance of [SiLK][]'s
[**rwflowpack**][rwflowpack] to create a local repository of flow data. This
tutorial does not provide details on installing and configuring SiLK, see
[Configuring YAF with SiLK][yaf_silk] for those details.

# [SETUP](#yp2_setup) {#yp2_setup}

Create a file directory to store the rolling PCAP files:

    $ mkdir /data/pcap

Create directories for the flow repository and logging:

    $ mkdir /data/flow
    $ mkdir /var/log/rwflowpack

Create a sensor configuration file for **rwflowpack** ([sensor.conf][]), in
this example for an IPFIX sensor exporting on TCP port 18001, treating
192.168.0.1/24 as the internal address block:

    $ cat >/data/flow/sensor.conf << END_CONF
    probe S0 ipfix
          protocol tcp
          listen-on-port 18001
    end probe
    sensor S0
           ipfix-probes S0
           internal-ipblock 192.168.1.0/24
           external-ipblock remainder
    end sensor
    END_CONF

Additionally, you will need to have a SiLK site configuration file
([silk.conf][]) in `/data/flow`. For this example, the one located in the
SiLK tarball (see the [SiLK downloads page][silk_download]) in
`site/twoway/silk.conf` should suffice.

Start **rwflowpack**:

    $ /usr/local/sbin/rwflowpack --sensor-conf=/data/flow/sensor.conf \
              --root-dir=/data/flow \
              --log-directory=/var/log/rwflowpack \
              --site-config=/data/flow/silk.conf \
              --pack-interfaces

Confirm **rwflowpack** is running and is listening on port 18001:

    $ netstat -an | grep 18001
    tcp4       0      0  *.18001        *.*        LISTEN

# [First Approach: Index per flow](#yp2_first) {#yp2_first}

This first approach will demonstrate how to use the rolling PCAP option in
**yaf** with the **--pcap-meta-file** parameter to write one line to the
capture meta-file for each flow corresponding to each rolling PCAP File. The
[**yafMeta2Pcap**][yafMeta2Pcap] tool will be used to query the capture
meta-file for a particular flow and provide the file names of the PCAP files
that contain the flow. **yaf** will then be run again over the particular
PCAP files that contain the flow, and **yafMeta2Pcap** will retrieve records
to produce the PCAP file for the flow. For a slightly quicker, but more
space-consuming process, jump to the [second approach](#yp2_second).

Start **yaf** as an ongoing process (daemon) generating flow records as
described in the **sensor.conf** file, with rolling PCAP generated in
`/data/pcap`, logging and process ID stored in `/var/log`:

    $ yaf --in=eth0 --live=pcap \
        --out=localhost \
        --ipfix=tcp --ipfix-port=18001 \
        --applabel --max-payload=500 \
        --silk --pcap=/data/pcap/yaf_pcap \
        --pcap-meta-file=/data/yaf_pcap_meta --pcap-timer=60 \
        --max-pcap=500 --daemonize --log=/var/log/yaf.log \
        --pidfile=/var/log/yaf.pid

By using the above options, **yaf** will create rolling PCAP files that will
rotate every 60 seconds (or 500MB) and write index information to the
capture meta-file. The default maximum file size for PCAP files is 5 MB, and
time is 5 minutes. By default, either the size or time (whichever is reached
first) are used to determine when a PCAP file should be rotated. If you
prefer to only rotate on time, set the argument to **--max-pcap** to
something very large. If you prefer to only rotate when a file reaches a
particular size, set the argument to **--pcap-timer** to a high value.
**yaf** will \"lock\" the files until the time has expired or the file limit
is reached, meaning that **yaf** will add \".lock\" to the end of the
filename until it has finished writing to it. The capture meta-file will
rotate before it reaches 2 GB.

For this example, we will do a few SiLK queries to pick a flow that is not
labeled by **yaf** as belonging to an application, so we need to view its
packets to determine what is going on. [**rwfilter**][rwfilter] is the most
import analysis tool included with the SiLK tools. It queries the data
repository for flow records that satisfy a set of filtering parameters. The
SiLK tools are intended to be combined to perform a particular task. The
analysis performed below will also use [**rwstats**][rwstats],
[**rwcut**][rwcut], and [**rwsilk2ipfix**][rwsilk2ipfix]. **rwstats**
summarizes SiLK flow records into a set of ordered bins. **rwcut** is used
to print the attributes of SiLK flow records in a delimited, columnar,
human-readable format. **rwsilk2ipfix** convers a stream of SiLK flow
records to IPFIX format.

To use the SiLK command line tools, set the SILK_DATA_ROOTDIR environment
variable to the flow repository to be queried, then summarize one day's
worth of traffic:

    $ export SILK_DATA_ROOTDIR=/data/flow
    $ rwfilter --start=2014/01/29 --type=all --protocol=0- --pass=stdout \
    rwstats --fields=29 --top --count=20
    INPUT: 395 Records for 5 Bins and 395 Total Records
    OUTPUT: Top 20 Bins by Records
    appli|   Records|  %Records|   cumul_%|
        0|       160| 40.506329| 40.506329|
      443|       124| 31.392405| 71.898734|
       80|        77| 19.493671| 91.392405|
       53|        30|  7.594937| 98.987342|
      137|         4|  1.012658|100.000000|

The above query shows what application protocols are running on this
network. Let's choose the first two flow records for the unknown protocols
(label 0), and display the flow key characteristics (fields 1-5), the number
of packets, and the start time:

    $ rwfilter --start=2014/01/29 --type=all --pass-destination=stdout \
               --application=0 --max-pass-records=2 \
          | rwcut --fields=1-5,packets,stime
            sIP|        dIP|sPort|dPort|pro|packets|                  sTime|
    10.20.11.51|10.64.22.15|61416| 8080|  6|      3|2014/01/29T15:02:39.025|
    10.64.22.15|10.20.11.51| 8080|61416|  6|      2|2014/01/29T15:02:39.026|

The IP address and port pairings show that these two flows are a
bidirectional flow (or biflow). Now we have all the information we need to
find the packets for this biflow. The following command will query the data
for one particular flow and **rwsilk2ipfix** will convert the SiLK flow
record to IPFIX. **getFlowKeyHash** takes IPFIX as input, by default, and
prints the 5-tuple, VLAN tag, flow key hash, and start time in milliseconds
to standard output.

    $ rwfilter --start=2014/01/29 --type=all --pass-destination=stdout \
               --application=0 --max-pass-records=1 \
          | rwsilk2ipfix \
          | getFlowKeyHash
                sIP|          dIP|sPort|dPort|pro| vlan|      hash|            ms
        10.20.11.51|  10.64.22.15|61416| 8080|  6|    0|4022100716| 1391007759025
    FILE PATH: 025/4022100716-201412915239_0.pcap

Now we can provide the information to **yafMeta2Pcap**. You can see that we
provided a glob pattern of the capture meta-files that **yaf** produced.
Alternatively, you could provide a text file that contains a list of the
names of the capture meta-files (see the [second approach](#yp2_second)
for an example). If an output file is not provided to **yafMeta2Pcap**, the
tool simply returns the name of the PCAP file that contains the flow
matching the hash and time. If this flow had been a long flow, and spanned
multiple PCAP files, the output of **yafMeta2Pcap** would have been all of
the file names that contain packets corresponding to the flow.

    $ yafMeta2Pcap --pcap-meta-file="/tmp/yaf_pcap_meta*" \
               --hash=4022100716 \
               --time=1391007759025
    /data/pcap/yaf_pcap20140129150236_00000.pcap

If we provide an output file, **yafMeta2Pcap** will create the PCAP file for
the flow by running a **yaf** process that will only create the PCAP file
for the flow using the hash and start time. The following examples provides
an example of combining all the tools to generate a single PCAP file.

    $ rwfilter --start=2014/01/29 --type=all --pass-destination=stdout \
               --application=0 --max-pass-records=1 \
          | rwsilk2ipfix \
          | getFlowKeyHash --ipfix \
          | yafMeta2Pcap --pcap-meta-file="/tmp/yaf_pcap_meta*" \
                --out=/tmp/mypcap.pcap
    Found 5 packets that match criteria.
    $ capinfos -c /tmp/mypcap.pcap
    File name:           /tmp/mypcap.pcap
    Number of packets:   5

The second example assumes that **yaf** was installed in your \$PATH. If
**yaf** was installed in a non-standard place, you can use the
**--yaf-program** parameter to specify the correct location of **yaf**. You
can then use [Wireshark][] or other packet display tool to examine the
packets in `/tmp/mypcap.pcap`.

# [Second Approach](#yp2_second) {#yp2_second}

The alternate method is to run **yaf** with the **--index-pcap** option to
write one line for each packet into the capture meta-file. We repeat the
SiLK query (with a different start time, to pull one hour of flow records),
then run **getFlowKeyHash** with parameters taken from the **rwcut** output.

    $ yaf --in=en2 --live=pcap \
          --out=localhost --ipfix=tcp --ipfix-port=18001 \
          --applabel --max-payload=500 --silk \
          --pcap=/tmp/pcap/yaf_pcap \
          --pcap-meta-file=/tmp/yaf_pcap_meta \
          --pcap-timer=60 --index-pcap \
          --daemonize --log=/var/log/yaf.log --pidfile=/var/log/yaf.pid
    $ rwfilter --start=2014/01/29T16 --type=all --pass-destination=stdout \
               --application=0 --max-pass-records=2 \
          | rwcut --fields=1-5,packets,stime
            sIP|        dIP|sPort|dPort|pro|packets|                  sTime|
    10.20.11.51|10.64.22.15|62024| 8080|  6|      2|2014/01/29T16:32:44.301|
    10.64.22.15|10.20.11.51| 8080|62024|  6|      2|2014/01/29T16:32:44.301|
    $ getFlowKeyHash --sip4=10.20.11.51 --dip4=10.64.22.15 \
                     --sport=62024 -dport=8080 --protocol=6 \
                     --date=2014-01-29 --time=16:32:44.301
                sIP|          dIP|sPort|dPort|pro| vlan|      hash|            ms
        10.20.11.51|  10.64.22.15|62024| 8080|  6|    0|4061946604| 1391013164301
    FILE PATH: 301/4061946604-2014129163244_0.pcap

Now we can use the **yafMeta2Pcap** and the capture meta-files to get the
PCAP for this biflow. Unlike the first example, where a glob pattern is
provided to **--pcap-meta-file**, this example first creates a list of all
the meta-files.

    $ ls -d -rt -1 /tmp/yaf_pcap_meta* > /tmp/meta-list.txt
    $ yafMeta2Pcap --metalist=/tmp/meta-list.txt --time=1391013164301 \
                   --hash=4061946604 --out=/tmp/mypcap.pcap
    Found 4 packets that match criteria.
    $ capinfos -c /tmp/mypcap.pcap
    File name:           /tmp/mypcap.pcap
    Number of packets:   4

This tutorial has shown two different ways of using YAF to capture full
packets and index them via flow data. The [second approach](#yp2_second)
has a few less steps but stores a line in the capture meta-file for each
packet as opposed to the [first approach](#yp2_first) that writes a line
for each flow, filename unique pair. The second approach creates larger
capture meta-files and requires more frequent writes to the capture
meta-files.

[Wireshark]:            http://www.wireshark.org/

[SiLK]:                 /silk/index.html
[rwcut]:                /silk/rwcut.html
[rwfilter]:             /silk/rwfilter.html
[rwflowpack]:           /silk/rwflowpack.html
[rwsilk2ipfix]:         /silk/rwsilk2ipfix.html
[rwstats]:              /silk/rwstats.html
[sensor.conf]:          /silk/sensor.conf.html
[silk_download]:        /silk/download.html
[silk.conf]:            /silk/silk.conf.html

[yafMeta2Pcap]:         yafMeta2Pcap.html
[yaf_pcap]:             yaf_pcap.html
[yaf_silk]:             yaf_silk.html

[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
