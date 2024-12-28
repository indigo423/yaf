% YAF: Integration with Specific Network Cards

YAF provides support for the Endace/Emulex, Napatech, and Netronome capture
cards. This support must be included when YAF is [configured and
built][installation] before it is installed. YAF can be configured to use
the custom libpcap on these cards by using the **--with-libpcap** option or
by setting CFLAGS and LDFLAGS when configuring YAF.

# [Endace](#endace) {#endace}

Endace DAG live input support requires libdag. Use the **--with-dag** option
to `./configure` to enable DAG support. Standard interface recording is
enabled by default when running YAF with **--live=dag**.

# [Napatech](#napatech) {#napatech}

Napatech live input support requires libntapi and the 3rd generation
Napatech drivers. Use the **--with-napatech** option to `./configure` to
enable Napatech support. Standard interface recording is enabled by default
when running YAF with **--live=napatech.**

## [Installing and Configuring Napatech Drivers and Service](#install-napatech) {#install-napatech}

1.  You have downloaded the appropriate package for your Napatech version.
    E.g., *ntanl_package_3gd-\<VERSION\>-linux.zip*

2.  Install the package:

        unzip ntanl_package_3gd-<VERSION>-linux.zip
        cd ntanl_package_3gd-<VERSION>-linux
        ./package_install_3gd.sh

3.  Configure ntpcap.ini and ntservice.ini \... load balancing mode,
    streams, virtual interfaces, host rx/tx buffers, etc. \... TODO

4.  Start the Napatech service - /opt/napatech3/bin/ntstart.sh

## [Compiling YAF with Napatech](#compile-yaf-napatech) {#compile-yaf-napatech}

Here is a sample `configure` invocation (line-wrapped for readability):

    ./configure                           \
        --with-napatech=/opt/napatech3/   \
        --with-libpcap=/opt/napatech3/    \
        --enable-plugins                  \
        --enable-applabel                 \
        --enable-dpi

## [Running YAF with Napatech](#run-yaf-napatech) {#run-yaf-napatech}

A sample YAF invocation (line-wrapped for readability):

    yaf --daemon --live pcap --in napa_lb0             \
        --out localhost --ipfix-port=18000 --ipfix tcp \
        --dpi --max-payload=4096

The *napa\_lb0* INPUT\_SPECIFIER is an example virtual interface as might be
defined in ntpcap.ini.

## [Single Card Configuration](#single-card) {#single-card}

The Napatech SmartNIC sensor cards require installation of driver software
and tools. Napatech Link Capture Software, release version 12.2.6 was
installed via Napatech's installer script. This installed necessary tools,
drivers, documentation, FPGA images and libpcap version 1.9.0. It also
installed the imgctrl tool which is necessary to change images and update
the cards firmware.

Static configuration was applied, utilizing the Napatech ntservice.ini file
and ntpcap.ini file, which allows you to alter sensor parameters. The
ntservice.ini file was modified to allocate the number of host buffers, host
buffer memory, and which NUMA nodes were used. The ntpcap.ini file,
constructed of the Napatech Programming Language (ntpl), was adjusted to use
a Hash5TupleSorted hash key and to create four or ten virtual devices which
correlated with the four or ten load balanced streams. Note that ntservice
needs restarting after the ntservices.ini is changed. The ntpcap.ini can be
changed without restarting the services. We've tested using the host buffer
memory set at 2048 (2GB) and at 1024 (1GB). The default NUMA node was used
for each server according to the PCI bus slot. To collect metrics,
Napatech's built in monitoring tool was used, as well as the output from
YAF. Metrics were collected and stored in the following spreadsheets and are
available from SEI on request.

## [Dual Card Configuration](#dual-card) {#dual-card}

The Napatech NT40E3 cards support dual card functionality where two cards
are installed on the same system to support different packet processing
configurations and features. Each card is installed in its own PCI slot but
the Napatech port configuration binds the cards together to enable the user
to access x8 ports, 4 ports on each card. Further configuration of the Host
Buffers and Streams allows packet processing to be further refined.

We expected that YAF and the cards would drop a negligible number of
packets. Our tests followed two separate configurations: Distributed Port
(Distroport) and Per-Port.

### [Distroport](#distroport) {#distroport}

In this configuration, the ntpcap.ini file was setup to simply use the
Hash5TupleSorted algorithm available through the ntpl. The streams were not
assigned to any specific port or NUMA node allowing the configuration to
rely solely on the algorithm. Each interface needed to use the 'packet-based
interface configuration'. The ntservices.ini file was changed to allow 16
host buffers using 16 MB RAM for NUMA nodes 0 and 1. Also we set the Time
Sync Reference Priority to OSTime, which allows each card to sync up via the
operating system clock.

### [Per-Port](#per-port) {#per-port}

In this configuration, the ntpcap.ini file was setup to map the streams
directly to the physical ports of both cards. The streams were also mapped
to the NUMA nodes, split evenly among the two. In the ntservices.ini file,
we set the Time Sync Reference Priority to OSTime but set up 8 host buffers
using 2 GB RAM instead. In the ntpcap.ini file, we assigned our StreamIds to
the NUMA nodes, split evenly amongst the two. We also assigned 2 streams to
each physical port and used the 'packet-based interfaces' configuration.

# [Netronome](#netronome) {#netronome}

Netronome live input support requires the Netronome Flow Manager (NFM) which
includes the NFM PCAP library and NFM software. Use the **--with-netronome**
option to `./configure` to enable Netronome support. Standard interface
recording is enabled by default when running YAF with **--live=netronome**.

The Netronome Agilio SmartNIC Basic Firmware User Guide provided scripts
that helped configure and validate that the drivers needed were installed.
We installed the card on the Dell PE840. We originally had trouble
confirming that the card's virtual interfaces were available and ready to
use, even though our host machine recognized the card. After installing an
"out-of-tree" NFP driver and enabling the NFP's internal Command Push/Pull
(CPP) bus, we were able to keep the virtual interfaces up and running
consistently. After we confirmed that the card was receiving traffic, we
created custom scripts to streamline the testing process. These scripts
handled collecting and parsing metrics and displaying test results on
spreadsheets.

# [Bivio](#bivio) {#bivio}

Support for Bivio interface labeling requires YAF to be configured with
**--with-bivio**.

# [Interface Numbers in YAF](#interface-numbers) {#interface-numbers}

If YAF is compiled with libdag, libntapi, or NFM and the appropriate name is
given to **--live**, YAF, by default, will record the physical interface the
packet was received on. Interface values can be used to determine
directionality of a flow in some cases. To export these values, use the
**--export-interface** option when running YAF. To disable interface
collection, configure YAF with **--enable-interface=no**. To separate
traffic received on separate ports into different flows, use the
**--enable-daginterface** option when configuring YAF.


[installation]:  install.html

[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
