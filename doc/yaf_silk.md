% Configuring YAF with SiLK

This tutorial is a step-by-step guide for setting up YAF and [SiLK][] on a
single machine for standalone Flow collection and analysis. These
instructions assume the user is on a Fedora, Redhat, or other RPM-based
system.

# [Install the Tools](#ys_install) {#ys_install}

This section is a brief summary of the installation of YAF and SiLK. For
detailed instructions, including using prebuilt RPMs from the SEI's Forensic
Team's Linux Tool Repository, see [this page][yaf_installation].

## [Install the Compiler and the Prerequisites](#ys_dev) {#ys_dev}

    $ yum groupinstall "Development Tools"
    $ yum install libpcap libpcap-devel pcre pcre-devel glib2-devel
    
## [Build and Install the NetSA Tools](#ys_netsa) {#ys_netsa}

### [libfixbuf](#ys_libfixbuf) {#ys_libfixbuf}

Build and install [libfixbuf][].

    $ tar -xvzf libfixbuf-3.0.0.tar.gz
    $ cd libfixbuf-3.0.0
    $ ./configure
    $ make
    $ make install

### [YAF](#ys_buildyaf) {#ys_buildyaf}

Build and install YAF. The minimum recommended options are shown here; see
the [installation page][yaf_installation] for other options.
    
>   **Note:** If you are upgrading YAF, the **make install** command here
>   will overwrite your exiting `/usr/local/etc/yaf.conf` file. Consider
>   making a backup of that file first.

    $ tar -xvzf yaf-3.0.0.tar.gz
    $ cd yaf-3.0.0
    $ ./configure --enable-applabel --enable-dpi
    $ make
    $ make install

When building YAF from source, the following file must be installed by hand.
It allows running **yaf** as a service:

    $ cp etc/init.d/yaf /etc/init.d/
    $ chmod +x /etc/init.d/yaf

### [SiLK](#ys_buildsilk) {#ys_buildsilk}

Build and install [SiLK][]. It is best if you can specify the default
location of the SiLK repository at build time, though this can be changed
later via an environment variable. Here, we use `/data` as the SiLK
repository.

    $ tar -xvzf silk-3.19.2.tar.gz
    $ cd silk-3.19.2
    $ ./configure --with-libfixbuf=/usr/local/lib/pkgconfig \
          --enable-ipv6 --enable-data-rootdir=/data
    $ make
    $ make install

# [Setup SiLK](#ys_silk) {#ys_silk}

This example uses /data as the location of the SiLK repository:

    $ mkdir -p /data

The default [silk.conf][] that comes with the SiLK distribution is typically
sufficient and should be copied to the repository:

    $ cp /usr/local/share/silk/twoway-silk.conf /data/silk.conf

>   **Note:** If you have installed from an RPM, you will find the above
>   file in the /usr/share/silk directory.

To run rwflowpack as a service:

>   **Note:** If you have installed from an RPM, these files are already in
>   place, and you need to edit /etc/sysconfig/rwflowpack.conf below.

    $ cp /usr/local/share/silk/etc/init.d/rwflowpack /etc/init.d/rwflowpack
    $ chmod +x /etc/init.d/rwflowpack
    $ cp /usr/local/share/silk/etc/rwflowpack.conf /usr/local/etc/rwflowpack.conf

To configure **rwflowpack**, edit `/usr/local/etc/rwflowpack.conf`:

    #/usr/local/etc/rwflowpack.conf
    ENABLED=1
    statedirectory=/var/lib/rwflowpack
    CREATE_DIRECTORIES=yes
    BIN_DIR=/usr/local/sbin
    SENSOR_CONFIG=/data/sensor.conf
    DATA_ROOTDIR=/data
    SITE_CONFIG=/data/silk.conf
    PACKING_LOGIC=
    INPUT_MODE=stream
    INCOMING_DIR=${statedirectory}/incoming
    ARCHIVE_DIR=${statedirectory}/archive
    FLAT_ARCHIVE=0
    ERROR_DIR=  #${statedirectory}/error
    OUTPUT_MODE=local
    SENDER_DIR=${statedirectory}/sender-incoming
    INCREMENTAL_DIR=${statedirectory}/incremental
    COMPRESSION_TYPE=
    POLLING_INTERVAL=
    FLUSH_TIMEOUT=
    FILE_CACHE_SIZE=
    FILE_LOCKING=1
    PACK_INTERFACES=0
    LOG_TYPE=syslog
    LOG_LEVEL=info
    LOG_DIR=${statedirectory}/log
    PID_DIR=${LOG_DIR}
    USER=root
    EXTRA_OPTIONS=

The [sensor.conf][] is required to setup the listening probe.  Change the
internal-ipblocks to match your network

    probe S0 ipfix
       listen-on-port 18001
       protocol tcp
    end probe

    sensor S0
       ipfix-probes S0
       internal-ipblocks 192.168.1.0/24 10.10.10.0/24
       external-ipblocks remainder
    end sensor

Move the sensor.conf to the repository:

    $ mv sensor.conf /data

Start **rwflowpack**:

    $ service rwflowpack start

Verify that **rwflowpack** is listening on port 18001:

    $ netstat -vnatpl

To use the SiLK command line tools, you may need to set the
SILK\_DATA\_ROOTDIR variable:

    $ export SILK_DATA_ROOTDIR=/data

# [Configure YAF](#ys_yaf) {#ys_yaf}

Create a directory for the **yaf** log file:

    $ mkdir /var/log/yaf
    $ mkdir /var/log/yaf/log
    $ mkdir /var/log/yaf/run

    $ export LTDL_LIBRARY_PATH=/usr/local/lib/yaf

To configure **yaf**, edit the configuration file `/usr/local/etc/yaf.conf`:

>   **Note:** If you have installed from an RPM, this file is in
>   `/etc/yaf.conf`.

    ENABLED=1
    YAF_CAP_TYPE=pcap
    YAF_CAP_IF=eth0
    YAF_IPFIX_PROTO=tcp
    YAF_IPFIX_HOST=localhost
    YAF_IPFIX_PORT=18001
    YAF_STATEDIR=/var/log/yaf
    YAF_EXTRAFLAGS="--silk --applabel --max-payload=2048 --dpi"

# [Start YAF](#ys_goyaf) {#ys_goyaf}

Either start YAF via service

    $ service yaf start

or invoke **yaf** from the command line.  See the following 2 examples.

Example **yaf** command line for processing a PCAP file:

    $ /usr/local/bin/yaf \
        --in <PCAP FILE> \
        --ipfix tcp \
        --out localhost \
        --ipfix-port 18001 \
        --log /var/log/yaf/yaf.log \
        --verbose \
        --silk \
        --dpi --max-payload 2048

Example **yaf** command line for sniffing interface eth0:

    $ /usr/local/bin/yaf \
        --in eth0 --live pcap \
        --ipfix tcp \
        --out localhost \
        --ipfix-port 18001 \
        --log /var/log/yaf/yaf.log \
        --verbose \
        --silk \
        --dpi --max-payload 2048

If you see an error similar to:

    Starting yaf:    /usr/local/bin/yaf: error while loading shared libraries: libairframe-2.5.0.so.4: cannot open shared object file: No such file or directory [Failed]

Run:

    $ ldconfig

Or add `/usr/local/lib` to the LD\_LIBRARY\_PATH environment variable.

Confirm SiLK is creating flow records:

    $ rwfilter --proto=0- --type=all --pass=stdout | rwcut | head


[SiLK]:                 /silk/index.html
[libfixbuf]:            /fixbuf/index.html
[sensor.conf]:          /silk/sensor.conf.html
[silk.conf]:            /silk/silk.conf.html

[yaf_installation]:     install.html

[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
