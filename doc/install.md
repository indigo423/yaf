% YAF: Installation Instructions &amp; Dependencies

YAF may be installed from [pre-built RPM files](#installRPM) on supported
platforms or by [compiling the source code](#fromSource).

When installing from a pre-built RPM, ideally `yum` should find and install
any required dependencies for you. If not, read the next section on
dependencies.

# [Dependencies](#dependencies) {#dependencies}

Build and/or install these dependencies before installing YAF.

## [Basic Build Environment](#build-dev) {#build-dev}

When building from source, ensure you have the packages needed to build
software.

-   For Redhat, Fedora, and other RPM systems, run

        sudo yum -y install gcc gcc-c++ make pkgconfig

    Alternatively, you may install the tools for a complete development
    environment:

        sudo yum -y group install "Development Tools"

-   For Debian and Ubuntu, run

        sudo apt install build-essential

-   For macOS, install Xcode from the App Store and the Xcode command line
    tools.

## [Package Dependency Note](#dev-packages) {#dev-packages}

On some systems (particularly Linux), many support libraries (for example,
`libpcap`), are divided into two (or more) packages:

1.   One package satisfies a *run dependency*: It is needed to run another
     package that depends on it. This package is named libpcap-VERISON.rpm
     on Redhat and libpcap-*VERSION*.deb on Ubuntu.

2.   Another package satisfies a *build dependency*: It is needed only when
     building a another piece of software, and it contains C header files
     and additional library files. This package is named
     libpcap-devel-*VERSION*.rpm on Redhat and libpcap-dev-*VERSION*.deb on
     Ubuntu.

3.   Sometimes documentation is in a third package.

When installing dependencies to build YAF from source, ensure you install
the package(s) that require the build dependencies; for example, either
`libpcap-devel` or `libpcap-dev`. Installing these packages also installs
the packages needed for the run dependency (for example `libpcap`).

When installing dependencies to install an RPM of YAF, only the run
dependency is needed (for example `libpcap`), and often the package manager
finds these packages for you.

## [Required Dependencies](#required-dependencies) {#required-dependencies}

YAF requires [GLib-2.0][] 2.18 or later. Note that GLib is included in many
operating environments or ports collections.

YAF requires [libpcap][]. Note that libpcap is included with many operating
environments or ports collections.

YAF requires [libfixbuf][]. YAF 3.x requires libfixbuf 3.x. Consult this
table for earlier versions.

| YAF VERSIONS   | FIXBUF VERSIONS |
| ------------   | --------------- |
| 3.0            | 3.0 |
| 2.11.x, 2.12.x | 2.3 and any later 2.x |
| 2.10.x         | any 2.x version |
| 2.8.x, 2.9.x   | 1.7 and any later 1.x |
| 2.6.x, 2.7.x   | 1.4 and any later 1.x |

## [Optional Dependencies](#optional-dependencies) {#optional-dependencies}

YAF is built with support to process compressed PCAP files when the [zlib][]
library is found by `configure`. Many systems have zlib installed.

The application labeling feature requires [PCRE][] 7.3 or later (but not
PCRE2). Many Linux systems already have PCRE installed. If `configure` does
not find PCRE, ensure the directory holding the `libpcre.pc` file is
included in the PKG\_CONFIG\_PATH environment variable.

OS fingerprinting via **p0f** requires the [libp0f][] library and specifying
the **--with-p0f** option to `configure`. You may need to set the
PKG\_CONFIG\_PATH environment variable if libp0f is not installed in the
default location.

YAF contains support for [**PF\_RING**][pfring] and [**PF\_RING ZC** (ZERO
COPY)][pfringzc]. PF\_RING is available through [ntop][]. Download and
install PF\_RING (v.6.2.0 or higher) kernel modules, drivers, and library.
PF\_RING ZC requires a license purchase through [ntop][ntopshop]. Specify
**--with-pfring** on the `configure` command line to enable this support. To
use PF\_RING ZC, you are required to run [yafzcbalance][] (a tool installed
with YAF) or a similar application which will load balance the traffic on
one or more interfaces to one or more YAF applications.

YAF can use the [nDPI][] deep packet inspection library. Specify
**--with-ndpi** to `configure` and if necessary modify the PKG\_CONFIG\_PATH
environment variable to help `configure` find the library.

For network card specific dependencies see
[Integration with Specific Network Cards][networkcards].

# [Install from the CERT Linux Forensics Tools Repository](#installRPM) {#installRPM}

On a Redhat, Fedora, or RPM-based host, the easiest way to install YAF is
using the [CERT Linux Forensics Tools Repository][lifter].

If you follow the instructions to add the Tools Reposistory to the locations
your your system looks for packages, you can use yum to find the YAF package
and yum will install its dependencies.

An alternative is the to download the YAF package, and install YAF and its
dependencies manually. See the [dependency section](#dependencies) above for
the list of dependencies.

# [Install from Source](#fromSource) {#fromSource}

To install from source, first [download][download] the version of YAF you
want to install.

YAF uses a reasonably standard autotools-based build system. YAF finds
libfixbuf using the pkg-config facility, and you may have to set the
PKG\_CONFIG\_PATH variable on the `configure` command line if the library is
installed in a nonstandard location; the build process automatically updates
PKG\_CONFIG\_PATH with the directory where YAF is being installed.

To install YAF from source you can run the following commands:

    $ tar -xvzf yaf-3.0.0.tar.gz
    $ cd yaf-3.0.0
    $ ./configure {configure_options}
    $ make
    $ make install

**NOTE** Installing from source will overwrite previous versions of YAF's
configuration files in the `/usr/local/etc` directory (the location may be
different depending on the options to `configure`). If you have customized
these files, make copies of them prior to installing a new version of YAF:
dhcp\_fingerprints.conf, p0f.fp, yaf.conf, yafDPIRules.conf

## [Configuration Options](#configuration-options) {#configuration-options}

YAF supports the following configuration options in addition to those
supplied by default via autoconf (such as **--prefix**). Unless otherwise
noted, the default behavior is to disable the feature when the option is not
given.

**--enable-plugins**

:   Enable support in YAF to load plug-in extensions.

**--enable-applabel**

:   Enable the packet payload application label engine (requires the
    [PCRE][] library).

**--enable-dpi**

:   Enable the deep packet inspection capabilities (requires
    **--enable-applabel**).

**--enable-entropy**

:   Enable the packet payload entropy calculation.

**--enable-daginterface**

:   Enable encoding DAG interface numbers into the record output.

**--enable-fpexporter**

:   Enable export of handshake headers for external operating system
    fingerprinters to use.

**--enable-mpls**

:   Enable MPLS label hashing and export.

**--enable-nonip**

:   Enable non-IP data decode and flow export (requires **--enable-mpls**).

**--enable-exportDNSAuth**

:   Enable export of DNS Authoritative Responses only.

**--enable-exportDNSNXDomain**

:   Enable export of DNS NXDomain Responses only.

**--enable-localtime**

:   Use the local timezone for command inputs and for printing
    records. Default is to use UTC.

**--with-libpcap=PCAP_DIR**

:   Tell `configure` that pcap.h is in PCAP\_DIR/include and libpcap in is
    PCAP\_DIR/lib.  YAF requires libpcap.

**--with-ndpi**

:   Enable nDPI application labeling (requires the [nDPI][] library).
    `configure` uses PKG\_CONFIG\_PATH to find nDPI.

**--with-pfring**, **--with-pfring=PFRING\_DIR**

:   Include [PF\_RING][pfring] or [PF\_RING ZC (Zero Copy)][pfringzc]
    support; tell `configure` to find pfring.h in PFRING\_DIR/include and
    libpfring in PFRING\_DIR/lib.

**--with-dag**, **--with-dag=DAG\_DIR**

:   Include Endace DAG support; tell `configure` to find dag.h in
    DAG\_DIR/include and libdag in DAG\_DIR/lib.

**--with-napatech**, **--with-napatech=NT\_DIR**

:   Include Napatech support; tell `configure` to find nt.h in
    NT\_DIR/include and libntapi in NT\_DIR/lib.

**--with-netronome**, **--with-netronome=NFE\_DIR**

:   Include Netronome API support; tell `configure` to find nfe_packetcap.h
    in NFE\_DIR/include.

**--with-bivio**, **--with-bivio=PCAP\_ZCOPY\_DIR**

:   Include Bivio support; tell configure to find pcap-zcopy.h in
    PCAP\_ZCOPY\_DIR/include

**--with-p0f**

:   Enable the p0f-based OS fingerprinting capability (requires [libp0f][]).
    `configure` uses PKG\_CONFIG\_PATH to find libp0f.

**--with-zlib**, **--with-zlib=ZLIB\_DIR**

:   Include the ability to read compressed PCAP files; tell configure to
    find zlib.h in ZLIB\_DIR/include and libz in ZLIB\_DIR/lib. The
    `configure` script automatically looks for [zlib][] and enables this
    feature when it is found.

**--with-zlib-includes=ZLIB\_INCLUDE**

:   Look for zlib.h in the ZLIB\_INCLUDE directory instead of in
    ZLIB\_DIR/include.

**--with-zlib-libraries=ZLIB\_LIB**

:   Look for libz in the ZLIB\_LIB directory instead of in ZLIB\_DIR/lib.

**--disable-interface**

:   Do not enable encoding of Napatech, Netronome, or DAG interface numbers
    into the record output. (Default is to enable).

**--disable-compact-ip4**

:   Disable use of compact data structures for IPv4 addresses internally and
    instead use full-sized IP address structures in the flow table. Has no
    effect on YAF's output.

**--disable-payload**

:   Disable YAF from being built with payload handling capability; payload
    processing is required for application labeling, deep packet inspection,
    entropy support, handshake header (fpexport) support, and p0f
    fingerprinting support.

**--disable-metadata-export**

:   Disable the ability to export options records for enterprise-specific
    information elements and template metadata.


[GLib-2.0]:       https://docs.gtk.org/glib/
[PCRE]:           http://www.pcre.org/
[libpcap]:        https://www.tcpdump.org/
[lifter]:         https://forensics.cert.org/
[nDPI]:           https://www.ntop.org/products/deep-packet-inspection/ndpi/
[ntop]:           http://www.ntop.org/get-started/download/
[ntopshop]:       https://shop.ntop.org/
[pfring]:         https://www.ntop.org/products/packet-capture/pf_ring/
[pfringzc]:       https://www.ntop.org/products/packet-capture/pf_ring/pf_ring-zc-zero-copy/
[zlib]:           http://zlib.net/

[libfixbuf]:      /fixbuf/index.html
[libp0f]:         /p0f/libp0f.html

[download]:       download.html
[networkcards]:   networkcards.html
[yafzcbalance]:   yafzcbalance.html


[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
