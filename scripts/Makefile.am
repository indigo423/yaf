##  Copyright 2006-2023 Carnegie Mellon University
##  See license information in LICENSE.txt.

##  Process this file with automake to produce Makefile.in
##  ------------------------------------------------------------------------
##  Makefile.am (scripts)
##  autotools build system for YAF
##  ------------------------------------------------------------------------
##  Authors: Emily Sarneso
##  ------------------------------------------------------------------------
##  @DISTRIBUTION_STATEMENT_BEGIN@
##  YAF 3.0.0
##
##  Copyright 2023 Carnegie Mellon University.
##
##  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
##  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
##  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
##  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
##  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
##  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
##  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
##  INFRINGEMENT.
##
##  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
##  contact permission@sei.cmu.edu for full terms.
##
##  [DISTRIBUTION STATEMENT A] This material has been approved for public
##  release and unlimited distribution.  Please see Copyright notice for
##  non-US Government use and distribution.
##
##  GOVERNMENT PURPOSE RIGHTS – Software and Software Documentation
##  Contract No.: FA8702-15-D-0002
##  Contractor Name: Carnegie Mellon University
##  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
##
##  The Government's rights to use, modify, reproduce, release, perform,
##  display, or disclose this software are restricted by paragraph (b)(2) of
##  the Rights in Noncommercial Computer Software and Noncommercial Computer
##  Software Documentation clause contained in the above identified
##  contract. No restrictions apply after the expiration date shown
##  above. Any reproduction of the software or portions thereof marked with
##  this legend must also reproduce the markings.
##
##  This Software includes and/or makes use of Third-Party Software each
##  subject to its own license.
##
##  DM23-2317
##  @DISTRIBUTION_STATEMENT_END@
##  ------------------------------------------------------------------------

AM_CFLAGS   = $(WARN_CFLAGS) $(DEBUG_CFLAGS)
AM_CPPFLAGS = $(YAF_CPPFLAGS) $(GLIB_CFLAGS) $(OPENSSL_CPPFLAGS) $(libfixbuf_CFLAGS)
AM_LDFLAGS  = $(libfixbuf_LIBS) $(GLIB_LIBS)
LDADD       = $(top_builddir)/airframe/src/libairframe.la $(GLIB_LDADD)

PODFILES = getFlowKeyHash.pod yafMeta2Pcap.pod yafzcbalance.pod
man1_MANS = getFlowKeyHash.1 yafMeta2Pcap.1
HTMLFILES = getFlowKeyHash.html yafMeta2Pcap.html yafzcbalance.html

bin_PROGRAMS = getFlowKeyHash yafMeta2Pcap

if HASPFRINGZC
bin_PROGRAMS += yafzcbalance
man1_MANS += yafzcbalance.1
endif

.pod.1:
	$(AM_V_GEN) $(POD2MAN) $(YAF_POD2MAN_ARGS) --section=1 $< $@

POD_TO_HTML = \
  { \
    file="$*.pod" ; \
    test -f "$${file}" || file="$(srcdir)/$${file}" ; \
    rm -f "$@.tmp" ; \
    $(POD2HTML) --noindex --title=$* --infile="$${file}" --outfile="$@.tmp" || \
      { rm -f "$@.tmp" ; exit 1; } ; \
    $(top_srcdir)/doc/add-header.pl "$@.tmp" || \
      { rm -f "$@.tmp" ; exit 1 ; } ; \
    test -f "$@.tmp" -a -s "$@.tmp" && mv "$@.tmp" "$@" || \
      { rm -f "$@.tmp" ; exit 1 ; } ; \
  }

pod_to_html_deps = Makefile $(top_srcdir)/doc/add-header.pl

.pod.html:
	$(AM_V_GEN) $(POD_TO_HTML)

getFlowKeyHash.html: getFlowKeyHash.pod $(pod_to_html_deps)
	$(AM_V_GEN) $(POD_TO_HTML)
yafMeta2Pcap.html: yafMeta2Pcap.pod $(pod_to_html_deps)
	$(AM_V_GEN) $(POD_TO_HTML)
yafzcbalance.html: yafzcbalance.pod $(pod_to_html_deps)
	$(AM_V_GEN) $(POD_TO_HTML)

copy-man-pages: $(HTMLFILES)
	$(MKDIR_P) $(top_builddir)/doc/html
	test -z "$(HTMLFILES)" || cp $(HTMLFILES) $(top_builddir)/doc/html

docs: $(man1_MANS) copy-man-pages

clean-docs:
	rm -f $(man1_MANS) $(HTMLFILES)

CLEANFILES = $(man1_MANS) $(HTMLFILES)

EXTRA_DIST = $(PODFILES) \
	yafzcbalance.c

clean-local:
	rm -f pod2htm*.tmp

getFlowKeyHash_SOURCES = getFlowKeyHash.c

yafMeta2Pcap_SOURCES = yafMeta2Pcap.c

yafzcbalance_SOURCES = yafzcbalance.c
yafzcbalance_LDFLAGS = $(GLIB_LIBS) -lpthread
yafzcbalance_CPPFLAGS = $(YAF_CPPFLAGS) $(GLIB_CFLAGS)

check_PROGRAMS = packtest
packtest_SOURCES = packtest.c
packtest_LDADD =
packtest_LDFLAGS =
