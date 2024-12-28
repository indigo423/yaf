##  Copyright 2005-2023 Carnegie Mellon University
##  See license information in LICENSE.txt.

##  Process this file with automake to produce Makefile.in
##  ------------------------------------------------------------------------
##  Makefile.am (documentation)
##  autotools build system for NAF applications
##  ------------------------------------------------------------------------
##  Authors: Brian Trammell
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


MARKDOWN_SOURCE = \
  applabeling.md \
  deeppacketinspection.md \
  docs.md \
  faq.md \
  install.md \
  networkcards.md \
  new_yaf3.md \
  usecases.md \
  yaf_orcus.md \
  yaf_pcap.md \
  yaf_pcap2.md \
  yaf_silk.md \
  yaf_sm_pipeline.md \
  yaf_sm_silk.md

MARKDOWN_HTML = \
  applabeling.html \
  deeppacketinspection.html \
  docs.html \
  faq.html \
  install.html \
  networkcards.html \
  new_yaf3.html \
  usecases.html \
  yaf_orcus.html \
  yaf_pcap.html \
  yaf_pcap2.html \
  yaf_silk.html \
  yaf_sm_pipeline.html \
  yaf_sm_silk.html

HTMLFILES = $(MARKDOWN_HTML) applabel.html yafdpi.html

# Do not include the TOC when making an HTML version of a man page
PANDOC_ARGS = \
  --standalone \
  --from markdown-smart \
  --to html \
  --columns 1000 \
  --css 'yaf.css'

PANDOC_ARGS_TOC = $(PANDOC_ARGS) --table-of-contents

MD_TO_HTML = \
  { \
    file="$*.md" ; \
    test -f "$${file}" || file="$(srcdir)/$${file}" ; \
    rm -f "$@.tmp" ; \
    sed -e 's|^\[//\]:.*||' "$${file}" | \
    $(PANDOC) $(PANDOC_ARGS_TOC) | \
    $(PERL) -lpwe 's,<(header|nav)\b[^>]*>,,; s,</(header|nav)>,,;' > "$@.tmp" ; \
    test -f "$@.tmp" -a -s "$@.tmp" && mv "$@.tmp" "$@" || \
      { rm -f "$@.tmp" ; exit 1 ; } ; \
  }

md_to_html_deps = Makefile

.md.html:
	$(AM_V_GEN) $(MD_TO_HTML)

applabeling.html: applabeling.md $(md_to_html_deps)
	$(AM_V_GEN) $(MD_TO_HTML)
deeppacketinspection.html: deeppacketinspection.md $(md_to_html_deps)
	$(AM_V_GEN) $(MD_TO_HTML)
docs.html: docs.md $(md_to_html_deps)
	$(AM_V_GEN) $(MD_TO_HTML)
faq.html: faq.md $(md_to_html_deps)
	$(AM_V_GEN) $(MD_TO_HTML)
install.html: install.md $(md_to_html_deps)
	$(AM_V_GEN) $(MD_TO_HTML)
networkcards.html: networkcards.md $(md_to_html_deps)
	$(AM_V_GEN) $(MD_TO_HTML)
new_yaf3.html: new_yaf3.md $(md_to_html_deps)
	$(AM_V_GEN) $(MD_TO_HTML)
usecases.html: usecases.md $(md_to_html_deps)
	$(AM_V_GEN) $(MD_TO_HTML)
yaf_orcus.html: yaf_orcus.md $(md_to_html_deps)
	$(AM_V_GEN) $(MD_TO_HTML)
yaf_pcap.html: yaf_pcap.md $(md_to_html_deps)
	$(AM_V_GEN) $(MD_TO_HTML)
yaf_pcap2.html: yaf_pcap2.md $(md_to_html_deps)
	$(AM_V_GEN) $(MD_TO_HTML)
yaf_silk.html: yaf_silk.md $(md_to_html_deps)
	$(AM_V_GEN) $(MD_TO_HTML)
yaf_sm_pipeline.html: yaf_sm_pipeline.md $(md_to_html_deps)
	$(AM_V_GEN) $(MD_TO_HTML)
yaf_sm_silk.html: yaf_sm_silk.md $(md_to_html_deps)
	$(AM_V_GEN) $(MD_TO_HTML)

MAN_SED = sed \
  -e 's|\?\?PACKAGE_VERSION\?\?|$(PACKAGE_VERSION)|' \
  -e 's|\?\?sysconfdir\?\?|/usr/local/etc|' \
  -e 's|\?\?pkglibdir\?\?|/usr/local/lib/yaf|'

#   Adds markdown for a man-page-style header and footer to the
#   markdown file on the standard input, then passes that through sed
#   to pandoc to create an HTML version of the man page
#
#   Add sed expression to modify the first line
#
MD_TO_MAN_TO_HTML = \
  { \
    test -n "$${file}" || { echo "file is not set" 2>&1 ; exit 1 ; } ; \
    test -f "$${file}" || file="$(srcdir)/$${file}" ; \
    rm -f "$@.tmp" ; \
    $(PERL) $(srcdir)/manify-md.pl --key=$@ "$${file}" | \
    $(MAN_SED) | \
    sed -e '1s/).*/)/' | \
    $(PANDOC) $(PANDOC_ARGS) | \
    $(PERL) -lpwe 's,<(header|nav)\b[^>]*>,,; s,</(header|nav)>,,;' > "$@.tmp" ; \
    test -f "$@.tmp" -a -s "$@.tmp" && mv "$@.tmp" "$@" || \
      { rm -f "$@.tmp" ; exit 1 ; } ; \
  }

md_to_man_to_html_deps = $(md_to_html_deps) $(srcdir)/manify-md.pl

applabel.html: applabeling.md $(md_to_man_to_html_deps)
	$(AM_V_GEN) file=applabeling.md ; $(MD_TO_MAN_TO_HTML)
yafdpi.html: deeppacketinspection.md $(md_to_man_to_html_deps)
	$(AM_V_GEN) file=deeppacketinspection.md ; $(MD_TO_MAN_TO_HTML)

NEWS2XHTML = \
  { \
    file=$(top_srcdir)/NEWS ; \
    rm -f "$@.tmp" ; \
    $(PERL) $(srcdir)/news2xhtml.pl < "$${file}" > "$@.tmp" || { rm -f "$@.tmp" ; exit 1 ; } ; \
    test -f "$@.tmp" -a -s "$@.tmp" && mv "$@.tmp" "$@" || \
      { rm -f "$@.tmp" ; exit 1 ; } ; \
   }

releases.xml: $(top_srcdir)/NEWS Makefile $(srcdir)/news2xhtml.pl
	$(AM_V_GEN) $(NEWS2XHTML)

copy-css:
	test -d html || mkdir html
	cp yaf.css html/.

copy-html-pages: $(HTMLFILES)
	test -d html || mkdir html
	test -z "$(HTMLFILES)" || cp $(HTMLFILES) html/.

docs: releases.xml copy-html-pages copy-css

clean-docs:
	test -z "$(HTMLFILES)" || rm -f $(HTMLFILES)
	rm -f releases.xml
	rm -rf html

DISTCLEANFILES = $(HTMLFILES) releases.xml

distclean-local:
	rm -rf html

EXTRA_DIST = $(MARKDOWN_SOURCE) yaf.css \
  add-header.pl manify-md.pl news2xhtml.pl
