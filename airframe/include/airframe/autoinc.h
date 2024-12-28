/*
 *  Copyright 2005-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  autoinc.h
 *  Autotools-happy standard library include file
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell
 *  ------------------------------------------------------------------------
 *  @DISTRIBUTION_STATEMENT_BEGIN@
 *  YAF 3.0.0
 *
 *  Copyright 2023 Carnegie Mellon University.
 *
 *  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 *  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 *  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
 *  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 *  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
 *  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 *  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
 *  INFRINGEMENT.
 *
 *  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
 *  contact permission@sei.cmu.edu for full terms.
 *
 *  [DISTRIBUTION STATEMENT A] This material has been approved for public
 *  release and unlimited distribution.  Please see Copyright notice for
 *  non-US Government use and distribution.
 *
 *  GOVERNMENT PURPOSE RIGHTS – Software and Software Documentation
 *  Contract No.: FA8702-15-D-0002
 *  Contractor Name: Carnegie Mellon University
 *  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
 *
 *  The Government's rights to use, modify, reproduce, release, perform,
 *  display, or disclose this software are restricted by paragraph (b)(2) of
 *  the Rights in Noncommercial Computer Software and Noncommercial Computer
 *  Software Documentation clause contained in the above identified
 *  contract. No restrictions apply after the expiration date shown
 *  above. Any reproduction of the software or portions thereof marked with
 *  this legend must also reproduce the markings.
 *
 *  This Software includes and/or makes use of Third-Party Software each
 *  subject to its own license.
 *
 *  DM23-2317
 *  @DISTRIBUTION_STATEMENT_END@
 *  ------------------------------------------------------------------------
 */

/**
 *  @file
 *  Convenience include file for libairframe.
 */

#ifndef _AIR_AUTOINC_H_
#define _AIR_AUTOINC_H_

#ifdef _AIRFRAME_SOURCE_
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>

#ifdef  HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef  HAVE_INTTYPES_H
#  include <inttypes.h>
#endif
#ifdef  HAVE_STDINT_H
#  include <stdint.h>
#endif
#ifdef  HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef  HAVE_SYS_TIME_H
#  include <sys/time.h>
#endif

#ifdef  HAVE_FCNTL_H
#  include <fcntl.h>
#endif
#ifdef  HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef  HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef  HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef  HAVE_SYSLOG_H
#  include <syslog.h>
#endif
#ifdef  HAVE_GLOB_H
#  include <glob.h>
#endif
#ifdef  HAVE_DIRENT_H
#  include <dirent.h>
#endif
#ifdef  HAVE_PWD_H
#  include <pwd.h>
#endif
#ifdef  HAVE_GRP_H
#  include <grp.h>
#endif

#include <glib.h>

#ifdef  HAVE_PCAP_H
#include <pcap.h>
#endif
#ifdef  WITH_DMALLOC
#include <dmalloc.h>
#endif

#endif /* ifndef _AIR_AUTOINC_H_ */
