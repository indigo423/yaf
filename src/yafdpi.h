/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafdpi.h
 *
 *  This defines the interface to the payload scanner functions
 *
 *  ------------------------------------------------------------------------
 *  Authors: Chris Inacio
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



#ifndef YAFDPI_H_
#define YAFDPI_H_

#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <yaf/yafcore.h>
#include <yaf/decode.h>


/**
 * Labels a flow's protocol according to its payload. Sets the appLabel
 * field within the flow.
 *
 * @param flow A YAF flow.
 *
 */
void
ydScanFlow(
    yfFlow_t  *flow);

void
ydAllocFlowContext(
    yfFlow_t  *flow);

void
ydFreeFlowContext(
    yfFlow_t  *flow);

void
ydInitDPI(
    gboolean    dpiEnabled,
    const char *dpiProtos,
    const char *rulesFileName);

void
ydPrintApplabelTiming(
    void);

#ifdef YAF_ENABLE_DPI
fbInfoModel_t *
ydGetDPIInfoModel(
    void);

gboolean
ydWriteDPIList(
    fbSubTemplateList_t  *rec,
    yfFlow_t             *flow,
    GError              **err);

gboolean
ydAddDPITemplatesToSession(
    fbSession_t  *session,
    GError      **err);

void
ydFreeDPILists(
    fbSubTemplateList_t  *stl,
    yfFlow_t             *flow);
#endif  /* YAF_ENABLE_DPI */
#endif  /* ifndef YAFDPI_H_ */
