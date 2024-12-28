/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  @file tftpplugin.c
 *
 *  @brief this is a protocol classifier for the Trivial File Transfer protocol
 *  (TFTP)
 *
 *  TFTP is a very simple protocol used to transfer files.
 *
 *  @sa rfc 1350  href="http://www.ietf.org/rfc/rfc1350.txt"
 *
 *  ------------------------------------------------------------------------
 *  Authors: Emily Ecoff
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


#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <yaf/yafcore.h>
#include <yaf/decode.h>

#include <arpa/inet.h>
#include <yaf/yafDPIPlugin.h>

#ifdef YAF_ENABLE_DPI

#define YAF_TFTP_TID   0xC400
#define YAF_TFTP_NAME  "yaf_tftp"
#define YAF_TFTP_DESC  NULL

static fbInfoElementSpec_t yaf_tftp_spec[] = {
    {"tftpFilename",          FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"tftpMode",              FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_tftp_st {
    fbVarfield_t   tftpFilename;
    fbVarfield_t   tftpMode;
} yaf_tftp_t;

static fbTemplate_t *yaf_tftp_tmpl;
#endif  /* YAF_ENABLE_DPI */

#define TFTP_PORT_NUMBER 69


static pcre *tftpRegex = NULL;


/**
 * ydpScanPayload
 *
 * returns TFTP_PORT_NUMBER if the passed in payload matches
 * a trivial file transfer protocol packet
 *
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * return 0 if no match
 */
uint16_t
ydpScanPayload(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
#define NUM_CAPT_VECTS 60
    int      vects[NUM_CAPT_VECTS];
    uint32_t offset = 0;
    int      rc;
    uint16_t tempVar = 0;
    uint16_t opcode;

    if (payloadSize < 3) {
        return 0;
    }

    opcode = ntohs(*(uint16_t *)payload);
    offset += 2;

    switch (opcode) {
      case 0:
        return 0;

      case 1:
      case 2:
        /* RRQ or WRQ */
        rc = pcre_exec(tftpRegex, NULL, (char *)payload, payloadSize,
                       0, 0, vects, NUM_CAPT_VECTS);
        if (rc <= 0) {
            return 0;
        }
#ifdef YAF_ENABLE_DPI
        if (rc > 1) {
            uint8_t fileLength = 0;
            fileLength = vects[3] - vects[2];
            ydRunPluginRegex(flow, payload, fileLength, NULL,
                             vects[2], 69, TFTP_PORT_NUMBER);
        }
        if (rc > 2) {
            tempVar = vects[5] - vects[4];  /*len of mode*/
            ydRunPluginRegex(flow, payload, tempVar, NULL, vects[4], 70,
                             TFTP_PORT_NUMBER);
        }
#endif /* ifdef YAF_ENABLE_DPI */
        break;

      case 3:
      case 4:
        /* DATA or ACK packet */
        tempVar = ntohs(*(uint16_t *)(payload + offset));
        if (tempVar != 1) {
            return 0;
        }
        break;

      case 5:
        /* Error Packet */
        tempVar = ntohs(*(uint16_t *)(payload + offset));
        /* Error codes are 1-7 */
        if (tempVar > 8) {
            return 0;
        }
        break;

      default:
        return 0;
    }

    return TFTP_PORT_NUMBER;
}


#ifdef YAF_ENABLE_DPI
void *
ydpProcessDPI(
    ypDPIFlowCtx_t       *flowContext,
    fbSubTemplateList_t  *stl,
    yfFlow_t             *flow,
    uint8_t               fwdcap,
    uint8_t               totalcap)
{
    yfDPIData_t *dpi = flowContext->dpi;
    yaf_tftp_t  *rec = NULL;
    int          count = flowContext->startOffset;

    rec = (yaf_tftp_t *)fbSubTemplateListInit(stl, 3, YAF_TFTP_TID,
                                              yaf_tftp_tmpl, 1);

    if (fwdcap) {
        rec->tftpFilename.buf = flow->val.payload + dpi[count].dpacketCapt;
        rec->tftpFilename.len = dpi[count].dpacketCaptLen;
        if (fwdcap > 1) {
            count++;
            rec->tftpMode.buf = flow->val.payload + dpi[count].dpacketCapt;
            rec->tftpMode.len = dpi[count].dpacketCaptLen;
        }
    } else if (flow->rval.payload) {
        rec->tftpFilename.buf = flow->rval.payload + dpi[count].dpacketCapt;
        rec->tftpFilename.len = dpi[count].dpacketCaptLen;
        if (dpi[++count].dpacketCapt) {
            rec->tftpMode.buf = flow->rval.payload + dpi[count].dpacketCapt;
            rec->tftpMode.len = dpi[count].dpacketCaptLen;
        }
    }

    return (void *)rec;
}

gboolean
ydpAddTemplates(
    fbSession_t  *session,
    GError      **err)
{
    fbTemplateInfo_t *mdInfo;

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_TFTP_NAME, YAF_TFTP_DESC,
                       TFTP_PORT_NUMBER, FB_TMPL_MD_LEVEL_1);

    if (!ydInitTemplate(&yaf_tftp_tmpl, session, yaf_tftp_spec,
                        mdInfo, YAF_TFTP_TID, 0, err))
    {
        return FALSE;
    }
    return TRUE;
}

void
ydpFreeRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yaf_tftp_t *rec = (yaf_tftp_t *)flowContext->rec;
    (void)rec;
}
#endif  /* YAF_ENABLE_DPI */


/**
 * ydpInitialize
 *
 * this initializes the PCRE expressions needed to search the payload for
 * TFTP and enables DPI Information Elements.
 *
 *
 * @sideeffect sets the initialized flag on success
 *
 * @return 1 if initialization is completed correctly, 0 on warning, -1 on
 * error.
 */
int
ydpInitialize(
    int        argc,
    char      *argv[],
    uint16_t   applabel,
    gboolean   applabelOnly,
    void      *extra,
    GError   **err)
{
    pluginExtras_t *pluginExtras = (pluginExtras_t *)extra;
    GArray         *pluginRegexes = (GArray *)pluginExtras->pluginRegexes;

    tftpRegex = ycFindCompilePluginRegex(
        pluginRegexes, "tftpRegex", PCRE_ANCHORED, err);

    if (!tftpRegex) {
        g_prefix_error(err, "In TFTP plugin: ");
        return -1;
    }
#ifdef YAF_ENABLE_DPI
    GArray *pluginTemplates = (GArray *)pluginExtras->pluginTemplates;
    YC_ENABLE_ELEMENTS(yaf_tftp, pluginTemplates);
#endif
    return 1;
}
