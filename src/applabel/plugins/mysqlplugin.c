/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  @file mysqlplugin.c
 *
 *  @brief this is a protocol classifier for the MySQL protocol (MySQL)
 *
 *  MySQL
 *
 *  @ href="http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol"
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

#define YAF_MYSQL_TID       0xCE0C
#define YAF_MYSQL_NAME      "yaf_mysql"
#define YAF_MYSQL_DESC      NULL

#define YAF_MYSQL_TXT_TID   0xCE0D
#define YAF_MYSQL_TXT_NAME  "yaf_mysql_txt"
#define YAF_MYSQL_TXT_DESC  NULL

static fbInfoElementSpec_t yaf_mysql_spec[] = {
    {"mysqlCommandTextCodeList",   FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"mysqlUsername",              FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_mysql_st {
    /* STL of yaf_mysql_txt */
    fbSubTemplateList_t   mysqlCommandTextCodeList;
    fbVarfield_t          mysqlUsername;
} yaf_mysql_t;

static fbInfoElementSpec_t yaf_mysql_txt_spec[] = {
    {"mysqlCommandText",           FB_IE_VARLEN, YAF_DISABLE_IE_FLAG },
    {"mysqlCommandCode",           1, YAF_DISABLE_IE_FLAG },
    {"paddingOctets",              7, YAF_INT_PADDING_FLAG },
    FB_IESPEC_NULL
};

typedef struct yaf_mysql_txt_st {
    fbVarfield_t   mysqlCommandText;
    uint8_t        mysqlCommandCode;
    uint8_t        padding[7];
} yaf_mysql_txt_t;

static fbTemplate_t *yaf_mysql_tmpl;
static fbTemplate_t *yaf_mysql_txt_tmpl;
#endif /* ifdef YAF_ENABLE_DPI */

#define MYSQL_PORT_NUMBER 3306


/**
 * ydpScanPayload
 *
 * returns MYSQL_PORT_NUMBER if the passed in payload matches
 * a MySQL Server Greeting packet
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
    uint32_t offset = 0;
    uint32_t fillerOffset = 0;
    int      i = 0;
    uint8_t  packetNumber;
    uint32_t packetLength;
    uint8_t  temp;

    if (0 == payloadSize) {
        return 0;
    }

    packetLength = ((*(uint32_t *)payload)) & 0x00FFFFFF;

    offset += 3;
    if (packetLength < 49 || offset > payloadSize ||
        packetLength > payloadSize)
    {
        return 0;
    }

    packetNumber = *(payload + offset);

    offset++;

    if (packetNumber > 1) {
        return 0;
    }

    if (offset > payloadSize) {
        return 0;
    }

    if (packetNumber == 0) {
        /* Server Greeting */
        /*protoVersion = *(payload + offset);*/
        offset++;

        /* Version would be here - str until null*/

        /* Beginning of 0x00 fillers */
        fillerOffset = packetLength - 26 + 4;

        if (fillerOffset + 13 > payloadSize) {
            return 0;
        }

        for (i = 0; i < 13; i++) {
            temp = *(payload + fillerOffset + i);
            if (temp != 0) {
                return 0;
            }
        }
    } else {
        /* Client Authentication */
        /* Client Capabilities && Extended Capabilities*/
        offset += 4;

        /* Max Packet Size + 1 for Charset*/
        offset += 5;

        if ((size_t)offset + 23 > payloadSize) {
            return 0;
        }

        for (i = 0; i < 23; i++) {
            temp = *(payload + offset);
            if (temp != 0) {
                return 0;
            }
            offset++;
        }

#ifdef YAF_ENABLE_DPI
        /* Here's the Username */
        i = 0;
        while ((offset < packetLength) &&
               ((size_t)offset + i < payloadSize))
        {
            if (*(payload + offset + i)) {
                i++;
            } else {
                break;
            }
        }

        ydRunPluginRegex(flow, payload, i, NULL, offset, 223,
                         MYSQL_PORT_NUMBER);

        /* Rest of pkt is password. Add 4 for pkt len & pkt num*/
        offset = packetLength + 4;

        if (packetLength > payloadSize) {
            return MYSQL_PORT_NUMBER;
        }

        /* Check for more packets */
        while (offset < payloadSize) {
            packetLength =
                (*(uint32_t *)(payload + offset)) & 0x00FFFFFF;

            if (packetLength > payloadSize) {
                return MYSQL_PORT_NUMBER;
            }

            offset += 4; /* add one for packet number */

            if (offset > payloadSize || packetLength == 0) {
                return MYSQL_PORT_NUMBER;
            }

            packetNumber = *(payload + offset);

            offset++;

            /* The text of the command follows */
            i = (packetLength - 1);

            if ((size_t)offset + i > payloadSize) {
                return MYSQL_PORT_NUMBER;
            }

            ydRunPluginRegex(flow, payload, i, NULL, offset,
                             packetNumber, MYSQL_PORT_NUMBER);

            offset += i;
        }

#endif /* ifdef YAF_ENABLE_DPI */
    }

    return MYSQL_PORT_NUMBER;
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
    yfDPIData_t     *dpi = flowContext->dpi;
    yaf_mysql_t     *rec = NULL;
    yaf_mysql_txt_t *mysql = NULL;
    yfFlowVal_t     *val;
    uint8_t          count;
    uint8_t          start = flowContext->startOffset;
    int              total = 0;

    g_assert(fwdcap <= totalcap);
    rec = (yaf_mysql_t *)fbSubTemplateListInit(stl, 3, YAF_MYSQL_TID,
                                               yaf_mysql_tmpl, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    for (count = start; count < totalcap; ++count) {
        /* since we test dpacketID < 29(0x1d), the != 223 is redundant.  did
         * not want to remove before confirming the test is correct. */
        if ((dpi[count].dpacketID != 223) && (dpi[count].dpacketID < 0x1d)) {
            total++;
        }
    }

    mysql = (yaf_mysql_txt_t *)fbSubTemplateListInit(
        &rec->mysqlCommandTextCodeList, 3, YAF_MYSQL_TXT_TID,
        yaf_mysql_txt_tmpl, total);
    val = &flow->val;
    for (count = start; count < totalcap && mysql != NULL; ++count) {
        if (count == fwdcap) {
            val = &flow->rval;
        }
        /* MySQL Username */
        if (dpi[count].dpacketID == 223) {
            rec->mysqlUsername.buf = val->payload + dpi[count].dpacketCapt;
            rec->mysqlUsername.len = dpi[count].dpacketCaptLen;
        } else {
            mysql->mysqlCommandCode = dpi[count].dpacketID;
            mysql->mysqlCommandText.buf = val->payload + dpi[count].dpacketCapt;
            mysql->mysqlCommandText.len = dpi[count].dpacketCaptLen;
            mysql = fbSubTemplateListGetNextPtr(
                &rec->mysqlCommandTextCodeList, mysql);
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
    fbTemplateInfoInit(mdInfo, YAF_MYSQL_NAME, YAF_MYSQL_DESC,
                       MYSQL_PORT_NUMBER, FB_TMPL_MD_LEVEL_1);

    if (!ydInitTemplate(&yaf_mysql_tmpl, session, yaf_mysql_spec,
                        mdInfo, YAF_MYSQL_TID, 0, err))
    {
        return FALSE;
    }

    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(mdInfo, YAF_MYSQL_TXT_NAME, YAF_MYSQL_TXT_DESC,
                       MYSQL_PORT_NUMBER, YAF_MYSQL_TID);

    if (!ydInitTemplate(&yaf_mysql_txt_tmpl, session, yaf_mysql_txt_spec,
                        mdInfo, YAF_MYSQL_TXT_TID, 0, err))
    {
        return FALSE;
    }
    return TRUE;
}

void
ydpFreeRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yaf_mysql_t *rec = (yaf_mysql_t *)flowContext->rec;

    fbSubTemplateListClear(&rec->mysqlCommandTextCodeList);
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
 * error
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
#ifdef YAF_ENABLE_DPI
    pluginExtras_t *pluginExtras = (pluginExtras_t *)extra;
    GArray         *pluginTemplates = (GArray *)pluginExtras->pluginTemplates;
    YC_ENABLE_ELEMENTS(yaf_mysql, pluginTemplates);
    YC_ENABLE_ELEMENTS(yaf_mysql_txt, pluginTemplates);
#endif /* ifdef YAF_ENABLE_DPI */
    return 1;
}
