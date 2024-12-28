/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafcore.c
 *  YAF core I/O routines
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell, Chris Inacio, Emily Ecoff
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
#include "yafctx.h"
#include <yaf/yafcore.h>
#include <yaf/decode.h>
#include <airframe/airutil.h>
#include <yaf/yafrag.h>
#ifdef YAF_ENABLE_DPI
#include <yafdpi.h>
#endif

#ifdef YAF_ENABLE_DPI
#define INFOMODEL_EXCLUDE_yaf_dpi 1
#endif
#define INFOMODEL_EXCLUDE_yaf_dhcp 1
#include "infomodel.h"

#ifdef YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif


/** These are the template ID's for the templates that YAF uses to
 *  select the output. Template ID's are maintained for a set of
 *  basic flow types data
 * BASE which gets various additions added as the flow requires,
 * FULL base plus the internal fields are added
 * EXT (extended) which has the additional records in the
 *    yaf_extime_spec (extended time specification)
 *
 *  WARNING: these need to be adjusted according to changes in the
 *  general & special dimensions */
#define YAF_FLOW_BASE_TID   0xB000 /* no general or special definitions */
#define YAF_FLOW_FULL_TID   0xB800 /* base no internal*/
#define YAF_FLOW_EXT_TID    0xB7FF /* everything except internal */

#define YAF_PROCESS_STATS_TID           0xD003
#define YAF_TOMBSTONE_TID               0xD004
#define YAF_TOMBSTONE_ACCESS_TID        0xD005
#define YAF_TYPE_METADATA_TID           0xD006
#define YAF_TEMPLATE_METADATA_TID       0xD007
#define YAF_TEMPLATE_METADATA_BL_TID    0xD008


#define YAF_FLOW_BASE_NAME "yaf_flow_base"
#define YAF_FLOW_FULL_NAME "yaf_flow_full"
#define YAF_FLOW_EXT_NAME  "yaf_flow_ext"

#define YAF_PROCESS_STATS_NAME      "yaf_process_stats"
#define YAF_TOMBSTONE_NAME          "tombstone_record"
#define YAF_TOMBSTONE_ACCESS_NAME   "tombstone_access"

#define YAF_TOP_LEVEL_DESC  ""
#define YAF_TOP_LEVEL_HIER  0x0

/** The dimensions are flags which determine which sets of fields will
 *  be exported out to an IPFIX record.  They are entries in a bitmap
 *  used to control the template. e.g. TCP flow information (seq num,
 *  tcp flags, etc.) only get added to the output record when the
 *  YTF_TCP flag is set; it only gets set when the transport protocol
 *  is set to 0x06. */

/* Generates the dimensions based on the 4 digit hidden flags and 4 digit
 * visible flags */
#define FLAG_GEN(h, v) (((h) & 0xFFFF) << 16 | ((v) & 0xFFFF))

/* Flow based dimensions */
#define YTF_RLE         FLAG_GEN(0x0001, 0x0000)
#define YTF_FLE         FLAG_GEN(0x0000, 0x0001) /* Non-reduced packet & octet
                                                  * counters */
#define YTF_TCP         FLAG_GEN(0x0000, 0x0002)
#define YTF_MPTCP       FLAG_GEN(0x0000, 0x0004)
#define YTF_IP4         FLAG_GEN(0x0002, 0x0000)
#define YTF_IP6         FLAG_GEN(0x0000, 0x0008)

/* Runtime dimensions */
#define YTF_TOTAL       FLAG_GEN(0x0004, 0x0000) /* Total (not delta) packet &
                                                  * octet counters */
#define YTF_DELTA       FLAG_GEN(0x0000, 0x0010)
#define YTF_BIF         FLAG_GEN(0x0000, 0x0020) /* Bi-flow */
#define YTF_DAGIF       FLAG_GEN(0x0000, 0x0040)
#define YTF_STATS       FLAG_GEN(0x0000, 0x0080)
#define YTF_MAC         FLAG_GEN(0x0000, 0x0100)
#define YTF_ENTROPY     FLAG_GEN(0x0000, 0x0200)
#define YTF_VNI         FLAG_GEN(0x0000, 0x0400)

/* Configure/runtime dimensions */
#define YTF_NDPI        FLAG_GEN(0x0010, 0x0000) /* Enabled via configure flag */
#define YTF_PAYLOAD     FLAG_GEN(0x0020, 0x0000) /* Enabled via runtime flag */
#define YTF_P0F         FLAG_GEN(0x0040, 0x0000) /* Enabled via configure flag */
#define YTF_FPEXPORT    FLAG_GEN(0x0080, 0x0000) /* Enabled via configure flag */
#define YTF_MPLS        FLAG_GEN(0x0100, 0x0000) /* Enabled via configure flag */
#define YTF_HOOK        FLAG_GEN(0x0200, 0x0000) /* Enabled via configure flag */
#define YTF_DPI         FLAG_GEN(0x0400, 0x0000) /* Enabled via runtime flag */


/* Special dimensions */
#define YTF_INTERNAL    FLAG_GEN(0x0000, 0x0800)
#define YTF_ALL         FLAG_GEN(0xFFFE, 0x0FFF) /* this is everything _except_
                                                  * RLE enabled */

#define YTF_RLE_NAME         "rle"
#define YTF_FLE_NAME         "fle"
#define YTF_TCP_NAME         "tcp"
#define YTF_MPTCP_NAME       "mptcp"
#define YTF_IP4_NAME         "ip4"
#define YTF_IP6_NAME         "ip6"
#define YTF_TOTAL_NAME       "total"
#define YTF_DELTA_NAME       "delta"
#define YTF_BIF_NAME         "biflow"
#define YTF_DAGIF_NAME       "dagif"
#define YTF_STATS_NAME       "stats"
#define YTF_MAC_NAME         "mac"
#define YTF_NDPI_NAME        "ndpi"
#define YTF_ENTROPY_NAME     "entropy"
#define YTF_VNI_NAME         "vni"
#define YTF_PAYLOAD_NAME     "payload"
#define YTF_P0F_NAME         "p0f"
#define YTF_FPEXPORT_NAME    "fpexport"
#define YTF_MPLS_NAME        "mpls"
#define YTF_INTERNAL_NAME    "internal"
#define YTF_ALL_NAME         "all"

/** If any of the FLE/RLE values are larger than this constant
 *  then we have to use FLE, otherwise, we choose RLE to
 *  conserve space/bandwidth etc.*/
#define YAF_RLEMAX      (1L << 31)

#define YF_PRINT_DELIM  "|"

/** Initial length to use for GStrings containing a flow record */
#define YF_PRINT_LINE_LEN   512

/**
 *  Names an environment variable that if defined (and if the first character
 *  is not '\0', '0', 'F', or 'f') causes the template alignment checks run by
 *  yaf and yafscii to be verbose.
 */
#define YAF_ALIGNMENT_CHECK  "YAF_ALIGNMENT_CHECK"


/* IPFIX definition of the full YAF flow record */
static fbInfoElementSpec_t yaf_flow_spec[] = {
    /* Millisecond start and end (epoch) (native time) */
    /* used by SM to label templates as TC_FLOW */
    { "flowStartMilliseconds",              8, 0 },
    /* used by SM to label templates as TC_FLOW */
    { "flowEndMilliseconds",                8, 0 },
    /* Counters */
    { "octetTotalCount",                    8, YTF_FLE | YTF_TOTAL },
    { "reverseOctetTotalCount",             8, YTF_FLE | YTF_TOTAL | YTF_BIF },
    { "packetTotalCount",                   8, YTF_FLE | YTF_TOTAL },
    { "reversePacketTotalCount",            8, YTF_FLE | YTF_TOTAL | YTF_BIF },
    /* delta Counters */
    { "octetDeltaCount",                    8, YTF_FLE | YTF_DELTA },
    { "reverseOctetDeltaCount",             8, YTF_FLE | YTF_DELTA | YTF_BIF },
    { "packetDeltaCount",                   8, YTF_FLE | YTF_DELTA },
    { "reversePacketDeltaCount",            8, YTF_FLE | YTF_DELTA | YTF_BIF },
    /* Reduced-length counters */
    { "octetTotalCount",                    4, YTF_RLE | YTF_TOTAL },
    { "reverseOctetTotalCount",             4, YTF_RLE | YTF_TOTAL | YTF_BIF },
    { "packetTotalCount",                   4, YTF_RLE | YTF_TOTAL },
    { "reversePacketTotalCount",            4, YTF_RLE | YTF_TOTAL | YTF_BIF },
    /* Reduced-length delta counters */
    { "octetDeltaCount",                    4, YTF_RLE | YTF_DELTA },
    { "reverseOctetDeltaCount",             4, YTF_RLE | YTF_DELTA | YTF_BIF },
    { "packetDeltaCount",                   4, YTF_RLE | YTF_DELTA },
    { "reversePacketDeltaCount",            4, YTF_RLE | YTF_DELTA | YTF_BIF },
    /* 5-tuple and flow status */
    { "sourceIPv6Address",                  16, YTF_IP6 },
    { "destinationIPv6Address",             16, YTF_IP6 },
    { "sourceIPv4Address",                  4, YTF_IP4 },
    { "destinationIPv4Address",             4, YTF_IP4 },
    /* used by SM to label templates as TC_FLOW */
    { "sourceTransportPort",                2, 0 },
    /* used by SM to label templates as TC_FLOW */
    { "destinationTransportPort",           2, 0 },
    /* used by SM to label templates as TC_FLOW */
    { "flowAttributes",                     2, 0 },
    /* used by SM to label flows as reverse */
    { "reverseFlowAttributes",              2, YTF_BIF },
    /* used by SM to label templates as TC_FLOW */
    { "protocolIdentifier",                 1, 0 },
    /* used by SM to label templates as TC_FLOW */
    { "flowEndReason",                      1, 0 },
#if defined(YAF_ENABLE_APPLABEL)
    { "silkAppLabel",                       2, 0 },
#else
    { "paddingOctets",                      2, YTF_INTERNAL },
#endif
    /* Round-trip time */
    /* used by SM to label flows as reverse */
    { "reverseFlowDeltaMilliseconds",       4, YTF_BIF }, /*  32-bit */
    /* used by SM to label templates as TC_FLOW */
    { "vlanId",                             2, 0 },
    /* used by SM to label flows as reverse */
    { "reverseVlanId",                      2, YTF_BIF },
    /* used by SM to label templates as TC_FLOW */
    { "ipClassOfService",                   1, 0 },
    /* used by SM to label flows as reverse */
    { "reverseIpClassOfService",            1, YTF_BIF },

#if defined(YAF_ENABLE_ENTROPY)
    /* Entropy */
    { "payloadEntropy",                     1, YTF_ENTROPY },
    { "reversePayloadEntropy",              1, YTF_ENTROPY | YTF_BIF },
#else
    { "paddingOctets",                      2, YTF_INTERNAL },
#endif /* if defined(YAF_ENABLE_ENTROPY) */

    /* MPTCP */
    { "mptcpInitialDataSequenceNumber",     8, YTF_MPTCP },
    { "mptcpReceiverToken",                 4, YTF_MPTCP },
    { "mptcpMaximumSegmentSize",            2, YTF_MPTCP },
    { "mptcpAddressId",                     1, YTF_MPTCP },
    { "mptcpFlags",                         1, YTF_MPTCP },

#ifdef YAF_ENABLE_DPI
    { "yafDPIList",                         FB_IE_VARLEN, YTF_DPI },
#endif

    /* MAC */
    { "paddingOctets",                      2, YTF_INTERNAL },
    { "sourceMacAddress",                   6, YTF_MAC },
    { "destinationMacAddress",              6, YTF_MAC },
    { "paddingOctets",                      2, YTF_INTERNAL },

#ifdef YAF_ENABLE_P0F
    /* P0F */
    { "osName",                             FB_IE_VARLEN, YTF_P0F },
    { "osVersion",                          FB_IE_VARLEN, YTF_P0F },
    { "osFingerprint",                      FB_IE_VARLEN, YTF_P0F },
    { "reverseOsName",                      FB_IE_VARLEN, YTF_P0F | YTF_BIF },
    { "reverseOsVersion",                   FB_IE_VARLEN, YTF_P0F | YTF_BIF },
    { "reverseOsFingerprint",               FB_IE_VARLEN, YTF_P0F | YTF_BIF },
#endif /* ifdef YAF_ENABLE_P0F */

#ifdef YAF_ENABLE_FPEXPORT
    { "firstPacketBanner",                  FB_IE_VARLEN, YTF_FPEXPORT },
    { "secondPacketBanner",                 FB_IE_VARLEN, YTF_FPEXPORT },
    { "reverseFirstPacketBanner",           FB_IE_VARLEN, YTF_FPEXPORT | YTF_BIF },
#endif /* ifdef YAF_ENABLE_FPEXPORT */

#ifdef YAF_ENABLE_PAYLOAD
    /* Payload */
    { "payload",                            FB_IE_VARLEN, YTF_PAYLOAD },
    { "reversePayload",                     FB_IE_VARLEN, YTF_PAYLOAD | YTF_BIF },
#endif /* ifdef YAF_ENABLE_PAYLOAD */

    /* DAG */
    { "ingressInterface",                   4, YTF_DAGIF },
    { "egressInterface",                    4, YTF_DAGIF },

    /* VNI */
    { "yafLayer2SegmentId",                 4, YTF_VNI },
    { "paddingOctets",                      4, YTF_INTERNAL },

    /* Flow stats */
    { "dataByteCount",                      8, YTF_STATS },
    { "averageInterarrivalTime",            8, YTF_STATS },
    { "standardDeviationInterarrivalTime",  8, YTF_STATS },
    { "tcpUrgTotalCount",                   4, YTF_STATS },
    { "smallPacketCount",                   4, YTF_STATS },
    { "nonEmptyPacketCount",                4, YTF_STATS },
    { "largePacketCount",                   4, YTF_STATS },
    { "firstNonEmptyPacketSize",            2, YTF_STATS },
    { "maxPacketSize",                      2, YTF_STATS },
    { "standardDeviationPayloadLength",     2, YTF_STATS },
    { "firstEightNonEmptyPacketDirections", 1, YTF_STATS },
    { "paddingOctets",                      1, YTF_STATS | YTF_INTERNAL },
    { "reverseDataByteCount",               8, YTF_STATS | YTF_BIF },
    { "reverseAverageInterarrivalTime",     8, YTF_STATS | YTF_BIF },
    { "reverseStandardDeviationInterarrivalTime", 8, YTF_STATS | YTF_BIF },
    { "reverseTcpUrgTotalCount",            4, YTF_STATS | YTF_BIF },
    { "reverseSmallPacketCount",            4, YTF_STATS | YTF_BIF },
    { "reverseNonEmptyPacketCount",         4, YTF_STATS | YTF_BIF },
    { "reverseLargePacketCount",            4, YTF_STATS | YTF_BIF },
    { "reverseFirstNonEmptyPacketSize",     2, YTF_STATS | YTF_BIF },
    { "reverseMaxPacketSize",               2, YTF_STATS | YTF_BIF },
    { "reverseStandardDeviationPayloadLength", 2, YTF_STATS | YTF_BIF },

    /* TCP */
    { "initialTCPFlags",                    1, YTF_TCP },
    { "unionTCPFlags",                      1, YTF_TCP },
    { "tcpSequenceNumber",                  4, YTF_TCP },
    { "reverseTcpSequenceNumber",           4, YTF_TCP | YTF_BIF },
    { "reverseInitialTCPFlags",             1, YTF_TCP | YTF_BIF },
    { "reverseUnionTCPFlags",               1, YTF_TCP | YTF_BIF },

#if defined(YAF_ENABLE_NDPI)
    { "ndpiL7Protocol",                     2, YTF_NDPI },
    { "ndpiL7SubProtocol",                  2, YTF_NDPI },
#else
    { "paddingOctets",                      4, YTF_INTERNAL },
#endif /* if defined(YAF_ENABLE_NDPI) */

    /* MPLS */
    { "paddingOctets",                      1, YTF_INTERNAL },
    { "mplsTopLabelStackSection",           3, YTF_MPLS },
    { "mplsLabelStackSection2",             3, YTF_MPLS },
    { "mplsLabelStackSection3",             3, YTF_MPLS },

#ifdef YAF_ENABLE_HOOKS
    { "subTemplateMultiList",               FB_IE_VARLEN, YTF_HOOK },
#endif
    FB_IESPEC_NULL
};

/* IPFIX definition of the YAF flow record time extension */
static fbInfoElementSpec_t yaf_extime_spec[] = {
    /* Microsecond start and end (RFC1305-style) (extended time) */
    { "flowStartMicroseconds",              8, 0 },
    { "flowEndMicroseconds",                8, 0 },
    /* Second start, end, and duration (extended time) */
    { "flowStartSeconds",                   4, 0 },
    { "flowEndSeconds",                     4, 0 },
    /* Flow durations (extended time) */
    { "flowDurationMicroseconds",           4, 0 },
    { "flowDurationMilliseconds",           4, 0 },
    /* Microsecond delta start and end (extended time) */
    { "flowStartDeltaMicroseconds",         4, 0 },
    { "flowEndDeltaMicroseconds",           4, 0 },
    FB_IESPEC_NULL
};

/* SM labels yaf stats by seeing if "most" of these elements are there
 * small changes will be ok, major rewrite needs coordination with SM */
/* SM has an Exact Match version. Changes won't break, but sync is good */
static fbInfoElementSpec_t yaf_process_stats_spec[] = {
    { "observationDomainId",                4, 0 },
    { "exportingProcessId",                 4, 0 },
    { "exporterIPv4Address",                4, 0 },
    { "observationTimeSeconds",             4, 0 },
    { "systemInitTimeMilliseconds",         8, 0 },
    { "exportedFlowRecordTotalCount",       8, 0 },
    { "packetTotalCount",                   8, 0 },
    { "droppedPacketTotalCount",            8, 0 },
    { "ignoredPacketTotalCount",            8, 0 },
    { "notSentPacketTotalCount",            8, 0 },
    { "yafExpiredFragmentCount",            4, 0 },
    { "yafAssembledFragmentCount",          4, 0 },
    { "yafFlowTableFlushEventCount",        4, 0 },
    { "yafFlowTablePeakCount",              4, 0 },
    { "yafMeanFlowRate",                    4, 0 },
    { "yafMeanPacketRate",                  4, 0 },
    FB_IESPEC_NULL
};

/* SM has an Exact Match version. Changes won't break, but sync is good */
static fbInfoElementSpec_t yaf_tombstone_spec[] = {
    { "observationDomainId",                4, 0 },
    { "exportingProcessId",                 4, 0 },
    { "certToolExporterConfiguredId",       2, 0 },
    { "paddingOctets",                      6, 0 },
    /* used by SM to label TOMBSTONE */
    { "certToolTombstoneId",                4, 0 },
    { "observationTimeSeconds",             4, 0 },
    { "certToolTombstoneAccessList",        FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

/* SM has an Exact Match version. Changes won't break, but sync is good */
static fbInfoElementSpec_t yaf_tombstone_access_spec[] = {
    { "certToolId",                         4, 0 },
    { "observationTimeSeconds",             4, 0 },
    FB_IESPEC_NULL
};

typedef struct yfTemplates_st {
    fbTemplate_t  *ipfixStatsTemplate;
    fbTemplate_t  *tombstoneRecordTemplate;
    fbTemplate_t  *tombstoneAccessTemplate;
} yfTemplates_t;

static yfTemplates_t yaf_tmpl;

/* IPv6-mapped IPv4 address prefix */
static uint8_t       yaf_ip6map_pfx[12] =
{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };

/* Full YAF flow record. */
typedef struct yfIpfixFlow_st {
    uint64_t                    flowStartMilliseconds;
    uint64_t                    flowEndMilliseconds;

    uint64_t                    octetTotalCount;
    uint64_t                    reverseOctetTotalCount;
    uint64_t                    packetTotalCount;
    uint64_t                    reversePacketTotalCount;

    uint64_t                    octetDeltaCount;
    uint64_t                    reverseOctetDeltaCount;
    uint64_t                    packetDeltaCount;
    uint64_t                    reversePacketDeltaCount;

    uint8_t                     sourceIPv6Address[16];
    uint8_t                     destinationIPv6Address[16];
    uint32_t                    sourceIPv4Address;
    uint32_t                    destinationIPv4Address;
    uint16_t                    sourceTransportPort;
    uint16_t                    destinationTransportPort;
    uint16_t                    flowAttributes;
    uint16_t                    reverseFlowAttributes;
    uint8_t                     protocolIdentifier;
    uint8_t                     flowEndReason;
#ifdef YAF_ENABLE_APPLABEL
    uint16_t                    silkAppLabel;
#else
    uint8_t                     paddingOctets1[2];
#endif
    int32_t                     reverseFlowDeltaMilliseconds;
    uint16_t                    vlanId;
    uint16_t                    reverseVlanId;
    uint8_t                     ipClassOfService;
    uint8_t                     reverseIpClassOfService;

#if defined(YAF_ENABLE_ENTROPY)
    uint8_t                     entropy;
    uint8_t                     reverseEntropy;
#else
    uint8_t                     paddingOctets2[2];
#endif /* if defined(YAF_ENABLE_ENTROPY) */

    /* MPTCP */
    uint64_t                    mptcpInitialDataSequenceNumber;
    uint32_t                    mptcpReceiverToken;
    uint16_t                    mptcpMaximumSegmentSize;
    uint8_t                     mptcpAddressId;
    uint8_t                     mptcpFlags;

#ifdef YAF_ENABLE_DPI
    fbSubTemplateList_t         yafDPIList;
#endif

    /* MAC */
    uint8_t                     paddingOctets3[2];
    uint8_t                     sourceMacAddress[6];
    uint8_t                     destinationMacAddress[6];
    uint8_t                     paddingOctets3_2[2];

#ifdef YAF_ENABLE_P0F
    fbVarfield_t                osName;
    fbVarfield_t                osVersion;
    fbVarfield_t                osFingerprint;
    fbVarfield_t                reverseOsName;
    fbVarfield_t                reverseOsVersion;
    fbVarfield_t                reverseOsFingerprint;
#endif /* ifdef YAF_ENABLE_P0F */

#ifdef YAF_ENABLE_FPEXPORT
    fbVarfield_t                firstPacketBanner;
    fbVarfield_t                secondPacketBanner;
    fbVarfield_t                reverseFirstPacketBanner;
#endif /* ifdef YAF_ENABLE_FPEXPORT */

#ifdef YAF_ENABLE_PAYLOAD
    /* Variable-length payload fields */
    fbVarfield_t                payload;
    fbVarfield_t                reversePayload;
#endif /* ifdef YAF_ENABLE_PAYLOAD */

    /* DAG */
    uint32_t                    ingressInterface;
    uint32_t                    egressInterface;

    uint32_t                    yafLayer2SegmentId;
    uint8_t                     paddingOctets4[4];

    /* Flow stats */
    uint64_t                    dataByteCount;
    uint64_t                    averageInterarrivalTime;
    uint64_t                    standardDeviationInterarrivalTime;
    uint32_t                    tcpUrgTotalCount;
    uint32_t                    smallPacketCount;
    uint32_t                    nonEmptyPacketCount;
    uint32_t                    largePacketCount;
    uint16_t                    firstNonEmptyPacketSize;
    uint16_t                    maxPacketSize;
    uint16_t                    standardDeviationPayloadLength;
    uint8_t                     firstEightNonEmptyPacketDirections;
    uint8_t                     paddingOctets5[1];
    /* reverse flow stats */
    uint64_t                    reverseDataByteCount;
    uint64_t                    reverseAverageInterarrivalTime;
    uint64_t                    reverseStandardDeviationInterarrivalTime;
    uint32_t                    reverseTcpUrgTotalCount;
    uint32_t                    reverseSmallPacketCount;
    uint32_t                    reverseNonEmptyPacketCount;
    uint32_t                    reverseLargePacketCount;
    uint16_t                    reverseFirstNonEmptyPacketSize;
    uint16_t                    reverseMaxPacketSize;
    uint16_t                    reverseStandardDeviationPayloadLength;

    /* TCP */
    uint8_t                     initialTCPFlags;
    uint8_t                     unionTCPFlags;
    uint32_t                    tcpSequenceNumber;
    uint32_t                    reverseTcpSequenceNumber;
    uint8_t                     reverseInitialTCPFlags;
    uint8_t                     reverseUnionTCPFlags;

    /* NDPI */
#ifdef YAF_ENABLE_NDPI
    uint16_t                    ndpi_master;
    uint16_t                    ndpi_sub;
#else
    uint8_t                     paddingOctets6[4];
#endif /* ifdef YAF_ENABLE_NDPI */

    /* MPLS */
    uint8_t                     paddingOctets7[1];
    uint8_t                     mpls_label1[3];
    uint8_t                     mpls_label2[3];
    uint8_t                     mpls_label3[3];

#ifdef YAF_ENABLE_HOOKS
    fbSubTemplateMultiList_t    subTemplateMultiList;
#endif
} yfIpfixFlow_t;

typedef struct yfIpfixExtFlow_st {
    yfIpfixFlow_t   f;
    uint64_t        flowStartMicroseconds;
    uint64_t        flowEndMicroseconds;
    uint32_t        flowStartSeconds;
    uint32_t        flowEndSeconds;
    uint32_t        flowDurationMicroseconds;
    uint32_t        flowDurationMilliseconds;
    uint32_t        flowStartDeltaMicroseconds;
    uint32_t        flowEndDeltaMicroseconds;
} yfIpfixExtFlow_t;

typedef struct yfIpfixStats_st {
    uint32_t   observationDomainId;
    uint32_t   exportingProcessId;
    uint32_t   exporterIPv4Address;
    uint32_t   observationTimeSeconds;
    uint64_t   systemInitTimeMilliseconds;
    uint64_t   exportedFlowTotalCount;
    uint64_t   packetTotalCount;
    uint64_t   droppedPacketTotalCount;
    uint64_t   ignoredPacketTotalCount;
    uint64_t   notSentPacketTotalCount;
    uint32_t   yafExpiredFragmentCount;
    uint32_t   yafAssembledFragmentCount;
    uint32_t   flowTableFlushEvents;
    uint32_t   yafFlowTablePeakCount;
    uint32_t   yafMeanFlowRate;
    uint32_t   yafMeanPacketRate;
} yfIpfixStats_t;

typedef struct yfTombstoneRecord_st {
    uint32_t              observationDomainId;
    uint32_t              exportingProcessId;
    uint16_t              certToolExporterConfiguredId;
    uint8_t               paddingOctets[6];
    uint32_t              certToolTombstoneId;
    uint32_t              observationTimeSeconds;
    fbSubTemplateList_t   accessList;
} yfTombstoneRecord_t;

typedef struct yfTombstoneAccess_st {
    uint32_t   certToolId;
    uint32_t   observationTimeSeconds;
} yfTombstoneAccess_t;

/* Core library configuration variables */
/* amount of payload to export; 0 to export none */
static unsigned int yaf_core_export_payload = 0;
#ifdef YAF_ENABLE_APPLABEL
/* limit export to these applabels; if NULL, export all */
static uint16_t *yaf_core_payload_applabels = NULL;
/* number of appLabels in `yaf_core_payload_applabels` */
static size_t yaf_core_payload_applabels_size = 0;
#endif  /* YAF_ENABLE_APPLABEL */

/* whether to map IPv4 addresses to IPv6 */
static gboolean     yaf_core_map_ipv6 = FALSE;

/**
 *  Checks the alignment of the record structs and aborts via g_error() if the
 *  elements are not aligned or there are gaps in the struct.
 *
 *  Ideally, all this magic would happen at compile time, but it doesn't
 *  currently, (can't really do it in C,) so we do it at run time.
 */
void
yfAlignmentCheck(
    void)
{
    size_t prevOffset = 0;
    size_t prevSize = 0;
    gboolean verbose = FALSE;
    const char *env;

    env = getenv(YAF_ALIGNMENT_CHECK);
    if (env) {
        switch (*env) {
          case '\0':
          case '0':
          case 'F':
          case 'f':
            break;
          default:
            verbose = TRUE;
            break;
        }
    }

    /* required aligned of an fbVarfield_t */
#define ALIGNED_VARFIELD    DO_SIZE(fbVarfield_t, buf)

    /* required aligned of an fbBasicList_t */
#define ALIGNED_BASICLIST   DO_SIZE(fbBasicList_t, dataPtr)

    /* required aligned of an fbSubTemplateList_t */
#define ALIGNED_STL         DO_SIZE(fbSubTemplateList_t, dataPtr)

    /* required aligned of an fbSubTemplateMultiList_t */
#define ALIGNED_STML        DO_SIZE(fbSubTemplateMultiList_t, firstEntry)

    /* compute sizeof member `F_` in struct `S_` */
#define DO_SIZE(S_, F_) (SIZE_T_CAST)sizeof(((S_ *)(0))->F_)

    /* exit with an error that member `F_` is not aligned on an
     * `L_`-byte-boundary in struct `S_` */
#define ABORT_ALIGNMENT(S_, F_, L_)                                     \
    g_error(("alignment error in struct " #S_ " for member " #F_        \
             ", offset %#" SIZE_T_FORMATX ", size %" SIZE_T_FORMAT      \
             ", required alignment %" SIZE_T_FORMAT                     \
             ", overhang %" SIZE_T_FORMAT),                             \
            (SIZE_T_CAST)offsetof(S_, F_), DO_SIZE(S_, F_),             \
            L_, (SIZE_T_CAST)(offsetof(S_, F_) % L_))

    /* exit with an error that struct `S_` contains a gap before member `F_`
     * (which requires `L_` alignment) and that previous member ended at
     * offset `P_` */
#define ABORT_GAP(S_, F_, L_, P_)                                       \
    g_error(("gap error in struct " #S_ " for member " #F_              \
             ", offset %#" SIZE_T_FORMATX ", size %" SIZE_T_FORMAT      \
             ", required alignement %" SIZE_T_FORMAT                    \
             ", end previous member %#" SIZE_T_FORMATX                  \
             ", gap %" SIZE_T_FORMAT),                                  \
            (SIZE_T_CAST)offsetof(S_, F_), DO_SIZE(S_, F_),             \
            L_, (SIZE_T_CAST)(P_),                                      \
            (SIZE_T_CAST)(offsetof(S_, F_) - P_))

    /* check that member `F_` in struct `S_` is properly aligned and does not
     * contain a gap between the previous member and `F_`.  If `A_` is 0, F_
     * must be on a multiple of its size.  If `A_` is any other value, `F_`
     * must be aligned on that size; specifically, octetArrays should use an
     * `A_` of 1 and structs should use DOSIZE() of their largest member. */
#define RUN_CHECKS(S_, F_, A_)                                          \
    {                                                                   \
        SIZE_T_CAST align = ((0 != (A_)) ? (A_) : DO_SIZE(S_, F_));     \
        if (((offsetof(S_, F_) % align) != 0)) {                        \
            ABORT_ALIGNMENT(S_, F_, align);                             \
        }                                                               \
        if (offsetof(S_, F_) != (prevOffset + prevSize)) {              \
            ABORT_GAP(S_, F_, align, (prevOffset + prevSize));          \
        }                                                               \
        prevOffset = offsetof(S_, F_);                                  \
        prevSize = DO_SIZE(S_, F_);                                     \
        if (verbose) {                                                  \
            fprintf(stderr,                                             \
                    "%19s %40s %#6lx %4" PRId64 " %#6" PRIx64 "\n",     \
                    #S_, #F_,                                           \
                    offsetof(S_,F_), DO_SIZE(S_,F_),                    \
                    offsetof(S_,F_)+DO_SIZE(S_,F_));                    \
        }                                                               \
    }


    RUN_CHECKS(yfIpfixFlow_t, flowStartMilliseconds, 0);
    RUN_CHECKS(yfIpfixFlow_t, flowEndMilliseconds, 0);

    RUN_CHECKS(yfIpfixFlow_t, octetTotalCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseOctetTotalCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, packetTotalCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, reversePacketTotalCount, 0);

    RUN_CHECKS(yfIpfixFlow_t, octetDeltaCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseOctetDeltaCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, packetDeltaCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, reversePacketDeltaCount, 0);

    RUN_CHECKS(yfIpfixFlow_t, sourceIPv6Address, 1);
    RUN_CHECKS(yfIpfixFlow_t, destinationIPv6Address, 1);
    RUN_CHECKS(yfIpfixFlow_t, sourceIPv4Address, 0);
    RUN_CHECKS(yfIpfixFlow_t, destinationIPv4Address, 0);
    RUN_CHECKS(yfIpfixFlow_t, sourceTransportPort, 0);
    RUN_CHECKS(yfIpfixFlow_t, destinationTransportPort, 0);
    RUN_CHECKS(yfIpfixFlow_t, flowAttributes, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseFlowAttributes, 0);
    RUN_CHECKS(yfIpfixFlow_t, protocolIdentifier, 0);
    RUN_CHECKS(yfIpfixFlow_t, flowEndReason, 0);
#ifdef YAF_ENABLE_APPLABEL
    RUN_CHECKS(yfIpfixFlow_t, silkAppLabel, 0);
#else
    RUN_CHECKS(yfIpfixFlow_t, paddingOctets1, 1);
#endif
    RUN_CHECKS(yfIpfixFlow_t, reverseFlowDeltaMilliseconds, 0);
    RUN_CHECKS(yfIpfixFlow_t, vlanId, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseVlanId, 0);
    RUN_CHECKS(yfIpfixFlow_t, ipClassOfService, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseIpClassOfService, 0);

#if defined(YAF_ENABLE_ENTROPY)
    /* Entropy */
    RUN_CHECKS(yfIpfixFlow_t, entropy, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseEntropy, 0);
#else
    RUN_CHECKS(yfIpfixFlow_t, paddingOctets2, 1);
#endif /* if defined(YAF_ENABLE_ENTROPY) */

    /* MPTCP */
    RUN_CHECKS(yfIpfixFlow_t, mptcpInitialDataSequenceNumber, 0);
    RUN_CHECKS(yfIpfixFlow_t, mptcpReceiverToken, 0);
    RUN_CHECKS(yfIpfixFlow_t, mptcpMaximumSegmentSize, 0);
    RUN_CHECKS(yfIpfixFlow_t, mptcpAddressId, 0);
    RUN_CHECKS(yfIpfixFlow_t, mptcpFlags, 0);

#ifdef YAF_ENABLE_DPI
    RUN_CHECKS(yfIpfixFlow_t, yafDPIList, ALIGNED_STL);
#endif

    /* MAC */
    RUN_CHECKS(yfIpfixFlow_t, paddingOctets3, 1);
    RUN_CHECKS(yfIpfixFlow_t, sourceMacAddress, 1);
    RUN_CHECKS(yfIpfixFlow_t, destinationMacAddress, 1);
    RUN_CHECKS(yfIpfixFlow_t, paddingOctets3_2, 1);

#ifdef YAF_ENABLE_P0F
    /* P0F */
    RUN_CHECKS(yfIpfixFlow_t, osName, ALIGNED_VARFIELD);
    RUN_CHECKS(yfIpfixFlow_t, osVersion, ALIGNED_VARFIELD);
    RUN_CHECKS(yfIpfixFlow_t, osFingerprint, ALIGNED_VARFIELD);
    RUN_CHECKS(yfIpfixFlow_t, reverseOsName, ALIGNED_VARFIELD);
    RUN_CHECKS(yfIpfixFlow_t, reverseOsVersion, ALIGNED_VARFIELD);
    RUN_CHECKS(yfIpfixFlow_t, reverseOsFingerprint, ALIGNED_VARFIELD);
#endif /* ifdef YAF_ENABLE_P0F */

#ifdef YAF_ENABLE_FPEXPORT
    /* FPEXPORT */
    RUN_CHECKS(yfIpfixFlow_t, firstPacketBanner, ALIGNED_VARFIELD);
    RUN_CHECKS(yfIpfixFlow_t, secondPacketBanner, ALIGNED_VARFIELD);
    RUN_CHECKS(yfIpfixFlow_t, reverseFirstPacketBanner, ALIGNED_VARFIELD);
#endif /* ifdef YAF_ENABLE_FPEXPORT */

#ifdef YAF_ENABLE_PAYLOAD
    /* Payload */
    RUN_CHECKS(yfIpfixFlow_t, payload, ALIGNED_VARFIELD);
    RUN_CHECKS(yfIpfixFlow_t, reversePayload, ALIGNED_VARFIELD);
#endif /* ifdef YAF_ENABLE_PAYLOAD */

    /* DAG */
    RUN_CHECKS(yfIpfixFlow_t, ingressInterface, 0);
    RUN_CHECKS(yfIpfixFlow_t, egressInterface, 0);

    RUN_CHECKS(yfIpfixFlow_t, yafLayer2SegmentId, 0);
    RUN_CHECKS(yfIpfixFlow_t, paddingOctets4, 1);

    RUN_CHECKS(yfIpfixFlow_t, dataByteCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, averageInterarrivalTime, 0);
    RUN_CHECKS(yfIpfixFlow_t, standardDeviationInterarrivalTime, 0);
    RUN_CHECKS(yfIpfixFlow_t, tcpUrgTotalCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, smallPacketCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, nonEmptyPacketCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, largePacketCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, firstNonEmptyPacketSize, 0);
    RUN_CHECKS(yfIpfixFlow_t, maxPacketSize, 0);
    RUN_CHECKS(yfIpfixFlow_t, standardDeviationPayloadLength, 0);
    RUN_CHECKS(yfIpfixFlow_t, firstEightNonEmptyPacketDirections, 0);
    RUN_CHECKS(yfIpfixFlow_t, paddingOctets5, 1);
    RUN_CHECKS(yfIpfixFlow_t, reverseDataByteCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseAverageInterarrivalTime, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseStandardDeviationInterarrivalTime, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseTcpUrgTotalCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseSmallPacketCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseNonEmptyPacketCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseLargePacketCount, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseFirstNonEmptyPacketSize, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseMaxPacketSize, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseStandardDeviationPayloadLength, 0);

    /* TCP */
    RUN_CHECKS(yfIpfixFlow_t, initialTCPFlags, 0);
    RUN_CHECKS(yfIpfixFlow_t, unionTCPFlags, 0);
    RUN_CHECKS(yfIpfixFlow_t, tcpSequenceNumber, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseTcpSequenceNumber, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseInitialTCPFlags, 0);
    RUN_CHECKS(yfIpfixFlow_t, reverseUnionTCPFlags, 0);

#ifdef YAF_ENABLE_NDPI
    RUN_CHECKS(yfIpfixFlow_t, ndpi_master, 0);
    RUN_CHECKS(yfIpfixFlow_t, ndpi_sub, 0);
#else
    RUN_CHECKS(yfIpfixFlow_t, paddingOctets6, 1);
#endif /* ifdef YAF_ENABLE_NDPI */

    /* MPLS */
    RUN_CHECKS(yfIpfixFlow_t, paddingOctets7, 1);
    RUN_CHECKS(yfIpfixFlow_t, mpls_label1, 1);
    RUN_CHECKS(yfIpfixFlow_t, mpls_label2, 1);
    RUN_CHECKS(yfIpfixFlow_t, mpls_label3, 1);

#ifdef YAF_ENABLE_HOOKS
    RUN_CHECKS(yfIpfixFlow_t, subTemplateMultiList, ALIGNED_STML);
#endif

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfIpfixExtFlow_t, f, DO_SIZE(yfIpfixFlow_t, octetTotalCount));
    RUN_CHECKS(yfIpfixExtFlow_t, flowStartMicroseconds, 0);
    RUN_CHECKS(yfIpfixExtFlow_t, flowEndMicroseconds, 0);
    RUN_CHECKS(yfIpfixExtFlow_t, flowStartSeconds, 0);
    RUN_CHECKS(yfIpfixExtFlow_t, flowEndSeconds, 0);
    RUN_CHECKS(yfIpfixExtFlow_t, flowDurationMicroseconds, 0);
    RUN_CHECKS(yfIpfixExtFlow_t, flowDurationMilliseconds, 0);
    RUN_CHECKS(yfIpfixExtFlow_t, flowStartDeltaMicroseconds, 0);
    RUN_CHECKS(yfIpfixExtFlow_t, flowEndDeltaMicroseconds, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfIpfixStats_t, observationDomainId, 0);
    RUN_CHECKS(yfIpfixStats_t, exportingProcessId, 0);
    RUN_CHECKS(yfIpfixStats_t, exporterIPv4Address, 0);
    RUN_CHECKS(yfIpfixStats_t, observationTimeSeconds, 0);
    RUN_CHECKS(yfIpfixStats_t, systemInitTimeMilliseconds, 0);
    RUN_CHECKS(yfIpfixStats_t, exportedFlowTotalCount, 0);
    RUN_CHECKS(yfIpfixStats_t, packetTotalCount, 0);
    RUN_CHECKS(yfIpfixStats_t, droppedPacketTotalCount, 0);
    RUN_CHECKS(yfIpfixStats_t, ignoredPacketTotalCount, 0);
    RUN_CHECKS(yfIpfixStats_t, notSentPacketTotalCount, 0);
    RUN_CHECKS(yfIpfixStats_t, yafExpiredFragmentCount, 0);
    RUN_CHECKS(yfIpfixStats_t, yafAssembledFragmentCount, 0);
    RUN_CHECKS(yfIpfixStats_t, flowTableFlushEvents, 0);
    RUN_CHECKS(yfIpfixStats_t, yafFlowTablePeakCount, 0);
    RUN_CHECKS(yfIpfixStats_t, yafMeanFlowRate, 0);
    RUN_CHECKS(yfIpfixStats_t, yafMeanPacketRate, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfTombstoneRecord_t, observationDomainId, 0);
    RUN_CHECKS(yfTombstoneRecord_t, exportingProcessId, 0);
    RUN_CHECKS(yfTombstoneRecord_t, certToolExporterConfiguredId, 0);
    RUN_CHECKS(yfTombstoneRecord_t, paddingOctets, 1);
    RUN_CHECKS(yfTombstoneRecord_t, certToolTombstoneId, 0);
    RUN_CHECKS(yfTombstoneRecord_t, observationTimeSeconds, 0);
    RUN_CHECKS(yfTombstoneRecord_t, accessList, ALIGNED_STL);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfTombstoneAccess_t, certToolId, 0);
    RUN_CHECKS(yfTombstoneAccess_t, observationTimeSeconds, 0);

    prevOffset = 0;
    prevSize = 0;


#undef ALIGNED_STRUCT
#undef DO_SIZE
#undef ABORT_ALIGNMENT
#undef ABORT_GAP
#undef RUN_CHECKS
}


void
yfWriterExportPayload(
    int   max_payload)
{
    yaf_core_export_payload = max_payload;
}

#ifdef YAF_ENABLE_APPLABEL
void
yfWriterExportPayloadApplabels(
    const GArray   *applabels)
{
    guint i;
    long applabel;

    g_assert(sizeof(long) == g_array_get_element_size((GArray *)applabels));
    if (0 == applabels->len) {
        return;
    }

    yaf_core_payload_applabels_size = applabels->len;
    yaf_core_payload_applabels = g_new(uint16_t, applabels->len);
    for (i = 0; i < applabels->len; ++i) {
        applabel = g_array_index(applabels, long, i);
        g_assert(applabel >= 0 && applabel <= UINT16_MAX);
        yaf_core_payload_applabels[i] = (uint16_t)applabel;
    }
}

static gboolean
findInApplabelArray(
    uint16_t    applabel)
{
    size_t i;
    for (i = 0; i < yaf_core_payload_applabels_size; i++) {
        if (yaf_core_payload_applabels[i] == applabel) {
            return TRUE;
        }
    }
    return FALSE;
}
#endif  /* YAF_ENABLE_APPLABEL */

void
yfWriterExportMappedV6(
    gboolean   map_mode)
{
    yaf_core_map_ipv6 = map_mode;
}


/**
 * yfFlowPrepare
 *
 * initialize the state of a flow to be "clean" so that they
 * can be reused
 *
 */
void
yfFlowPrepare(
    yfFlow_t  *flow)
{
#ifdef YAF_ENABLE_HOOKS
    unsigned int loop;
#endif

#ifdef YAF_ENABLE_PAYLOAD
    flow->val.paylen = 0;
    flow->val.payload = NULL;
    flow->rval.paylen = 0;
    flow->rval.payload = NULL;
#endif /* ifdef YAF_ENABLE_PAYLOAD */

#ifdef YAF_ENABLE_HOOKS
    for (loop = 0; loop < YAF_MAX_HOOKS; loop++) {
        flow->hfctx[loop] = 0x0;
    }
#endif

#ifdef YAF_ENABLE_DPI
    flow->dpictx = NULL;
#endif

    memset(flow->sourceMacAddr, 0, ETHERNET_MAC_ADDR_LENGTH);
    memset(flow->destinationMacAddr, 0, ETHERNET_MAC_ADDR_LENGTH);
}


/**
 * yfFlowCleanup
 *
 * cleans up after a flow is no longer needed by deallocating
 * the dynamic memory allocated to the flow (think payload)
 *
 */
void
yfFlowCleanup(
    yfFlow_t  *flow)
{
#ifdef YAF_ENABLE_PAYLOAD
    if (flow->val.payload) {
        g_free(flow->val.payload);
        flow->val.payload = NULL;
    }

    if (flow->rval.payload) {
        g_free(flow->rval.payload);
        flow->rval.payload = NULL;
    }
#endif /* ifdef YAF_ENABLE_PAYLOAD */
}


/**
 * yfPayloadCopyIn
 *
 *
 *
 *
 */
#ifdef YAF_ENABLE_PAYLOAD
static void
yfPayloadCopyIn(
    fbVarfield_t  *payvar,
    yfFlowVal_t   *val)
{
    if (payvar->len) {
        if (!val->payload) {
            val->payload = g_malloc0(payvar->len);
        } else {
            val->payload = g_realloc(val->payload, payvar->len);
        }
        val->paylen = payvar->len;
        memcpy(val->payload, payvar->buf, payvar->len);
    } else {
        if (val->payload) {g_free(val->payload);}
        val->payload = NULL;
        val->paylen = 0;
    }
}
#endif /* ifdef YAF_ENABLE_PAYLOAD */


/**
 * yfInfoModel
 *
 *
 */
static fbInfoModel_t *
yfInfoModel(
    void)
{
    static fbInfoModel_t *yaf_model = NULL;
#ifdef YAF_ENABLE_HOOKS
    fbInfoElement_t      *yaf_hook_elements = NULL;
#endif
    if (!yaf_model) {
        yaf_model = fbInfoModelAlloc();

        infomodelAddGlobalElements(yaf_model);

#ifdef YAF_ENABLE_HOOKS
        yaf_hook_elements = yfHookGetInfoModel();
        if (yaf_hook_elements) {
            fbInfoModelAddElementArray(yaf_model, yaf_hook_elements);
        }
#endif /* ifdef YAF_ENABLE_HOOKS */

#ifdef YAF_ENABLE_DPI
        /* Add in any elements that are created through user-specified DPI.
         * Note: There could definitely be a possibility of making this function
         *   public and having the DPI add it's elements to this, it would
         *   need to be looked into whether or not this affects the getting of
         *   hook's info models. Notably because getting the info model would
         *   then happen before initialization. */
        fbInfoModel_t *dpiModel = ydGetDPIInfoModel();
        fbInfoModelIter_t iter;
        const fbInfoElement_t *dpiElem;
        fbInfoModelIterInit(&iter, dpiModel);
        while ((dpiElem = fbInfoModelIterNext(&iter))) {
            if (!fbInfoModelContainsElement(yaf_model, dpiElem)) {
                fbInfoModelAddElement(yaf_model, dpiElem);
            }
        }
#endif  /* YAF_ENABLE_DPI */
    }

    return yaf_model;
}


/**
 * yfInitExporterSession
 *
 *
 */
static fbSession_t *
yfInitExporterSession(
    uint32_t    domain,
    yfConfig_t *cfg,
    GError    **err)
{
    fbInfoModel_t     *model = yfInfoModel();
    fbTemplate_t      *tmpl = NULL;
    fbSession_t       *session = NULL;
    fbTemplateInfo_t  *mdInfo = NULL;

    /* Allocate the session */
    session = fbSessionAlloc(model);

    /* set observation domain */
    fbSessionSetDomain(session, domain);

    /* Create the full record template */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_spec, YTF_ALL, err)) {
        return NULL;
    }

#ifdef YAF_ENABLE_METADATA_EXPORT
    /* yafcollect does not pass a cfg, so ensure non-NULL */
    if (cfg) {
        if (cfg->ie_metadata) {
            if (!fbSessionSetMetadataExportElements(
                    session, TRUE, YAF_TYPE_METADATA_TID, err))
            {
                return NULL;
            }
        }
        if (cfg->tmpl_metadata) {
            if (!fbSessionSetMetadataExportTemplates(
                    session, TRUE, YAF_TEMPLATE_METADATA_TID,
                    YAF_TEMPLATE_METADATA_BL_TID, err))
            {
                return NULL;
            }
        }
    }
#endif /* ifdef YAF_ENABLE_METADATA_EXPORT */

    /* Add the full record template to the internal session only */
    if (!fbSessionAddTemplate(session, TRUE, YAF_FLOW_FULL_TID,
                              tmpl, NULL, err))
    {
        return NULL;
    }

    if (!cfg || !cfg->nostats) {
        /* Create the Stats Options Template */
        yaf_tmpl.ipfixStatsTemplate = fbTemplateAlloc(model);
        if (!fbTemplateAppendSpecArray(yaf_tmpl.ipfixStatsTemplate,
                                       yaf_process_stats_spec, 0, err))
        {
            return NULL;
        }

        /* Scope fields are exporterIPv4Address, observationDomainId,
         * and exportingProcessID */
        fbTemplateSetOptionsScope(yaf_tmpl.ipfixStatsTemplate, 3);
#ifdef YAF_ENABLE_METADATA_EXPORT
        if (cfg && cfg->tmpl_metadata) {
            mdInfo = fbTemplateInfoAlloc();
            fbTemplateInfoInit(
                mdInfo, YAF_PROCESS_STATS_NAME, YAF_TOP_LEVEL_DESC, 0,
                FB_TMPL_MD_LEVEL_0);
        }
#endif /* ifdef YAF_ENABLE_METADATA_EXPORT */
        if (!fbSessionAddTemplate(session, FALSE, YAF_PROCESS_STATS_TID,
                                  yaf_tmpl.ipfixStatsTemplate, mdInfo, err))
        {
            return NULL;
        }
        if (!fbSessionAddTemplate(session, TRUE, YAF_PROCESS_STATS_TID,
                                  yaf_tmpl.ipfixStatsTemplate, NULL, err))
        {
            return NULL;
        }
    }

    if (!cfg || !cfg->no_tombstone) {
        /* Create the Tombstone record Template */
        yaf_tmpl.tombstoneRecordTemplate = fbTemplateAlloc(model);
        if (!fbTemplateAppendSpecArray(yaf_tmpl.tombstoneRecordTemplate,
                                       yaf_tombstone_spec, 0, err))
        {
            return NULL;
        }
        /* Scope fields are exportingProcessID, observationDomainId,
         * and certToolExporterConfiguredId */
        fbTemplateSetOptionsScope(yaf_tmpl.tombstoneRecordTemplate, 3);
#ifdef YAF_ENABLE_METADATA_EXPORT
        if (cfg && cfg->tmpl_metadata) {
            mdInfo = fbTemplateInfoAlloc();
            fbTemplateInfoInit(
                mdInfo, YAF_TOMBSTONE_NAME, YAF_TOP_LEVEL_DESC, 0,
                FB_TMPL_MD_LEVEL_0);
        }
#endif /* ifdef YAF_ENABLE_METADATA_EXPORT */
        if (!fbSessionAddTemplate(session, FALSE, YAF_TOMBSTONE_TID,
                                  yaf_tmpl.tombstoneRecordTemplate,
                                  mdInfo, err))
        {
            return NULL;
        }

        if (!fbSessionAddTemplate(session, TRUE, YAF_TOMBSTONE_TID,
                                  yaf_tmpl.tombstoneRecordTemplate, NULL, err))
        {
            return NULL;
        }

        /* Create the Tombstone Access SubTemplate */
        yaf_tmpl.tombstoneAccessTemplate = fbTemplateAlloc(model);
        if (!fbTemplateAppendSpecArray(yaf_tmpl.tombstoneAccessTemplate,
                                       yaf_tombstone_access_spec, 0, err))
        {
            return NULL;
        }
#ifdef YAF_ENABLE_METADATA_EXPORT
        if (cfg && cfg->tmpl_metadata) {
            mdInfo = fbTemplateInfoAlloc();
            fbTemplateInfoInit(
                mdInfo, YAF_TOMBSTONE_ACCESS_NAME, YAF_TOP_LEVEL_DESC, 0,
                FB_TMPL_MD_LEVEL_1);
        }
#endif /* ifdef YAF_ENABLE_METADATA_EXPORT */
        if (!fbSessionAddTemplate(session, FALSE, YAF_TOMBSTONE_ACCESS_TID,
                                  yaf_tmpl.tombstoneAccessTemplate, mdInfo,
                                  err))
        {
            return NULL;
        }
        if (!fbSessionAddTemplate(session, TRUE, YAF_TOMBSTONE_ACCESS_TID,
                                  yaf_tmpl.tombstoneAccessTemplate, NULL, err))
        {
            return NULL;
        }
    }

#ifdef YAF_ENABLE_HOOKS
    /*  Add the hook template fields if available  */
    if (!yfHookGetTemplate(session)) {
        g_debug("Hook Templates could not be added to the session");
    }
#endif /* ifdef YAF_ENABLE_HOOKS */

#ifdef YAF_ENABLE_DPI
    /*  Add the dpi template fields if available  */
    if (ydAddDPITemplatesToSession(session, err) == FALSE) {
        g_error("Error Getting Templates for DPI: %s"
                "DPI cannot be used. Exiting", (*err)->message);
        abort();
    }
#endif /* ifdef YAF_ENABLE_DPI */

    /* Done. Return the session. */
    return session;
}



/**
 * yfInitExporterBuffer
 *
 *
 *
 */
static fBuf_t *
yfInitExporterBuffer(
    fbSession_t   *session,
    fbExporter_t  *exporter,
    GError       **err)
{
    fBuf_t  *fbuf;

    fbuf = fBufAllocForExport(session, exporter);

    /* write YAF flow templates */
    if (!fbSessionExportTemplates(session, err)) {goto err;}

    /* set internal template */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {goto err;}

    /* all done */
    return fbuf;

  err:
    /* free buffer if necessary */
    if (fbuf) {fBufFree(fbuf);}
    return NULL;
}


/**
 * yfSetExportTemplate
 *
 *
 *
 */
#define TEMPLATE_NAME_INIT_LEN 32

static gboolean
yfSetExportTemplate(
    fBuf_t    *fbuf,
    uint32_t   tid,
    GError   **err)
{
    fbSession_t      *session = NULL;
    fbTemplate_t     *tmpl = NULL;
    GString          *template_name = NULL;
    uint16_t          tid_16_bit = (uint16_t)(tid & 0xFFFF);
    fbTemplateInfo_t *mdInfo = NULL;

    /* Try to set export template */
    if (fBufSetExportTemplate(fbuf, tid_16_bit, err)) {
        return TRUE;
    }

    /* Check for error other than missing template */
    if (!g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
        return FALSE;
    }

    /* Okay. We have a missing template. Clear the error and try to load it. */
    g_clear_error(err);

    template_name = g_string_sized_new(TEMPLATE_NAME_INIT_LEN);

    session = fBufGetSession(fbuf);
    tmpl = fbTemplateAlloc(yfInfoModel());

    if ( (tid & YAF_FLOW_BASE_TID) == YAF_FLOW_BASE_TID) {
        g_string_append_printf(template_name, "yaf_flow");

        if (tid & YTF_RLE) {
            g_string_append_printf(template_name, "_%s", YTF_RLE_NAME);
        } else {
            g_string_append_printf(template_name, "_%s", YTF_FLE_NAME);
        }

        if (tid & YTF_TCP) {
            g_string_append_printf(template_name, "_%s", YTF_TCP_NAME);
        }

        if (tid & YTF_MPTCP) {
            g_string_append_printf(template_name, "_%s", YTF_MPTCP_NAME);
        }

        if (tid & YTF_IP6) {
            g_string_append_printf(template_name, "_%s", YTF_IP6_NAME);
        } else {
            g_string_append_printf(template_name, "_%s", YTF_IP4_NAME);
        }

        if (tid & YTF_DELTA) {
            g_string_append_printf(template_name, "_%s", YTF_DELTA_NAME);
        } else {
            g_string_append_printf(template_name, "_%s", YTF_TOTAL_NAME);
        }

        if (tid & YTF_BIF) {
            g_string_append_printf(template_name, "_%s", YTF_BIF_NAME);
        }

        if (tid & YTF_DAGIF) {
            g_string_append_printf(template_name, "_%s", YTF_DAGIF_NAME);
        }

        if (tid & YTF_STATS) {
            g_string_append_printf(template_name, "_%s", YTF_STATS_NAME);
        }

        if (tid & YTF_MAC) {
            g_string_append_printf(template_name, "_%s", YTF_MAC_NAME);
        }

        if (tid & YTF_NDPI) {
            g_string_append_printf(template_name, "_%s", YTF_NDPI_NAME);
        }

        if (tid & YTF_ENTROPY) {
            g_string_append_printf(template_name, "_%s", YTF_ENTROPY_NAME);
        }

        if (tid & YTF_VNI) {
            g_string_append_printf(template_name, "_%s", YTF_VNI_NAME);
        }

        if (tid & YTF_PAYLOAD) {
            g_string_append_printf(template_name, "_%s", YTF_PAYLOAD_NAME);
        }

        if (tid & YTF_P0F) {
            g_string_append_printf(template_name, "_%s", YTF_P0F_NAME);
        }

        if (tid & YTF_FPEXPORT) {
            g_string_append_printf(template_name, "_%s", YTF_FPEXPORT_NAME);
        }

        if (tid & YTF_MPLS) {
            g_string_append_printf(template_name, "_%s", YTF_MPLS_NAME);
        }
    }

    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_spec,
                                   (tid & (~YAF_FLOW_BASE_TID)), err))
    {
        return FALSE;
    }

#ifdef YAF_ENABLE_METADATA_EXPORT
    mdInfo = fbTemplateInfoAlloc();
    fbTemplateInfoInit(
        mdInfo, template_name->str, YAF_TOP_LEVEL_DESC, 0,
        FB_TMPL_MD_LEVEL_0);
#endif /* ifdef YAF_ENABLE_METADATA_EXPORT */

    if (!fbSessionAddTemplate(session, FALSE, tid_16_bit, tmpl, mdInfo, err))
    {
        g_error("error setting template metadata: tid: %x, name: %s\n",
                tid_16_bit, template_name->str);
        g_string_free(template_name, TRUE);
        return FALSE;
    }

    /*g_debug("adding new template %02x", tid);*/
    g_string_free(template_name, TRUE);

    /* Template should be loaded. Try setting the template again. */
    return fBufSetExportTemplate(fbuf, tid, err);
}


/**
 * yfWriterForFile
 *
 *
 */
fBuf_t *
yfWriterForFile(
    const char *path,
    void       *cfg_in,
    uint32_t    domain,
    GError    **err)
{
    yfConfig_t     *cfg = (yfConfig_t*)cfg_in;
    fbExporter_t   *exporter;
    fbSession_t    *session;

    /* Create a new buffer */
    if (!(session = yfInitExporterSession(domain, cfg, err))) {
        return NULL;
    }

    /* Allocate an exporter for the file */
    exporter = fbExporterAllocFile(path);

    return yfInitExporterBuffer(session, exporter, err);
}


/**
 * yfWriterForFP
 *
 *
 *
 */
fBuf_t *
yfWriterForFP(
    FILE      *fp,
    uint32_t   domain,
    GError   **err)
{
    fbExporter_t *exporter;
    fbSession_t  *session;

    /* Create a new buffer */
    if (!(session = yfInitExporterSession(domain, NULL, err))) {
        return NULL;
    }

    /* Allocate an exporter for the file */
    exporter = fbExporterAllocFP(fp);

    return yfInitExporterBuffer(session, exporter, err);
}


/**
 * yfWriterForSpec
 *
 *
 *
 */
fBuf_t *
yfWriterForSpec(
    fbConnSpec_t   *spec,
    void           *cfg_in,
    uint32_t        domain,
    GError        **err)
{
    yfConfig_t     *cfg = (yfConfig_t*)cfg_in;
    fbSession_t    *session;
    fbExporter_t   *exporter;

    /* initialize session and exporter */
    if (!(session = yfInitExporterSession(domain, cfg, err))) {
        return NULL;
    }

    exporter = fbExporterAllocNet(spec);

    /* 2021.03.22. Of the three yfWriterFor*() functions, only this one had a
     * call to fbSessionSetDomain() after the fbuf was created (in addition to
     * the one in yfInitExporterSession().  It should not matter, but adding
     * this reminder here in case we determine that it does.  */

    return yfInitExporterBuffer(session, exporter, err);
}


/**
 * yfWriteOptionsDataFlows
 *
 *
 */
gboolean
yfWriteOptionsDataFlows(
    void      *yfContext,
    uint32_t   pcap_drop,
    GTimer    *timer,
    GError   **err)
{
    yfContext_t *ctx = (yfContext_t *)yfContext;

    if (!yfWriteStatsFlow(yfContext, pcap_drop, timer, err)) {
        return FALSE;
    }
    if (!ctx->cfg->no_tombstone) {
        if (!yfWriteTombstoneFlow(yfContext, err)) {
            return FALSE;
        }
    }
    return TRUE;
}


/**
 * yfWriteStatsFlow
 *
 *
 */
gboolean
yfWriteStatsFlow(
    void      *yfContext,
    uint32_t   pcap_drop,
    GTimer    *timer,
    GError   **err)
{
    yfIpfixStats_t  rec;
    yfContext_t    *ctx = (yfContext_t *)yfContext;
    fBuf_t         *fbuf = ctx->fbuf;
    uint32_t        mask = 0x000000FF;
    char            buf[200];
    uint32_t        total_frags = 0;
    static struct hostent *host;
    static uint32_t host_ip = 0;

    yfGetFlowTabStats(ctx->flowtab, &(rec.packetTotalCount),
                      &(rec.exportedFlowTotalCount),
                      &(rec.notSentPacketTotalCount),
                      &(rec.yafFlowTablePeakCount),
                      &(rec.flowTableFlushEvents));
    if (ctx->fragtab) {
        yfGetFragTabStats(ctx->fragtab, &(rec.yafExpiredFragmentCount),
                          &(rec.yafAssembledFragmentCount), &total_frags);
    } else {
        rec.yafExpiredFragmentCount = 0;
        rec.yafAssembledFragmentCount = 0;
    }

    if (!fbuf) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Error Writing Stats Message: No fbuf [output] Available");
        return FALSE;
    }

    /* Get IP of sensor for scope */
    if (!host) {
        gethostname(buf, 200);
        host = (struct hostent *)gethostbyname(buf);
        if (host) {
            host_ip = (host->h_addr[0] & mask) << 24;
            host_ip |= (host->h_addr[1] & mask) << 16;
            host_ip |= (host->h_addr[2] & mask) << 8;
            host_ip |= (host->h_addr[3] & mask);
        }
    }

    /* Rejected/Ignored Packet Total Count from decode.c */
    rec.ignoredPacketTotalCount = yfGetDecodeStats(ctx->dectx);

    /* Dropped packets - from yafcap.c & libpcap */
    rec.droppedPacketTotalCount = pcap_drop;
    rec.exporterIPv4Address = host_ip;

    rec.observationDomainId = ctx->cfg->odid;
    rec.exportingProcessId = getpid();
    rec.observationTimeSeconds = (int)time(NULL);

    rec.yafMeanFlowRate =
        rec.exportedFlowTotalCount / g_timer_elapsed(timer, NULL);
    rec.yafMeanPacketRate = rec.packetTotalCount / g_timer_elapsed(timer, NULL);

    rec.systemInitTimeMilliseconds = ctx->yaf_start_time;

    g_debug("YAF statistics: Flows: %" PRIu64 " Packets: %" PRIu64
            " Dropped: %" PRIu64 " Ignored: %" PRIu64
            " Out of Sequence: %" PRIu64
            " Expired Frags: %u Assembled Frags: %u",
            rec.exportedFlowTotalCount, rec.packetTotalCount,
            rec.droppedPacketTotalCount, rec.ignoredPacketTotalCount,
            rec.notSentPacketTotalCount, rec.yafExpiredFragmentCount,
            rec.yafAssembledFragmentCount);

    /* Set Internal Template for Buffer to Options TID */
    if (!fBufSetInternalTemplate(fbuf, YAF_PROCESS_STATS_TID, err)) {
        return FALSE;
    }

    /* Set Export Template for Buffer to Options TMPL */
    if (!yfSetExportTemplate(fbuf, YAF_PROCESS_STATS_TID, err)) {
        return FALSE;
    }

    /* Append Record */
    if (!fBufAppend(fbuf, (uint8_t *)&rec, sizeof(rec), err)) {
        return FALSE;
    }

    /* emit buffer */
    if (!fBufEmit(fbuf, err)) {
        return FALSE;
    }

    /* Set Internal TID Back to Flow Record */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {
        return FALSE;
    }

    return TRUE;
}


/**
 * yfWriteTombstoneFlow
 *
 *
 */
gboolean
yfWriteTombstoneFlow(
    void    *yfContext,
    GError **err)
{
    yfTombstoneRecord_t rec;
    yfContext_t        *ctx = (yfContext_t *)yfContext;
    fBuf_t             *fbuf = ctx->fbuf;
    static uint32_t     certToolTombstoneId = 0;
    uint32_t            currentTime;
    yfTombstoneAccess_t *accessListPtr;

    if (!fbuf) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "Error Writing Stats Message: No fbuf [output] Available");
        return FALSE;
    }

    /* Set Internal Template for Buffer to Options TID */
    if (!fBufSetInternalTemplate(fbuf, YAF_TOMBSTONE_TID, err)) {
        return FALSE;
    }

    /* Set Export Template for Buffer to Options TMPL */
    if (!yfSetExportTemplate(fbuf, YAF_TOMBSTONE_TID, err)) {
        return FALSE;
    }

    memset(rec.paddingOctets, 0, sizeof(rec.paddingOctets));
    currentTime = (uint32_t)time(NULL);
    rec.certToolTombstoneId = certToolTombstoneId++;
    rec.certToolExporterConfiguredId = ctx->cfg->tombstone_configured_id;
    rec.exportingProcessId = getpid();
    rec.observationTimeSeconds = currentTime;
    rec.observationDomainId = ctx->cfg->odid;
    accessListPtr = (yfTombstoneAccess_t *)fbSubTemplateListInit(
        &(rec.accessList), 3,
        YAF_TOMBSTONE_ACCESS_TID,
        yaf_tmpl.tombstoneAccessTemplate, 1);

    accessListPtr->certToolId = 1;
    accessListPtr->observationTimeSeconds = currentTime;

    /* Append Record */
    if (!fBufAppend(fbuf, (uint8_t *)&rec, sizeof(rec), err)) {
        return FALSE;
    }

    /* emit buffer */
    if (!fBufEmit(fbuf, err)) {
        return FALSE;
    }

    g_message("Sent Tombstone record: observationDomain:%d, "
              "exporterId:%d:%d, certToolTombstoneId: %d",
              rec.observationDomainId, rec.certToolExporterConfiguredId,
              rec.exportingProcessId, rec.certToolTombstoneId);

    fbSubTemplateListClear(&(rec.accessList));

    /* Set Internal TID Back to Flow Record */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {
        return FALSE;
    }

    return TRUE;
}


/**
 * yfWriteFlow
 *
 *
 *
 */
gboolean
yfWriteFlow(
    void      *yfContext,
    yfFlow_t  *flow,
    GError   **err)
{
    yfIpfixFlow_t  rec;
    uint32_t       wtid;
    uint16_t       etid = 0;      /* extra templates */
    gboolean       ok;
    int32_t        temp = 0;
    int            loop, count;
    yfContext_t   *ctx = (yfContext_t *)yfContext;
    fBuf_t        *fbuf = ctx->fbuf;

    if (ctx->cfg->no_output) {
        return TRUE;
    }

    /* copy time */
    rec.flowStartMilliseconds = flow->stime;
    rec.flowEndMilliseconds = flow->etime;
    rec.reverseFlowDeltaMilliseconds = flow->rdtime;

    /* copy addresses */
    if (yaf_core_map_ipv6 && (flow->key.version == 4)) {
        memcpy(rec.sourceIPv6Address, yaf_ip6map_pfx,
               sizeof(yaf_ip6map_pfx));
        *(uint32_t *)(&(rec.sourceIPv6Address[sizeof(yaf_ip6map_pfx)])) =
            g_htonl(flow->key.addr.v4.sip);
        memcpy(rec.destinationIPv6Address, yaf_ip6map_pfx,
               sizeof(yaf_ip6map_pfx));
        *(uint32_t *)(&(rec.destinationIPv6Address[sizeof(yaf_ip6map_pfx)])) =
            g_htonl(flow->key.addr.v4.dip);
    } else if (flow->key.version == 4) {
        rec.sourceIPv4Address = flow->key.addr.v4.sip;
        rec.destinationIPv4Address = flow->key.addr.v4.dip;
    } else if (flow->key.version == 6) {
        memcpy(rec.sourceIPv6Address, flow->key.addr.v6.sip,
               sizeof(rec.sourceIPv6Address));
        memcpy(rec.destinationIPv6Address, flow->key.addr.v6.dip,
               sizeof(rec.destinationIPv6Address));
    } else {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                    "Illegal IP version %u", flow->key.version);
    }

    /* choose options for basic template */
    wtid = YAF_FLOW_BASE_TID;
    rec.vlanId = flow->val.vlan;
    /* right? */
    rec.reverseVlanId = flow->rval.vlan;

    /* copy key and counters */
    rec.sourceTransportPort = flow->key.sp;
    rec.destinationTransportPort = flow->key.dp;
    rec.flowAttributes = flow->val.attributes;
    rec.reverseFlowAttributes = flow->rval.attributes;
    rec.protocolIdentifier = flow->key.proto;
    rec.flowEndReason = flow->reason;

    if (ctx->cfg->deltaMode) {
        rec.octetDeltaCount = flow->val.oct;
        rec.reverseOctetDeltaCount = flow->rval.oct;
        rec.packetDeltaCount = flow->val.pkt;
        rec.reversePacketDeltaCount = flow->rval.pkt;
        wtid |= YTF_DELTA;
    } else {
        rec.octetTotalCount = flow->val.oct;
        rec.reverseOctetTotalCount = flow->rval.oct;
        rec.packetTotalCount = flow->val.pkt;
        rec.reversePacketTotalCount = flow->rval.pkt;
        wtid |= YTF_TOTAL;
    }

    rec.ingressInterface = ctx->cfg->ingressInt;
    rec.egressInterface = ctx->cfg->egressInt;

    /* Type Of Service */
    rec.ipClassOfService = flow->key.tos;
    rec.reverseIpClassOfService = flow->rtos;

#ifdef YAF_ENABLE_DAG_SEPARATE_INTERFACES
    rec.ingressInterface = flow->key.netIf;
    rec.egressInterface  = flow->key.netIf | 0x100;
#endif

#ifdef YAF_ENABLE_SEPARATE_INTERFACES
    rec.ingressInterface = flow->val.netIf;
    if (flow->rval.pkt) {
        rec.egressInterface = flow->rval.netIf;
    } else {
        rec.egressInterface = flow->val.netIf | 0x100;
    }
#endif /* ifdef YAF_ENABLE_SEPARATE_INTERFACES */

#ifdef YAF_ENABLE_APPLABEL
    rec.silkAppLabel = flow->appLabel;
#endif /* ifdef YAF_ENABLE_APPLABEL */

#ifdef YAF_ENABLE_NDPI
    rec.ndpi_master = flow->ndpi_master;
    rec.ndpi_sub = flow->ndpi_sub;
    wtid |= YTF_NDPI;
#endif

#ifdef YAF_MPLS
    if (ctx->cfg->mpls_mode) {
        /* since the mpls label isn't defined as an integer in fixbuf, it's
         * not endian-converted on transcode, so we fix that here */
        /*    temp = htonl(flow->mpls->mpls_label[0]) >> 8;*/
        memcpy(rec.mpls_label1, &(flow->mpls->mpls_label[0]), 3);
        /*temp = htonl(flow->mpls->mpls_label[1]) >> 8;*/
        memcpy(rec.mpls_label2, &(flow->mpls->mpls_label[1]), 3);
        /*temp = htonl(flow->mpls->mpls_label[2]) >> 8;*/
        memcpy(rec.mpls_label3, &(flow->mpls->mpls_label[2]), 3);

        wtid |= YTF_MPLS;
    }
#endif /* ifdef YAF_MPLS */

    if (flow->rval.pkt) {
        wtid |= YTF_BIF;
        etid = YTF_BIF;
    }

    if (rec.protocolIdentifier == YF_PROTO_TCP) {
        rec.tcpSequenceNumber = flow->val.isn;
        rec.initialTCPFlags = flow->val.iflags;
        rec.unionTCPFlags = flow->val.uflags;
        if (ctx->cfg->silkmode || etid) {
            rec.reverseTcpSequenceNumber = flow->rval.isn;
            rec.reverseInitialTCPFlags = flow->rval.iflags;
            rec.reverseUnionTCPFlags = flow->rval.uflags;
        }
        wtid |= YTF_TCP;
    }

    if (flow->mptcp.token) {
        rec.mptcpInitialDataSequenceNumber = flow->mptcp.idsn;
        rec.mptcpReceiverToken = flow->mptcp.token;
        rec.mptcpMaximumSegmentSize = flow->mptcp.mss;
        rec.mptcpAddressId = flow->mptcp.addrid;
        rec.mptcpFlags = flow->mptcp.flags;
        wtid |= YTF_MPTCP;
    }

    if (flow->val.oct < YAF_RLEMAX && flow->rval.oct < YAF_RLEMAX &&
        flow->val.pkt < YAF_RLEMAX && flow->rval.pkt < YAF_RLEMAX)
    {
        wtid |= YTF_RLE;
    } else {
        wtid |= YTF_FLE;
    }

    if (yaf_core_map_ipv6 || (flow->key.version == 6)) {
        wtid |= YTF_IP6;
    } else {
        wtid |= YTF_IP4;
    }

    if (rec.ingressInterface || rec.egressInterface) {
        wtid |= YTF_DAGIF;
    }

#if defined(YAF_ENABLE_DAG_SEPARATE_INTERFACES) || defined(YAF_ENABLE_SEPARATE_INTERFACES)
    if (ctx->cfg->exportInterface) {
        wtid |= YTF_DAGIF;
    }
#endif

    if (ctx->cfg->macmode) {
        memcpy(rec.sourceMacAddress, flow->sourceMacAddr,
               ETHERNET_MAC_ADDR_LENGTH);
        memcpy(rec.destinationMacAddress, flow->destinationMacAddr,
               ETHERNET_MAC_ADDR_LENGTH);
        wtid |= YTF_MAC;
    }

    if (ctx->cfg->statsmode && flow->val.stats &&
        (flow->val.stats->payoct || flow->rval.stats))
    {
        uint32_t pktavg = 0;
        yfFlowStats_t *fwd_stats = flow->val.stats;
        yfFlowStats_t *rev_stats = flow->rval.stats;

        rec.firstEightNonEmptyPacketDirections = flow->pktdir;
        rec.tcpUrgTotalCount = fwd_stats->tcpurgct;
        rec.smallPacketCount = fwd_stats->smallpktct;
        rec.firstNonEmptyPacketSize = (uint16_t)fwd_stats->firstpktsize;
        rec.nonEmptyPacketCount = fwd_stats->nonemptypktct;
        rec.dataByteCount = fwd_stats->payoct;
        rec.maxPacketSize = (uint16_t)fwd_stats->maxpktsize;
        rec.largePacketCount = fwd_stats->largepktct;
        if (0 == fwd_stats->nonemptypktct) {
            rec.standardDeviationPayloadLength = 0;
        } else {
            count = MIN(fwd_stats->nonemptypktct, 10);
            pktavg = fwd_stats->payoct / fwd_stats->nonemptypktct;
            /* sum the squares of the deviations */
            temp = 0;
            for (loop = 0; loop < count; loop++) {
                int32_t diff =
                    (int32_t)fwd_stats->pktsize[loop] - (int32_t)pktavg;
                temp += diff * diff;
            }
            rec.standardDeviationPayloadLength = sqrt(temp / count);
        }
        if (flow->val.pkt <= 1) {
            rec.averageInterarrivalTime = 0;
            rec.standardDeviationInterarrivalTime = 0;
        } else {
            uint64_t time_temp = 0;
            int64_t  diff;
            rec.averageInterarrivalTime =
                fwd_stats->aitime / (flow->val.pkt - 1);
            count = MIN(flow->val.pkt, 11) - 1;
            for (loop = 0; loop < count; loop++) {
                diff = ((int64_t)fwd_stats->iaarray[loop] -
                        (int64_t)rec.averageInterarrivalTime);
                time_temp += diff * diff;
            }
            rec.standardDeviationInterarrivalTime = sqrt(time_temp / count);
        }

        if (etid) {
            rec.reverseTcpUrgTotalCount = rev_stats->tcpurgct;
            rec.reverseSmallPacketCount = rev_stats->smallpktct;
            rec.reverseFirstNonEmptyPacketSize =
                (uint16_t)rev_stats->firstpktsize;
            rec.reverseNonEmptyPacketCount = rev_stats->nonemptypktct;
            rec.reverseDataByteCount = rev_stats->payoct;
            rec.reverseMaxPacketSize = (uint16_t)rev_stats->maxpktsize;
            rec.reverseLargePacketCount = rev_stats->largepktct;
            if (0 == rev_stats->nonemptypktct) {
                rec.reverseStandardDeviationPayloadLength = 0;
            } else {
                count = MIN(rev_stats->nonemptypktct, 10);
                pktavg = rev_stats->payoct / rev_stats->nonemptypktct;
                temp = 0;
                for (loop = 0; loop < count; loop++) {
                    int32_t diff =
                        (int32_t)rev_stats->pktsize[loop] - (int32_t)pktavg;
                    temp += diff * diff;
                }
                rec.reverseStandardDeviationPayloadLength = sqrt(temp / count);
            }
            if (flow->rval.pkt <= 1) {
                rec.reverseAverageInterarrivalTime = 0;
                rec.reverseStandardDeviationInterarrivalTime = 0;
            } else {
                uint64_t time_temp = 0;
                int64_t  diff;
                rec.reverseAverageInterarrivalTime =
                    rev_stats->aitime / (flow->rval.pkt - 1);
                count = MIN(flow->rval.pkt, 11) - 1;
                for (loop = 0; loop < count; loop++) {
                    diff = ((int64_t)rev_stats->iaarray[loop] -
                            (int64_t)rec.reverseAverageInterarrivalTime);
                    time_temp += diff * diff;
                }
                rec.reverseStandardDeviationInterarrivalTime =
                    sqrt(time_temp / count);
            }
        }
        wtid |= YTF_STATS;
    }

#ifdef YAF_ENABLE_PAYLOAD
    if (0 == yaf_core_export_payload) {
        /* --export-payload switch not given */
        rec.payload.len = 0;
        rec.reversePayload.len = 0;
    } else {
        /* point to payload */
        wtid |= YTF_PAYLOAD;
        if (0 == flow->val.paylen && 0 == flow->rval.paylen) {
            /* no payload to point to */
            rec.payload.len = 0;
            rec.reversePayload.len = 0;
#ifdef YAF_ENABLE_APPLABEL
        } else if (yaf_core_payload_applabels
                   && !findInApplabelArray(flow->appLabel))
        {
            /* per-appLabel requested but not for this appLabel */
            rec.payload.len = 0;
            rec.reversePayload.len = 0;
#endif /* YAF_ENABLE_APPLABEL */
        } else {
            rec.payload.len = MIN(flow->val.paylen, yaf_core_export_payload);
            rec.payload.buf = flow->val.payload;

            if (etid) {
                rec.reversePayload.len = MIN(flow->rval.paylen,
                                             yaf_core_export_payload);
                rec.reversePayload.buf = flow->rval.payload;
            }
        }
    }
#endif /* ifdef YAF_ENABLE_PAYLOAD */
    rec.yafLayer2SegmentId = flow->key.layer2Id;

#ifdef YAF_ENABLE_ENTROPY
    if (flow->val.entropy || flow->rval.entropy) {
        rec.entropy = flow->val.entropy;
        if (etid) {
            rec.reverseEntropy = flow->rval.entropy;
        }
        wtid |= YTF_ENTROPY;
    }
#endif

#ifdef YAF_ENABLE_P0F
    if (flow->val.osname || flow->val.osver ||
        flow->rval.osname || flow->rval.osver ||
        flow->val.osFingerprint || flow->rval.osFingerprint)
    {
        if (NULL != flow->val.osname) {
            rec.osName.buf  = (uint8_t *)flow->val.osname;
            rec.osName.len  = strlen(flow->val.osname);
        } else {
            rec.osName.len = 0;
        }

        if (NULL != flow->val.osver) {
            rec.osVersion.buf = (uint8_t *)flow->val.osver;
            rec.osVersion.len = strlen(flow->val.osver);
        } else {
            rec.osVersion.len = 0;
        }

        if (NULL != flow->val.osFingerprint) {
            rec.osFingerprint.buf = (uint8_t *)flow->val.osFingerprint;
            rec.osFingerprint.len = strlen(flow->val.osFingerprint);
        } else {
            rec.osFingerprint.len = 0;
        }

        if (etid) {
            if (NULL != flow->rval.osname) {
                rec.reverseOsName.buf = (uint8_t *)flow->rval.osname;
                rec.reverseOsName.len = strlen(flow->rval.osname);
            } else {
                rec.reverseOsName.len = 0;
            }

            if (NULL != flow->rval.osver) {
                rec.reverseOsVersion.buf = (uint8_t *)flow->rval.osver;
                rec.reverseOsVersion.len = strlen(flow->rval.osver);
            } else {
                rec.reverseOsVersion.len = 0;
            }
            if (NULL != flow->rval.osFingerprint) {
                rec.reverseOsFingerprint.buf = (uint8_t *)
                    flow->rval.osFingerprint;
                rec.reverseOsFingerprint.len =
                    strlen(flow->rval.osFingerprint);
            } else {
                rec.reverseOsFingerprint.len = 0;
            }
        }
    } else {
        rec.osName.len = 0;
        rec.osVersion.len = 0;
        rec.osFingerprint.len = 0;
        rec.reverseOsName.len = 0;
        rec.reverseOsVersion.len = 0;
        rec.reverseOsFingerprint.len = 0;
    }
    if (ctx->cfg->p0fPrinterMode) {
        wtid |= YTF_P0F;
    }
#endif /* ifdef YAF_ENABLE_P0F */

#ifdef YAF_ENABLE_FPEXPORT
    if (flow->val.firstPacket || flow->rval.firstPacket ||
        flow->val.secondPacket)
    {
        rec.firstPacketBanner.buf = flow->val.firstPacket;
        rec.firstPacketBanner.len = flow->val.firstPacketLen;
        rec.secondPacketBanner.buf = flow->val.secondPacket;
        rec.secondPacketBanner.len = flow->val.secondPacketLen;
        if (etid) {
            rec.reverseFirstPacketBanner.buf = flow->rval.firstPacket;
            rec.reverseFirstPacketBanner.len = flow->rval.firstPacketLen;
        }
    } else {
        rec.firstPacketBanner.len = 0;
        rec.secondPacketBanner.len = 0;
        rec.reverseFirstPacketBanner.len = 0;
    }
    if (ctx->cfg->fpExportMode) {
        wtid |= YTF_FPEXPORT;
    }
#endif /* ifdef YAF_ENABLE_FPEXPORT */

    if (ctx->cfg->layer2IdExportMode) {
        wtid |= YTF_VNI;
    }

#ifdef YAF_ENABLE_DPI
    if (NULL != flow->dpictx) {
        wtid |= YTF_DPI;
    }
#endif

#ifdef YAF_ENABLE_HOOKS
    wtid |= YTF_HOOK;
#endif

    if (!yfSetExportTemplate(fbuf, wtid, err)) {
        return FALSE;
    }

#ifdef YAF_ENABLE_DPI
    if (NULL != flow->dpictx) {
        if (FALSE == ydWriteDPIList(&(rec.yafDPIList), flow, err)) {
            return FALSE;
        }
    }
#endif

#ifdef YAF_ENABLE_HOOKS
    /* Initialize SubTemplateMultiList with number of templates we are to add*/
    fbSubTemplateMultiListInit(&(rec.subTemplateMultiList), 3,
                               yfHookGetTemplateCount(flow));
    /* write hook record - only add if there are some available in list*/
    if (!yfHookFlowWrite(&(rec.subTemplateMultiList), NULL, flow, err)) {
        return FALSE;
    }
#endif

    /* IF UDP - Check to see if we need to re-export templates */
    /* We do not advise in using UDP (nicer than saying you're stupid) */
    if ((ctx->cfg->connspec.transport == FB_UDP) ||
        (ctx->cfg->connspec.transport == FB_DTLS_UDP))
    {
        /* 3 is the factor from RFC 5101 as a recommendation of how often
         * between timeouts to resend */
        if ((flow->etime > ctx->lastUdpTempTime) &&
            ((flow->etime - ctx->lastUdpTempTime) >
             ((ctx->cfg->yaf_udp_template_timeout) / 3)))
        {
            /* resend templates */
            ok = fbSessionExportTemplates(fBufGetSession(ctx->fbuf), err);
            ctx->lastUdpTempTime = flow->etime;
            if (!ok) {
                g_warning("Failed to renew UDP Templates: %s",
                          (*err)->message);
                g_clear_error(err);
            }
        }
        if (!(ctx->cfg->livetype)) {
            /* slow down UDP export if reading from a file */
            usleep(2);
        }
    }

    /* Now append the record to the buffer */
    if (!fBufAppend(fbuf, (uint8_t *)&rec, sizeof(rec), err)) {
        return FALSE;
    }

#ifdef YAF_ENABLE_HOOKS
    /* clear basic lists */
    yfHookFreeLists(flow);
    fbSubTemplateMultiListClear(&(rec.subTemplateMultiList));
#endif

#ifdef YAF_ENABLE_DPI
    if (NULL != flow->dpictx) {
        ydFreeDPILists(&(rec.yafDPIList), flow);
    }
#endif
    /* Clear MultiList */

    return TRUE;
}


/**
 * yfWriterClose
 *
 *
 *
 */
gboolean
yfWriterClose(
    fBuf_t    *fbuf,
    gboolean   flush,
    GError   **err)
{
    gboolean ok = TRUE;

    if (flush) {
        ok = fBufEmit(fbuf, err);
    }

    fBufFree(fbuf);

    return ok;
}


/**
 * yfTemplateCallback
 *
 *
 */
static void
yfTemplateCallback(
    fbSession_t           *session,
    uint16_t               tid,
    fbTemplate_t          *tmpl,
    void                  *app_ctx,
    void                 **tmpl_ctx,
    fbTemplateCtxFree_fn  *fn)
{
    if (YAF_FLOW_BASE_TID == (tid & 0xF000)) {
        fbSessionAddTemplatePair(session, tid, tid);
    }

    fbSessionAddTemplatePair(session, tid, 0);
}


/**
 * yfInitCollectorSession
 *
 *
 *
 */
static fbSession_t *
yfInitCollectorSession(
    GError **err)
{
    fbInfoModel_t *model = yfInfoModel();
    fbTemplate_t  *tmpl = NULL;
    fbSession_t   *session = NULL;

    /* Allocate the session */
    session = fbSessionAlloc(model);

    /* Add the full record template */
    tmpl = fbTemplateAlloc(model);

    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_spec, YTF_ALL, err)) {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_FLOW_FULL_TID, tmpl, NULL, err)) {
        return NULL;
    }

    /* Add the extended record template */
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, yaf_flow_spec, YTF_ALL, err)) {
        return NULL;
    }
    if (!fbTemplateAppendSpecArray(tmpl, yaf_extime_spec, YTF_ALL, err)) {
        return NULL;
    }
    if (!fbSessionAddTemplate(session, TRUE, YAF_FLOW_EXT_TID, tmpl, NULL, err)) {
        return NULL;
    }

    /** Add the template callback so we don't try to decode DPI */
    fbSessionAddNewTemplateCallback(session, yfTemplateCallback, NULL);

    return session;
}


/**
 * yfReaderForFP
 *
 *
 *
 */
fBuf_t *
yfReaderForFP(
    fBuf_t  *fbuf,
    FILE    *fp,
    GError **err)
{
    fbSession_t   *session;
    fbCollector_t *collector;

    /* Allocate a collector for the file */
    collector = fbCollectorAllocFP(NULL, fp);

    /* Allocate a buffer, or reset the collector */
    if (fbuf) {
        fBufSetCollector(fbuf, collector);
    } else {
        if (!(session = yfInitCollectorSession(err))) {goto err;}
        fbuf = fBufAllocForCollection(session, collector);
    }

    /* FIXME do a preread? */

    return fbuf;

  err:
    /* free buffer if necessary */
    if (fbuf) {fBufFree(fbuf);}
    return NULL;
}


/**
 * yfListenerForSpec
 *
 *
 *
 */
fbListener_t *
yfListenerForSpec(
    fbConnSpec_t          *spec,
    fbListenerAppInit_fn   appinit,
    fbListenerAppFree_fn   appfree,
    GError               **err)
{
    fbSession_t *session;

    if (!(session = yfInitCollectorSession(err))) {return NULL;}

    return fbListenerAlloc(spec, session, appinit, appfree, err);
}


/**
 * yfReadFlow
 *
 * read an IPFIX record in, with respect to fields YAF cares about
 *
 */
gboolean
yfReadFlow(
    fBuf_t    *fbuf,
    yfFlow_t  *flow,
    GError   **err)
{
    yfIpfixFlow_t    rec;
    size_t           len;
    fbTemplate_t    *next_tmpl = NULL;

    len = sizeof(yfIpfixFlow_t);

    /* Check if Options Template - if so - ignore */
    next_tmpl = fBufNextCollectionTemplate(fbuf, NULL, err);
    if (next_tmpl) {
        if (fbTemplateGetOptionsScope(next_tmpl)) {
            /* Stats Msg - Don't actually Decode */
            if (!fBufNext(fbuf, (uint8_t *)&rec, &len, err)) {
                return FALSE;
            }
            return TRUE;
        }
    } else {
        return FALSE;
    }

    /* read next YAF record */
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_FULL_TID, err)) {
        return FALSE;
    }
    if (!fBufNext(fbuf, (uint8_t *)&rec, &len, err)) {
        return FALSE;
    }

    /* copy time */
    flow->stime = rec.flowStartMilliseconds;
    flow->etime = rec.flowEndMilliseconds;
    flow->rdtime = rec.reverseFlowDeltaMilliseconds;
    /* copy addresses */
    if (rec.sourceIPv4Address || rec.destinationIPv4Address) {
        flow->key.version = 4;
        flow->key.addr.v4.sip = rec.sourceIPv4Address;
        flow->key.addr.v4.dip = rec.destinationIPv4Address;
    } else {
        flow->key.version = 6;
        memcpy(flow->key.addr.v6.sip, rec.sourceIPv6Address,
               sizeof(flow->key.addr.v6.sip));
        memcpy(flow->key.addr.v6.dip, rec.destinationIPv6Address,
               sizeof(flow->key.addr.v6.dip));
    }

    /* copy key and counters */
    flow->key.sp = rec.sourceTransportPort;
    flow->key.dp = rec.destinationTransportPort;
    flow->key.proto = rec.protocolIdentifier;
    flow->val.oct = rec.octetTotalCount;
    flow->val.pkt = rec.packetTotalCount;
    if (flow->val.oct == 0 && flow->val.pkt == 0) {
        flow->val.oct = rec.octetDeltaCount;
        flow->val.pkt = rec.packetDeltaCount;
    }
    flow->key.vlanId = rec.vlanId;
    flow->val.vlan = rec.vlanId;
    flow->rval.vlan = rec.reverseVlanId;
    flow->rval.oct = rec.reverseOctetTotalCount;
    flow->rval.pkt = rec.reversePacketTotalCount;
    flow->reason = rec.flowEndReason;

#ifdef YAF_ENABLE_APPLABEL
    flow->appLabel = rec.silkAppLabel;
#endif

    flow->val.isn = rec.tcpSequenceNumber;
    flow->val.iflags = rec.initialTCPFlags;
    flow->val.uflags = rec.unionTCPFlags;
    flow->rval.isn = rec.reverseTcpSequenceNumber;
    flow->rval.iflags = rec.reverseInitialTCPFlags;
    flow->rval.uflags = rec.reverseUnionTCPFlags;
    flow->key.layer2Id = rec.yafLayer2SegmentId;

#ifdef YAF_ENABLE_ENTROPY
    flow->val.entropy = rec.entropy;
    flow->rval.entropy = rec.reverseEntropy;
#endif /* ifdef YAF_ENABLE_ENTROPY */

    memcpy(flow->sourceMacAddr, rec.sourceMacAddress,
           ETHERNET_MAC_ADDR_LENGTH);
    memcpy(flow->destinationMacAddr, rec.destinationMacAddress,
           ETHERNET_MAC_ADDR_LENGTH);

#ifdef YAF_ENABLE_PAYLOAD
    yfPayloadCopyIn(&rec.payload, &flow->val);
    yfPayloadCopyIn(&rec.reversePayload, &flow->rval);
#endif /* ifdef YAF_ENABLE_PAYLOAD */

#ifdef YAF_ENABLE_HOOKS
    fbSubTemplateMultiListClear(&(rec.subTemplateMultiList));
#endif /* ifdef YAF_ENABLE_HOOKS */

    return TRUE;
}


/**
 * yfNTPDecode
 *
 * Decodes a 64-bit NTP time variable (in native byte order) and returns it in
 * terms of UNIX epoch milliseconds
 *
 *
 */
static uint64_t
yfNTPDecode(
    uint64_t   ntp)
{
    /* The number of seconds between the NTP epoch (Jan 1, 1900) and the UNIX
     * epoch (Jan 1, 1970).  Seventy 365-day years plus 17 leap days, at 86400
     * sec/day: ((70 * 365 + 17) * 86400) */
    const uint64_t NTP_EPOCH_TO_UNIX_EPOCH = 0x83AA7E80ULL;
    /* NTP rollover = 1 << 32 */
    const uint64_t NTP_ROLLOVER = 0x100000000ULL;
    /* Bit to check to determine whether to round up, 1 << 31 */
    const uint64_t ONE_SHIFT_31 = 0x80000000ULL;
    /* Bit to check to determine NTP Era, 1 << 63 */
    const uint64_t ONE_SHIFT_63 = 0x8000000000000000ULL;
    /* milliseconds */
    uint64_t ms;

    /* Mask the lower 32 bits of `ntp` to get the fractional second part.
     * Divide by 2^32 to get a floating point number that is a fraction of a
     * second, and multiply by 1000 to get milliseconds, but do those in
     * reverse order and use shift for the division.  Before the shift, round
     * up if needed by checking the highest bit that is about to get chopped
     * off. */
    ms = (ntp & 0xffffffffULL) * 1000;
    ms = (ms + ((ms & ONE_SHIFT_31) << 1)) >> 32;

    /* Right shift `ntp` by 32 to get the whole seconds since 1900.  Subtract
     * the difference between the epochs to get a UNIX time, then multiply by
     * 1000 to get milliseconds.
     *
     * Use the highest bit of ntp to determine (assume) the NTP Era and add
     * NTP_ROLLOVER if Era 1; this is valid from 1968 to 2104. */
    if (ntp & ONE_SHIFT_63) {
        /* Assume NTP Era 0 */
        /* valid for 1968-01-20 03:14:08Z to 2036-02-07 06:28:15Z */
        ms += ((ntp >> 32) - NTP_EPOCH_TO_UNIX_EPOCH) * 1000;
    } else {
        /* Assume NTP Era 1 */
        /* valid for 2036-02-07 06:28:16Z to 2104-02-26 09:42:23Z */
        ms += ((ntp >> 32) + NTP_ROLLOVER - NTP_EPOCH_TO_UNIX_EPOCH) * 1000;
    }

    return ms;
}


/**
 * yfReadFlowExtended
 *
 * read an IPFIX flow record in (with respect to fields YAF cares about)
 * using YAF's extended precision time recording
 *
 */
gboolean
yfReadFlowExtended(
    fBuf_t    *fbuf,
    yfFlow_t  *flow,
    GError   **err)
{
    yfIpfixExtFlow_t rec;
    fbTemplate_t    *next_tmpl = NULL;
    size_t           len;

    /* read next YAF record; retrying on missing template or EOF. */
    len = sizeof(yfIpfixExtFlow_t);
    if (!fBufSetInternalTemplate(fbuf, YAF_FLOW_EXT_TID, err)) {
        return FALSE;
    }

    while (1) {
        /* Check if Options Template - if so - ignore */
        next_tmpl = fBufNextCollectionTemplate(fbuf, NULL, err);
        if (next_tmpl) {
            if (fbTemplateGetOptionsScope(next_tmpl)) {
                if (!(fBufNext(fbuf, (uint8_t *)&rec, &len, err))) {
                    return FALSE;
                }
                continue;
            }
        } else {
            return FALSE;
        }
        if (fBufNext(fbuf, (uint8_t *)&rec, &len, err)) {
            break;
        } else {
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
                /* try again on missing template */
                g_debug("skipping IPFIX data set: %s", (*err)->message);
                g_clear_error(err);
                continue;
            } else {
                /* real, actual error */
                return FALSE;
            }
        }
    }

    /* Run the Gauntlet of Time. */
    if (rec.f.flowStartMilliseconds) {
        flow->stime = rec.f.flowStartMilliseconds;
        if (rec.f.flowEndMilliseconds >= rec.f.flowStartMilliseconds) {
            flow->etime = rec.f.flowEndMilliseconds;
        } else {
            flow->etime = flow->stime + rec.flowDurationMilliseconds;
        }
    } else if (rec.flowStartMicroseconds) {
        /* Decode NTP-format microseconds */
        flow->stime = yfNTPDecode(rec.flowStartMicroseconds);
        if (rec.flowEndMicroseconds >= rec.flowStartMicroseconds) {
            flow->etime = yfNTPDecode(rec.flowEndMicroseconds);
        } else {
            flow->etime = flow->stime + (rec.flowDurationMicroseconds / 1000);
        }
    } else if (rec.flowStartSeconds) {
        /* Seconds? Well. Okay... */
        flow->stime = rec.flowStartSeconds * 1000;
        flow->etime = rec.flowEndSeconds * 1000;
    } else if (rec.flowStartDeltaMicroseconds) {
        /* Handle delta microseconds. */
        flow->stime = fBufGetExportTime(fbuf) * 1000 -
            rec.flowStartDeltaMicroseconds / 1000;
        if (rec.flowEndDeltaMicroseconds &&
            rec.flowEndDeltaMicroseconds <= rec.flowStartDeltaMicroseconds)
        {
            flow->etime = fBufGetExportTime(fbuf) * 1000 -
                rec.flowEndDeltaMicroseconds / 1000;
        } else {
            flow->etime = flow->stime + (rec.flowDurationMicroseconds / 1000);
        }
    } else {
        /* Out of time. Use current timestamp, zero duration */
        struct timeval ct;
        gettimeofday(&ct, NULL);
        flow->stime = ((uint64_t)ct.tv_sec * 1000) +
            ((uint64_t)ct.tv_usec / 1000);
        flow->etime = flow->stime;
    }

    /* copy private time field - reverse delta */
    flow->rdtime = rec.f.reverseFlowDeltaMilliseconds;

    /* copy addresses */
    if (rec.f.sourceIPv4Address || rec.f.destinationIPv4Address) {
        flow->key.version = 4;
        flow->key.addr.v4.sip = rec.f.sourceIPv4Address;
        flow->key.addr.v4.dip = rec.f.destinationIPv4Address;
    } else {
        flow->key.version = 6;
        memcpy(flow->key.addr.v6.sip, rec.f.sourceIPv6Address,
               sizeof(flow->key.addr.v6.sip));
        memcpy(flow->key.addr.v6.dip, rec.f.destinationIPv6Address,
               sizeof(flow->key.addr.v6.dip));
    }

    /* copy key and counters */
    flow->key.sp = rec.f.sourceTransportPort;
    flow->key.dp = rec.f.destinationTransportPort;
    flow->key.proto = rec.f.protocolIdentifier;
    flow->val.oct = rec.f.octetTotalCount;
    flow->val.pkt = rec.f.packetTotalCount;
    flow->rval.oct = rec.f.reverseOctetTotalCount;
    flow->rval.pkt = rec.f.reversePacketTotalCount;
    flow->key.vlanId = rec.f.vlanId;
    flow->val.vlan = rec.f.vlanId;
    flow->rval.vlan = rec.f.reverseVlanId;
    flow->reason = rec.f.flowEndReason;
    /* Handle delta counters */
    if (!(flow->val.oct)) {
        flow->val.oct = rec.f.octetDeltaCount;
        flow->rval.oct = rec.f.reverseOctetDeltaCount;
    }
    if (!(flow->val.pkt)) {
        flow->val.pkt = rec.f.packetDeltaCount;
        flow->rval.pkt = rec.f.reversePacketDeltaCount;
    }

#ifdef YAF_ENABLE_APPLABEL
    flow->appLabel = rec.f.silkAppLabel;
#endif
#ifdef YAF_ENABLE_NDPI
    flow->ndpi_master = rec.f.ndpi_master;
    flow->ndpi_sub = rec.f.ndpi_sub;
#endif

#ifdef YAF_ENABLE_ENTROPY
    flow->val.entropy = 0;
    flow->rval.entropy = 0;
#endif

    flow->val.isn = rec.f.tcpSequenceNumber;
    flow->val.iflags = rec.f.initialTCPFlags;
    flow->val.uflags = rec.f.unionTCPFlags;
    flow->rval.isn = rec.f.reverseTcpSequenceNumber;
    flow->rval.iflags = rec.f.reverseInitialTCPFlags;
    flow->rval.uflags = rec.f.reverseUnionTCPFlags;

#ifdef YAF_ENABLE_ENTROPY
    flow->val.entropy = rec.f.entropy;
    flow->rval.entropy = rec.f.reverseEntropy;
#endif /* ifdef YAF_ENABLE_ENTROPY */

    memcpy(flow->sourceMacAddr, rec.f.sourceMacAddress,
           ETHERNET_MAC_ADDR_LENGTH);
    memcpy(flow->destinationMacAddr, rec.f.destinationMacAddress,
           ETHERNET_MAC_ADDR_LENGTH);

#ifdef YAF_ENABLE_PAYLOAD
    yfPayloadCopyIn(&rec.f.payload, &flow->val);
    yfPayloadCopyIn(&rec.f.reversePayload, &flow->rval);
#endif /* ifdef YAF_ENABLE_PAYLOAD */

#ifdef YAF_ENABLE_HOOKS
    fbSubTemplateMultiListClear(&(rec.f.subTemplateMultiList));
#endif /* ifdef YAF_ENABLE_HOOKS */

    return TRUE;
}


/**
 * yfPrintFlags
 *
 *
 *
 */
static void
yfPrintFlags(
    GString  *str,
    uint8_t   flags)
{
    if (flags & YF_TF_ECE) {g_string_append_c(str, 'E');}
    if (flags & YF_TF_CWR) {g_string_append_c(str, 'C');}
    if (flags & YF_TF_URG) {g_string_append_c(str, 'U');}
    if (flags & YF_TF_ACK) {g_string_append_c(str, 'A');}
    if (flags & YF_TF_PSH) {g_string_append_c(str, 'P');}
    if (flags & YF_TF_RST) {g_string_append_c(str, 'R');}
    if (flags & YF_TF_SYN) {g_string_append_c(str, 'S');}
    if (flags & YF_TF_FIN) {g_string_append_c(str, 'F');}
    if (!flags) {g_string_append_c(str, '0');}
}


/**
 * yfPrintString
 *
 *
 *
 */
void
yfPrintString(
    GString   *rstr,
    yfFlow_t  *flow)
{
    char sabuf[AIR_IP6ADDR_BUF_MINSZ],
         dabuf[AIR_IP6ADDR_BUF_MINSZ];

    if (!rstr) {
        return;
    }

    /* print start as date and time */
    air_mstime_g_string_append(rstr, flow->stime, AIR_TIME_ISO8601);

    /* print end as time and duration if not zero-duration */
    if (flow->stime != flow->etime) {
        g_string_append_printf(rstr, " - ");
        air_mstime_g_string_append(rstr, flow->etime, AIR_TIME_ISO8601_HMS);
        g_string_append_printf(rstr, " (%.3f sec)",
                               (flow->etime - flow->stime) / 1000.0);
    }

    /* print protocol and addresses */
    if (flow->key.version == 4) {
        air_ipaddr_buf_print(sabuf, flow->key.addr.v4.sip);
        air_ipaddr_buf_print(dabuf, flow->key.addr.v4.dip);
    } else if (flow->key.version == 6) {
        air_ip6addr_buf_print(sabuf, flow->key.addr.v6.sip);
        air_ip6addr_buf_print(dabuf, flow->key.addr.v6.dip);
    } else {
        sabuf[0] = (char)0;
        dabuf[0] = (char)0;
    }

    switch (flow->key.proto) {
      case YF_PROTO_TCP:
        if (flow->rval.oct) {
            g_string_append_printf(rstr, " tcp %s:%u => %s:%u %08x:%08x ",
                                   sabuf, flow->key.sp, dabuf, flow->key.dp,
                                   flow->val.isn, flow->rval.isn);
        } else {
            g_string_append_printf(rstr, " tcp %s:%u => %s:%u %08x ",
                                   sabuf, flow->key.sp, dabuf, flow->key.dp,
                                   flow->val.isn);
        }

        yfPrintFlags(rstr, flow->val.iflags);
        g_string_append_c(rstr, '/');
        yfPrintFlags(rstr, flow->val.uflags);
        if (flow->rval.oct) {
            g_string_append_c(rstr, ':');
            yfPrintFlags(rstr, flow->rval.iflags);
            g_string_append_c(rstr, '/');
            yfPrintFlags(rstr, flow->rval.uflags);
        }
        break;
      case YF_PROTO_UDP:
        g_string_append_printf(rstr, " udp %s:%u => %s:%u",
                               sabuf, flow->key.sp, dabuf, flow->key.dp);
        break;
      case YF_PROTO_ICMP:
        g_string_append_printf(rstr, " icmp [%u:%u] %s => %s",
                               (flow->key.dp >> 8), (flow->key.dp & 0xFF),
                               sabuf, dabuf);
        break;
      case YF_PROTO_ICMP6:
        g_string_append_printf(rstr, " icmp6 [%u:%u] %s => %s",
                               (flow->key.dp >> 8), (flow->key.dp & 0xFF),
                               sabuf, dabuf);
        break;
      default:
        g_string_append_printf(rstr, " ip %u %s => %s",
                               flow->key.proto, sabuf, dabuf);
        break;
    }

    /* print vlan tags */
    if (flow->key.vlanId) {
        if (flow->rval.oct) {
            g_string_append_printf(rstr, " vlan %03hx:%03hx",
                                   flow->val.vlan, flow->rval.vlan);
        } else {
            g_string_append_printf(rstr, " vlan %03hx",
                                   flow->val.vlan);
        }
    }

    /* print flow counters and round-trip time */
    if (flow->rval.pkt) {
        g_string_append_printf(rstr, " (%llu/%llu <-> %llu/%llu) rtt %u ms",
                               (long long unsigned int)flow->val.pkt,
                               (long long unsigned int)flow->val.oct,
                               (long long unsigned int)flow->rval.pkt,
                               (long long unsigned int)flow->rval.oct,
                               flow->rdtime);
    } else {
        g_string_append_printf(rstr, " (%llu/%llu ->)",
                               (long long unsigned int)flow->val.pkt,
                               (long long unsigned int)flow->val.oct);
    }

    /* end reason flags */
    if ((flow->reason & YAF_END_MASK) == YAF_END_IDLE) {
        g_string_append(rstr, " idle");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_ACTIVE) {
        g_string_append(rstr, " active");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_FORCED) {
        g_string_append(rstr, " eof");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_RESOURCE) {
        g_string_append(rstr, " rsrc");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_UDPFORCE) {
        g_string_append(rstr, " force");
    }

    /* if app label is enabled, print the label */
#ifdef YAF_ENABLE_APPLABEL
    if (0 != flow->appLabel) {
        g_string_append_printf(rstr, " applabel: %u", flow->appLabel);
    }
#endif
#ifdef YAF_ENABLE_NDPI
    if (0 != flow->ndpi_master) {
        if (flow->ndpi_sub) {
            g_string_append_printf(rstr, " ndpi: %u[%u]", flow->ndpi_master,
                                   flow->ndpi_sub);
        } else {
            g_string_append_printf(rstr, " ndpi: %u", flow->ndpi_master);
        }
    }
#endif /* ifdef YAF_ENABLE_NDPI */

    /* if entropy is enabled, print the entropy values */
#ifdef YAF_ENABLE_ENTROPY
    if (0 != flow->val.entropy || 0 != flow->rval.entropy) {
        g_string_append_printf(rstr, " entropy: %u rev entropy: %u",
                               flow->val.entropy, flow->rval.entropy);
    }
#endif /* ifdef YAF_ENABLE_ENTROPY */

    /* finish line */
    g_string_append(rstr, "\n");

    /* print payload if necessary */
#ifdef YAF_ENABLE_PAYLOAD
    if (flow->val.payload) {
        air_hexdump_g_string_append(rstr, "  -> ",
                                    flow->val.payload, flow->val.paylen);
        g_free(flow->val.payload);
        flow->val.payload = NULL;
        flow->val.paylen = 0;
    }
    if (flow->rval.payload) {
        air_hexdump_g_string_append(rstr, " <-  ",
                                    flow->rval.payload, flow->rval.paylen);
        g_free(flow->rval.payload);
        flow->rval.payload = NULL;
        flow->rval.paylen = 0;
    }
#endif /* ifdef YAF_ENABLE_PAYLOAD */
}


/**
 * yfPrintDelimitedString
 *
 *
 *
 */
void
yfPrintDelimitedString(
    GString   *rstr,
    yfFlow_t  *flow,
    gboolean   yaft_mac)
{
    char           sabuf[AIR_IP6ADDR_BUF_MINSZ],
                   dabuf[AIR_IP6ADDR_BUF_MINSZ];
    GString       *fstr = NULL;
    int            loop = 0;
    unsigned short rvlan = 0;

    if (!rstr) {
        return;
    }

    /* print time and duration */
    air_mstime_g_string_append(rstr, flow->stime, AIR_TIME_ISO8601);
    g_string_append_printf(rstr, "%s", YF_PRINT_DELIM);
    air_mstime_g_string_append(rstr, flow->etime, AIR_TIME_ISO8601);
    g_string_append_printf(rstr, "%s%8.3f%s",
                           YF_PRINT_DELIM, (flow->etime - flow->stime) / 1000.0,
                           YF_PRINT_DELIM);

    /* print initial RTT */
    g_string_append_printf(rstr, "%8.3f%s",
                           flow->rdtime / 1000.0, YF_PRINT_DELIM);

    /* print five tuple */
    if (flow->key.version == 4) {
        air_ipaddr_buf_print(sabuf, flow->key.addr.v4.sip);
        air_ipaddr_buf_print(dabuf, flow->key.addr.v4.dip);
    } else if (flow->key.version == 6) {
        air_ip6addr_buf_print(sabuf, flow->key.addr.v6.sip);
        air_ip6addr_buf_print(dabuf, flow->key.addr.v6.dip);
    } else {
        sabuf[0] = (char)0;
        dabuf[0] = (char)0;
    }
    g_string_append_printf(rstr, "%3u%s%40s%s%5u%s%40s%s%5u%s",
                           flow->key.proto, YF_PRINT_DELIM,
                           sabuf, YF_PRINT_DELIM, flow->key.sp, YF_PRINT_DELIM,
                           dabuf, YF_PRINT_DELIM, flow->key.dp, YF_PRINT_DELIM);

    if (yaft_mac) {
        for (loop = 0; loop < 6; loop++) {
            g_string_append_printf(rstr, "%02x", flow->sourceMacAddr[loop]);
            if (loop < 5) {
                g_string_append_printf(rstr, ":");
            }
            /* clear out mac addr for next flow */
            flow->sourceMacAddr[loop] = 0;
        }
        g_string_append_printf(rstr, "%s", YF_PRINT_DELIM);
        for (loop = 0; loop < 6; loop++) {
            g_string_append_printf(rstr, "%02x",
                                   flow->destinationMacAddr[loop]);
            if (loop < 5) {
                g_string_append_printf(rstr, ":");
            }
            /* clear out mac addr for next flow */
            flow->destinationMacAddr[loop] = 0;
        }
        g_string_append_printf(rstr, "%s", YF_PRINT_DELIM);
    }

    /* print tcp flags */
    fstr = g_string_sized_new(16);
    yfPrintFlags(fstr, flow->val.iflags);
    g_string_append_printf(rstr, "%8s%s", fstr->str, YF_PRINT_DELIM);
    g_string_truncate(fstr, 0);
    yfPrintFlags(fstr, flow->val.uflags);
    g_string_append_printf(rstr, "%8s%s", fstr->str, YF_PRINT_DELIM);
    g_string_truncate(fstr, 0);
    yfPrintFlags(fstr, flow->rval.iflags);
    g_string_append_printf(rstr, "%8s%s", fstr->str, YF_PRINT_DELIM);
    g_string_truncate(fstr, 0);
    yfPrintFlags(fstr, flow->rval.uflags);
    g_string_append_printf(rstr, "%8s%s", fstr->str, YF_PRINT_DELIM);
    g_string_free(fstr, TRUE);

    /* print tcp sequence numbers */
    g_string_append_printf(rstr, "%08x%s%08x%s", flow->val.isn, YF_PRINT_DELIM,
                           flow->rval.isn, YF_PRINT_DELIM);

    /* print vlan tags */
    if (flow->rval.oct) {
        g_string_append_printf(rstr, "%03hx%s%03hx%s", flow->val.vlan,
                               YF_PRINT_DELIM, flow->rval.vlan,
                               YF_PRINT_DELIM);
    } else {
        g_string_append_printf(rstr, "%03hx%s%03hx%s", flow->key.vlanId,
                               YF_PRINT_DELIM, rvlan, YF_PRINT_DELIM);
    }

    /* print flow counters */
    g_string_append_printf(rstr, "%8llu%s%8llu%s%8llu%s%8llu%s",
                           (long long unsigned int)flow->val.pkt,
                           YF_PRINT_DELIM,
                           (long long unsigned int)flow->val.oct,
                           YF_PRINT_DELIM,
                           (long long unsigned int)flow->rval.pkt,
                           YF_PRINT_DELIM,
                           (long long unsigned int)flow->rval.oct,
                           YF_PRINT_DELIM);

    /* if app label is enabled, print the label */
#ifdef YAF_ENABLE_APPLABEL
    g_string_append_printf(rstr, "%5u%s", flow->appLabel, YF_PRINT_DELIM);
#endif

    /* if entropy is enabled, print the entropy values */
#ifdef YAF_ENABLE_ENTROPY
    g_string_append_printf(rstr, "%3u%s%3u%s",
                           flow->val.entropy, YF_PRINT_DELIM,
                           flow->rval.entropy, YF_PRINT_DELIM);
#endif

    /* end reason flags */
    if ((flow->reason & YAF_END_MASK) == YAF_END_IDLE) {
        g_string_append(rstr, "idle ");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_ACTIVE) {
        g_string_append(rstr, "active ");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_FORCED) {
        g_string_append(rstr, "eof ");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_RESOURCE) {
        g_string_append(rstr, "rsrc ");
    }
    if ((flow->reason & YAF_END_MASK) == YAF_END_UDPFORCE) {
        g_string_append(rstr, "force ");
    }

    /* finish line */
    g_string_append(rstr, "\n");

    /* not printing payload - but need to free */
#ifdef YAF_ENABLE_PAYLOAD
    if (flow->val.payload) {
        g_free(flow->val.payload);
        flow->val.payload = NULL;
        flow->val.paylen = 0;
    }
    if (flow->rval.payload) {
        g_free(flow->rval.payload);
        flow->rval.payload = NULL;
        flow->rval.paylen = 0;
    }
#endif /* ifdef YAF_ENABLE_PAYLOAD */
}


/**
 * yfPrint
 *
 *
 *
 */
gboolean
yfPrint(
    FILE      *out,
    yfFlow_t  *flow,
    GError   **err)
{
    GString *rstr = NULL;
    int      rc = 0;

    rstr = g_string_sized_new(YF_PRINT_LINE_LEN);

    yfPrintString(rstr, flow);

    rc = fwrite(rstr->str, rstr->len, 1, out);

    if (rc != 1) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "error printing flow: %s", strerror(errno));
    }

    g_string_free(rstr, TRUE);

    return (rc == 1);
}


/**
 * yfPrintDelimited
 *
 *
 *
 */
gboolean
yfPrintDelimited(
    FILE      *out,
    yfFlow_t  *flow,
    gboolean   yaft_mac,
    GError   **err)
{
    GString *rstr = NULL;
    int      rc = 0;

    rstr = g_string_sized_new(YF_PRINT_LINE_LEN);

    yfPrintDelimitedString(rstr, flow, yaft_mac);

    rc = fwrite(rstr->str, rstr->len, 1, out);

    if (rc != 1) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                    "error printing delimited flow: %s", strerror(errno));
    }

    g_string_free(rstr, TRUE);

    return (rc == 1);
}


/**
 * yfPrintColumnHeaders
 *
 *
 */
void
yfPrintColumnHeaders(
    FILE      *out,
    gboolean   yaft_mac,
    GError   **err)
{
    GString *rstr = NULL;

    rstr = g_string_sized_new(YF_PRINT_LINE_LEN);

    g_string_append_printf(rstr, "start-time%14s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "end-time%16s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "duration%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "rtt%6s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "proto%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "sip%36s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "sp%4s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "dip%38s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "dp%4s", YF_PRINT_DELIM);
    if (yaft_mac) {
        g_string_append_printf(rstr, "srcMacAddress%5s", YF_PRINT_DELIM);
        g_string_append_printf(rstr, "destMacAddress%4s", YF_PRINT_DELIM);
    }
    g_string_append_printf(rstr, "iflags%3s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "uflags%3s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "riflags%2s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "ruflags%2s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "isn%6s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "risn%5s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "tag%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "rtag%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "pkt%5s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "oct%6s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "rpkt%5s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "roct%5s", YF_PRINT_DELIM);

#ifdef YAF_ENABLE_APPLABEL
    g_string_append_printf(rstr, "app%3s", YF_PRINT_DELIM);
#endif
#ifdef YAF_ENABLE_ENTROPY
    g_string_append_printf(rstr, "entropy%s", YF_PRINT_DELIM);
    g_string_append_printf(rstr, "rentropy%s", YF_PRINT_DELIM);
#endif

    g_string_append_printf(rstr, "end-reason");
    g_string_append(rstr, "\n");

    fwrite(rstr->str, rstr->len, 1, out);

    g_string_free(rstr, TRUE);
}
