/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  yaftab.h
 *  YAF Active Flow Table
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

/*
 * This is the documentation for the _old_ yaftab.h; it is no longer current,
 * and should not be read by anyone.
 *
 * Flow generation interface for YAF. This facility works by maintaining a
 * current flow table. Packets may be added to the active flows within this
 * table using the yfFlowPkt() call. Completed flows may be written to an
 * IPFIX message buffer using yfFlowFlush().
 *
 * The flow table is configured by a number of global variables.
 *
 * <tt>yaf_idle</tt> sets
 * the idle timeout in seconds. A flow that receives no packets for the idle
 * timeout is assumed to be complete. The idle timeout is set to 300 seconds
 * (five minutes) by default.
 *
 * <tt>yaf_active</tt> sets the active timeout in seconds.
 * The maximum duration of a flow is the active timeout; additional packets
 * for the same flow will be counted as part of a new flow. The active timeout
 * is set to 1800 seconds (half an hour) by default.
 *
 * <tt>yaf_flowlim</tt> sets the maximum size of the flow table; flows
 * exceeding
 * this limit will be expired in least-recent order, as if they were idle. The
 * flow limit defaults to zero, for no limit. Use this global to limit resource
 * usage by the flow table.
 *
 * <tt>yaf_paylen</tt> sets the number of bytes of payload to capture from the
 * start of each flow. The payload length defaults to zero, which disables
 * payload capture.
 *
 * <tt>yaf_uniflow</tt>, if TRUE, exports flows in uniflow mode, using the
 * record adjacency export method described in section 3 of
 * draft-ietf-ipfix-biflow. Defaults to FALSE.
 *
 * <tt>yaf_macmode</tt>, if TRUE, exports layer 2 information with each flow;
 * presently this is limited to VLAN tags but may be expanded to include the
 * MPLS stack and MAC addresses in the future. Defaults to FALSE.
 *
 * <tt>yaf_silkmode</tt>, if TRUE, enables SiLK compatibility mode. In this
 * mode, totalOctetCount and reverseTotalOctetCount are clamped to 32 bits.
 * Any packet that would cause either of these counters to overflow 32 bits
 * will force an active timeout. The high-order bit of the flowEndReason IE
 * is set on any flow created on a counter overflow, as above, or on an active
 * timeout. Defaults to FALSE.
 *
 * <tt>yaf_reqtype</tt> limits the flow table to collecting IPv4 or IPv6 flows
 * only. Set to YF_TYPE_IPv4 for IPv4 flows only, YF_TYPE_IPv6 for IPv6 flows
 * only, or YF_TYPE_IPANY (the default) to collect both IPv4 and IPv6 flows.
 *
 * This facility is used by YAF to assemble packets into flows.
 */

/**
 * @file
 *
 * Flow generation interface for YAF. [TODO - frontmatter]
 *
 * This facility is used by YAF to assemble packets into flows.
 */

#ifndef _YAF_TAB_H_
#define _YAF_TAB_H_

#include <yaf/autoinc.h>
#include <yaf/yafcore.h>
#include <yaf/decode.h>


/**
 *  A flow table. Opaque. Create with yfFlowTabAlloc() and free with
 *  yfFlowTabFree().
 */
typedef struct yfFlowTab_st yfFlowTab_t;

/**
 *  Configuration settings used to initalize the flow table in
 *  yfFlowTabAlloc().
 */
typedef struct yfFlowTabConfig_st {
    /**
     *  Active timeout in milliseconds. The maximum duration of a flow is the
     *  active timeout; additional packets for the same flow will be counted
     *  as part of a new flow.
     */
    uint64_t   active_ms;
    /**
     *  Idle timeout in milliseconds. A flow that receives no packets for the
     *  idle timeout is assumed to be complete.
     */
    uint64_t   idle_ms;
    /**
     *  Maximum number of active flows. Flows exceeding this limit will be
     *  expired in least-recent order, as if they were idle. Used to limit
     *  resource usage of a flow table. A value of 0 disables flow count
     *  limits.
     */
    uint32_t   max_flows;
    /**
     *  Maximum octets of payload to capture per flow direction. Requires at
     *  least max_payload octets of payload to be available in each packet
     *  buffer passed to yfFlowPBuf(). A value of 0 disables payload capture
     *  and export.
     */
    uint32_t   max_payload;

    /**
     *  If not NULL, and `ndpi` is TRUE, use the provided protocol file to
     *  expand the sub-protocols list and port-based detection methods.
     */
    char      *ndpi_proto_file;

    /**
     *  Directory to put pcap-per-flow files
     */
    char      *pcap_dir;
    /**
     *  The flow key hash to create a PCAP for.
     */
    char      *pcap_flowkey;
    /**
     *  Maximum size [in bytes] of a pcap file before rotating.
     */
    uint64_t   pcap_maxfile;
    /**
     *  File for pcap meta output. Default is stdout
     */
    char      *pcap_meta_file;
    /**
     *  The start time to create a PCAP for.
     */
    char      *pcap_stime;

    /**
     *  If not 0, then this will enable exporting a single UDP packet with
     *  this src/dst port as a flow.  If 1, all UDP packets are treated as
     *  independent flows.
     */
    uint16_t   udp_uniflow_port;

    /**
     *  If TRUE, then the payload, as limited by max_payload, is sent through
     *  various plugins and code in order to determine which protocol is
     *  running on the flow by doing only payload inspection and exporting
     *  payload relevent information.
     */
    gboolean   applabel_mode;
    /**
     *  If TRUE, then a Shannon Entropy measurement is made over the captured
     *  payload (as limited by max_payload).  The entropy value is exported as
     *  two values one for forward payload and one for reverse payload.
     */
    gboolean   entropy_mode;
    /**
     *  If TRUE, then YAF will do some extra calculations on flows.
     */
    gboolean   flowstats_mode;
    /**
     *  If TRUE, then yaf will process files that are out of sequence.
     */
    gboolean   force_read_all;
    /**
     *  If TRUE, then this will enable exporting of full packet banners of the
     *  TCP negotiations for the first three packets (including IP and
     *  transport headers) for external fingerprinting
     */
    gboolean   fpexport_mode;
    /**
     *  If TRUE, collect and export source and destination Mac Addresses.
     */
    gboolean   mac_mode;
    /**
     *  If TRUE, use MPLS labels when determining flows. Requires YAF to have
     *  been built with MPLS support.
     */
    gboolean   mpls_mode;
    /**
     *  If TRUE, enable nDPI application labeling with standard protocols.
     */
    gboolean   ndpi;
    /**
     *  If TRUE, this will remove the vlan in the calculation of the flow key
     *  hash.
     */
    gboolean   no_vlan_in_key;
    /**
     *  If TRUE, then this will enable passive OS finger printing using the
     *  p0f engine based mostly on TCP negotiation
     */
    gboolean   p0f_mode;
    /**
     *  If TRUE, print one line per packet we export. This will give offset
     *  and length into the pcap yaf writes.
     */
    gboolean   pcap_index;
    /**
     *  If TRUE, then `pcap_dir` will be set to the directory to place
     *  pcap-per-flow files.
     */
    gboolean   pcap_per_flow;
    /**
     *  If TRUE, clamp totalOctetCount and maxTotalOctetCount to 32 bits and
     *  force active timeout on overflow. Set high order bit in flowEndReason
     *  for each flow created on an overflow or active timeout. Breaks IPFIX
     *  interoperability; use for direct export to SiLK rwflowpack or flowcap.
     */
    gboolean   silk_mode;
    /**
     *  If TRUE, then this will enable capturing payload for all UDP packets
     *  in a flow (instead of just the first packet) up to `max_payload`
     */
    gboolean   udp_multipkt_payload;
    /**
     *  If TRUE, export biflows using record adjacency (two uniflows exported
     *  back-to-back. Use this for interoperability with IPFIX collectors that
     *  do not implement RFC 5103.
     */
    gboolean   uniflow_mode;

} yfFlowTabConfig_t;

/**
 * yfFlowTabAlloc
 *
 * Allocate a flow table.
 *
 * @param ftconfig  The configuration settings to use for the table.
 * @param hfctx     The plugin hooks context variable (NULL if plugins not
 *                  enabled)
 *
 * @return a new flow table.
 */
yfFlowTab_t *
yfFlowTabAlloc(
    const yfFlowTabConfig_t  *ftconfig,
    void                    **hfctx);

/**
 * Free a previously allocated flow table. Discards any outstanding active
 * flows without closing or flushing them; use yfFlowTabFlushAll() before
 * yfFlowFree() to do this.
 *
 * @param flowtab a flow table allocated by yfFlowTabAlloc()
 */
void
yfFlowTabFree(
    yfFlowTab_t  *flowtab);


/**
 * Update the Pcap Filename in the Flowtab for pcap meta data output
 *
 * @param flowtab pointer to flow table
 * @param new_file_name the filename of the next pcap file to write to
 */
void
yfUpdateRollingPcapFile(
    yfFlowTab_t  *flowtab,
    char         *new_file_name);

/**
 * yfGetFlowTabStats
 * Get Flow Table Stats for Export
 *
 * @param flowtab
 * @param packets number of packets processed
 * @param flows number of flows created
 * @param rej_pkts number of packets rejected due to out of sequence
 * @param peak maximum number of flows in the flow table at any 1 time
 * @param flush number of flush events called on flow table
 */
void
yfGetFlowTabStats(
    yfFlowTab_t  *flowtab,
    uint64_t     *packets,
    uint64_t     *flows,
    uint64_t     *rej_pkts,
    uint32_t     *peak,
    uint32_t     *flush);

/**
 * Add a decoded packet buffer to a given flow table. Adds the packet to
 * the flow to which it belongs, creating a new flow if necessary. Causes
 * the flow to which it belongs to time out if it is longer than the active
 * timeout.  Closes the flow if the flow closure conditions (TCP RST, TCP FIN
 * four-way teardown) are met.
 *
 * @param flowtab   flow table to add the packet to
 * @param pbuflen   size of the packet buffer pbuf
 * @param pbuf      packet buffer containing decoded packet to add.
 */
void
yfFlowPBuf(
    yfFlowTab_t  *flowtab,
    size_t        pbuflen,
    yfPBuf_t     *pbuf);

/**
 * Flush closed flows in the given flow table to the given IPFIX Message
 * Buffer. Causes any idle flows to time out, removing them from the active
 * flow table; also enforces the flow table's resource limit. If close is
 * TRUE, additionally closes all active flows and flushes as well.
 *
 * @param yfContext YAF thread context structure, holds pointers for the
 *                  flowtable from which to flush flows and the fbuf, the
 *                  destination to which the flows should be flushed
 * @param close     close all active flows before flushing
 * @param err       An error description pointer; must not be NULL.
 * @return TRUE on success, FALSE otherwise.
 */
gboolean
yfFlowTabFlush(
    void      *yfContext,
    gboolean   close,
    GError   **err);

/**
 * Get the current packet clock from a flow table.
 *
 * @param flowtab a flow table
 * @return current packet clock
 */
uint64_t
yfFlowTabCurrentTime(
    const yfFlowTab_t  *flowtab);

/**
 * Print flow table statistics to the log.
 *
 * @param flowtab flow table to dump stats for
 * @param timer a GTimer containing the runtime
 *              (for packet and flow rate logging). May be NULL to suppress
 *              rate logging.
 */
uint64_t
yfFlowDumpStats(
    yfFlowTab_t  *flowtab,
    GTimer       *timer);

#endif /* ifndef _YAF_TAB_H_ */
