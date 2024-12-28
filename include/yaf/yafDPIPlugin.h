/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @internal
 *
 *  yafDPIPlugin.h
 *  Declares functions used by DPI plugins.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Chris Inacio, Emily Sarneso, Dillon Lareau
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
 *  @file yafDPIPlugin.h
 *
 *  header file for all of the functions in yafdpi.c needed by DPI plugins.
 */

#ifndef _YAF_DPI_PUBLIC_H_
#define _YAF_DPI_PUBLIC_H_

#include <yaf/autoinc.h>

#ifdef YAF_ENABLE_APPLABEL

#include <ctype.h>
#include <glib/gstdio.h>
#include <pcre.h>

#ifdef YAF_ENABLE_DPI
#define YAF_INT_PADDING_FLAG    0x01
#define YAF_DISABLE_IE_FLAG     0x04

/* max num of DPI fields we'll export - total */
#define YAF_MAX_CAPTURE_FIELDS  50
/* per side */
#define YAF_MAX_CAPTURE_SIDE    25
#endif  /* YAF_ENABLE_DPI */


/*  Macros for dealing with packet payload data  */

/*
 *  Interprets octets in a data buffer as an integer ("unpacks" an integer).
 *
 *  These are helper macros for processing the packet payload data.  They
 *  interpret the octets at DATA[POS] as an integer of type TYPE and put the
 *  the result in the referent of VALUE (a pointer to local variable of the
 *  appropriate type), where DATA is start of the payload data, POS is a
 *  pointer to the current position (or offset) into DATA, and LEN is the
 *  total length of DATA.  The macros add the length of TYPE to POS.
 *
 *  If there are too few octets available in DATA to get an integer of TYPE
 *  (or if POS is greater than LEN), POS is set to LEN+1 and VALUE is set to
 *  0.  The macros use LEN+1 so the caller can distinguish between an error
 *  and successfully reading to the exact end of the buffer.
 *
 *  Performs network byte swapping on the values if needed.
 */

/**
 *  Unpacks a uint8_t at the position (or byte-offset) stored in the referent
 *  of `y_srcpos` (an integer pointer) from the data buffer `y_srcbuf` having
 *  total length `y_srclen`, stores the value in the referent of `y_dstval` (a
 *  uint8_t pointer), and advances the referent of `y_srcpos` by 1.
 *
 *  If there are too few bytes to read a uint8_t, sets the referent of
 *  `y_dstval` to 0 and sets the referent of `y_srcpos` to one more than
 *  `y_srclen`.
 *
 *  Although size_t is used for y_srcpos in the declaration mock-up, any
 *  integer value should work.
 *
 *  void
 *  yfUnpackU8(
 *      uint8_t        *y_dstval,   // VALUE
 *      const uint8_t  *y_srcbuf,   // DATA
 *      uint32_t       *y_srcpos,   // POS
 *      size_t          y_srclen);  // LEN
 */
#define yfUnpackU8(y_dstval, y_srcbuf, y_srcpos, y_srclen)      \
    do {                                                        \
        const uint8_t *pt_srcbuf = (const uint8_t *)y_srcbuf;   \
        size_t         pt_srclen = y_srclen;                    \
        size_t         pt_srcpos = *(y_srcpos);                 \
        uint8_t       *pt_dstval   = (uint8_t *)(y_dstval);     \
                                                                \
        if (pt_srcpos < pt_srclen) {                            \
            *pt_dstval = pt_srcbuf[pt_srcpos];                  \
            ++*(y_srcpos);                                      \
        } else {                                                \
            *pt_dstval = 0;                                     \
            *(y_srcpos) = pt_srclen + 1;                        \
        }                                                       \
    } while(0)

/**
 *  Unpacks a uint16_t at the position (or byte-offset) stored in the referent
 *  of `y_srcpos` (an integer pointer) from the data buffer `y_srcbuf` having
 *  total length `y_srclen`, stores the value in the referent of `y_dstval` (a
 *  uint16_t pointer), and advances the the referent of `y_srcpos` by 2.
 *
 *  If a uint16_t cannot be read, sets the referent of `y_dstval` to 0 and sets
 *  the referent of `y_srcpos` to one more than `y_srclen`.
 *
 *  Although size_t is used for y_srcpos in the declaration mock-up, any
 *  integer value should work.
 *
 *  void
 *  yfUnpackU16(
 *      uint16_t       *y_dstval,   // VALUE
 *      const uint8_t  *y_srcbuf,   // DATA
 *      uint32_t       *y_srcpos,   // POS
 *      size_t          y_srclen);  // LEN
 */
#define yfUnpackU16(y_dstval, y_srcbuf, y_srcpos, y_srclen)               \
    yfUnpackType(uint16_t, ntohs, y_dstval, y_srcbuf, y_srcpos, y_srclen)

/**
 *  Unpacks a uint32_t at the position (or byte-offset) stored in the referent
 *  of `y_srcpos` (an integer pointer) from the data buffer `y_srcbuf` having
 *  total length `y_srclen`, stores the value in the referent of `y_dstval` (a
 *  uint32_t pointer), and advances the the referent of `y_srcpos` by 4.
 *
 *  If a uint32_t cannot be read, sets the referent of `y_dstval` to 0 and sets
 *  the referent of `y_srcpos` to one more than `y_srclen`.
 *
 *  Although size_t is used for y_srcpos in the declaration mock-up, any
 *  integer value should work.
 *
 *  void
 *  yfUnpackU32(
 *      uint32_t       *y_dstval,   // VALUE
 *      const uint8_t  *y_srcbuf,   // DATA
 *      uint32_t       *y_srcpos,   // POS
 *      size_t          y_srclen);  // LEN
 */
#define yfUnpackU32(y_dstval, y_srcbuf, y_srcpos, y_srclen)               \
    yfUnpackType(uint32_t, ntohl, y_dstval, y_srcbuf, y_srcpos, y_srclen)

/**
 *  Gets (or unpacks) a uint8_t from `y_srcbuf` at position (or byte-offset)
 *  `y_srcpos` (an integer) and sets the referent of `y_dstval` (a uint8_t
 *  pointer) to that value without checking whether there are enough octets in
 *  `y_srcbuf` to read the value.
 *
 *  Although size_t is used for y_srcpos in the declaration mock-up, any
 *  integer value should work.
 *
 *  void
 *  yfGetRiskyU8(
 *      uint8_t        *y_dstval,   // VALUE
 *      const uint8_t  *y_srcbuf,   // DATA
 *      size_t          y_srcpos);  // POS
 */
#define yfGetRiskyU8(y_dstval, y_srcbuf, y_srcpos)              \
    do {                                                        \
        const uint8_t *pt_srcbuf = (const uint8_t *)y_srcbuf;   \
        size_t         pt_srcpos = y_srcpos;                    \
        uint8_t       *pt_dstval = (uint8_t *)(y_dstval);       \
                                                                \
        *pt_dstval = pt_srcbuf[pt_srcpos];                      \
    } while(0)

/**
 *  Gets (or unpacks) a uint16_t from `y_srcbuf` at position (or byte-offset)
 *  `y_srcpos` (an integer) and sets the referent of `y_dstval` (a uint16_t
 *  pointer) to that value without checking whether there are enough octets in
 *  `y_srcbuf` to read the value.
 *
 *  Although size_t is used for y_srcpos in the declaration mock-up, any
 *  integer value should work.
 *
 *  void
 *  yfGetRiskyU16(
 *      uint16_t       *y_dstval,   // VALUE
 *      const uint8_t  *y_srcbuf,   // DATA
 *      size_t          y_srcpos);  // POS
 */
#define yfGetRiskyU16(y_dstval, y_srcbuf, y_srcpos)                     \
    yfGetRiskyType(uint16_t, ntohs, y_dstval, y_srcbuf, y_srcpos)

/**
 *  Gets (or unpacks) a uint32_t from `y_srcbuf` at position (or byte-offset)
 *  `y_srcpos` (an integer) and sets the referent of `y_dstval` (a uint32_t
 *  pointer) to that value without checking whether there are enough octets in
 *  `y_srcbuf` to read the value.
 *
 *  Although size_t is used for y_srcpos in the declaration mock-up, any
 *  integer value should work.
 *
 *  void
 *  yfGetRiskyU32(
 *      uint32_t       *y_dstval,   // VALUE
 *      const uint8_t  *y_srcbuf,   // DATA
 *      size_t          y_srcpos);  // POS
 */
#define yfGetRiskyU32(y_dstval, y_srcbuf, y_srcpos)                     \
    yfGetRiskyType(uint32_t, ntohl, y_dstval, y_srcbuf, y_srcpos)

/**
 *  Helper macro for the uint16_t and uint32_t versions.
 *
 *  @param y_type   TYPE:  the type of integer to read (uint8_t, uint16_t, etc)
 *  @param y_swap   SWAP:  macro to swap network/host endian
 *  @param y_dstval VALUE: where to put the value, a pointer (&uint32_t)
 *  @param y_srcbuf DATA:  the start of the data buffer holding the value
 *  @param y_srcpos POS:   the position or offset within DATA, a pointer
 *  @param y_srclen LEN:   the total length of the data buffer
 */
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED

#define yfGetRiskyType(y_type, y_swap, y_dstval, y_srcbuf, y_srcpos)    \
    do {                                                                \
        const uint8_t *pt_srcbuf = (uint8_t *)y_srcbuf;                 \
        size_t         pt_srcpos = y_srcpos;                            \
        y_type        *pt_dstval = (y_type *)(y_dstval);                \
        y_type         pt_temp;                                         \
                                                                        \
        memcpy(&pt_temp, &pt_srcbuf[pt_srcpos], sizeof(pt_temp));       \
        *pt_dstval = y_swap(pt_temp);                                   \
    } while(0)

#define yfUnpackType(y_type, y_swap, y_dstval, y_srcbuf, y_srcpos, y_srclen) \
    do {                                                                \
        const uint8_t *pt_srcbuf = (uint8_t *)y_srcbuf;                 \
        size_t         pt_srclen = y_srclen;                            \
        size_t         pt_srcpos = *(y_srcpos);                         \
        y_type        *pt_dstval = (y_type *)(y_dstval);                \
        y_type         pt_temp;                                         \
                                                                        \
        if (pt_srcpos + sizeof(y_type) <= pt_srclen) {                  \
            memcpy(&pt_temp, &pt_srcbuf[pt_srcpos], sizeof(pt_temp));   \
            *pt_dstval = y_swap(pt_temp);                               \
            *(y_srcpos) += sizeof(y_type);                              \
        } else {                                                        \
            *pt_dstval = 0;                                             \
            *(y_srcpos) = pt_srclen + 1;                                \
        }                                                               \
    } while(0)

#else  /* #ifdef HAVE_ALIGNED_ACCESS_REQUIRED */

#define yfGetRiskyType(y_type, y_swap, y_dstval, y_srcbuf, y_srcpos)    \
    do {                                                                \
        const uint8_t *pt_srcbuf = (uint8_t *)y_srcbuf;                 \
        size_t         pt_srcpos = y_srcpos;                            \
        y_type        *pt_dstval = (y_type *)(y_dstval);                \
        const y_type  *pt_temp;                                         \
                                                                        \
        pt_temp = (const y_type *)(&pt_srcbuf[pt_srcpos]);              \
        *pt_dstval = y_swap(*pt_temp);                                  \
    } while(0)

#define yfUnpackType(y_type, y_swap, y_dstval, y_srcbuf, y_srcpos, y_srclen) \
    do {                                                                \
        const uint8_t *pt_srcbuf = (const uint8_t *)y_srcbuf;           \
        size_t         pt_srclen = y_srclen;                            \
        size_t         pt_srcpos = *(y_srcpos);                         \
        y_type        *pt_dstval = (y_type *)(y_dstval);                \
        const y_type  *pt_temp;                                         \
                                                                        \
        if (pt_srcpos + sizeof(y_type) <= pt_srclen) {                  \
            pt_temp = (const y_type *)(&pt_srcbuf[pt_srcpos]);          \
            *pt_dstval = y_swap(*pt_temp);                              \
            *(y_srcpos) += sizeof(y_type);                              \
        } else {                                                        \
            *pt_dstval = 0;                                             \
            *(y_srcpos) = pt_srclen + 1;                                \
        }                                                               \
    } while(0)

#endif  /* #else of #ifdef HAVE_ALIGNED_ACCESS_REQUIRED */


/*
 *  Puts an integer or octet-array into a data buffer ("packs" an integer).
 *
 *  These are helper macros for processing the packet payload data, especially
 *  for filling the `exbuf` of `ypDPIFlowCtx_t`.  They copy a local integer
 *  value VALUE of type TYPE to DATA[POS], where DATA is start of the output
 *  buffer, POS is a pointer to the current position (or offset) within DATA,
 *  and LEN is the total length of DATA.  The macros add the number of octets
 *  copied to POS.
 *
 *  If there are too few octets available in DATA to put the value (or if POS
 *  is greater than LEN), POS is set to LEN+1.  The macros use LEN+1 so the
 *  caller can distinguish between an error and successfully writing to the
 *  exact end of the buffer.
 *
 *  NOTE: Since this is often used to fill an internal buffer, these macros do
 *  not byte-swap `y_value` prior to packing it into the array.  If that is
 *  needed, wrap `y_value` with `ntohl()` or `ntohs()`.
 */

/**
 *  Copies `y_srclen` octets of data from `y_srcbuf` into `y_dstbuf` at
 *  position (or byte-offset) `y_dstpos` (an integer pointer), where
 *  `y_dstlen` is the total length of `y_dstbuf`, and advances the referent of
 *  `y_dstpos` by `y_srclen`.
 *
 *  If there are too few bytes available in `y_dstbuf` to copy the data,
 *  leaves `y_dstbuf` unchanged and sets the referent of `y_dstpos` to one
 *  more than `y_dstlen`.
 *
 *  Although size_t is used for y_dstpos in the declaration mock-up, any
 *  integer value should work.
 *
 *  void
 *  yfPackArrayU8(
 *      const uint8_t  *y_srcbuf,
 *      size_t          y_srclen,
 *      uint8_t        *y_dstbuf,
 *      size_t         *y_dstpos,
 *      size_t          y_dstlen);
 */
#define yfPackArrayU8(y_srcbuf, y_srclen, y_dstbuf, y_dstpos, y_dstlen) \
    do {                                                                \
        const uint8_t  *pt_srcbuf = (const uint8_t *)y_srcbuf;          \
        size_t          pt_srclen = y_srclen;                           \
        uint8_t        *pt_dstbuf = (uint8_t *)y_dstbuf;                \
        size_t          pt_dstlen = y_dstlen;                           \
        size_t          pt_dstpos = *(y_dstpos);                        \
                                                                        \
        if (pt_dstpos + pt_srclen <= pt_dstlen) {                       \
            memcpy(&pt_dstbuf[pt_dstpos], pt_srcbuf, pt_srclen);        \
            *(y_dstpos) += pt_srclen;                                   \
        } else {                                                        \
            *(y_dstpos) = pt_dstlen + 1;                                \
        }                                                               \
    } while(0)

/**
 *  Packs the uint8_t `y_srcval` into the destination data buffer `y_dstbuf`
 *  at the position (or byte-offset) stored in the referent of `y_dstpos` (an
 *  integer pointer), where `y_dstlen` is the total length of the buffer, and
 *  advances the referent of `y_dstpos` by 1.
 *
 *  If there are too few bytes to pack a uint8_t, leaves `y_dstbuf` unchanged
 *  and sets the referent of `y_dstpos` to one more than `y_dstlen`.
 *
 *  Although size_t is used for y_dstpos in the declaration mock-up, any
 *  integer value should work.
 *
 *  void
 *  yfPackU8(
 *      uint8_t   y_srcval,     // VALUE
 *      uint8_t  *y_dstbuf,     // DATA
 *      size_t   *y_dstpos,     // POS
 *      size_t    y_dstlen);    // LEN
 */
#define yfPackU8(y_srcval, y_dstbuf, y_dstpos, y_dstlen)        \
    do {                                                        \
        uint8_t *pt_dstbuf = (uint8_t *)y_dstbuf;               \
        size_t   pt_dstlen = y_dstlen;                          \
        size_t   pt_dstpos = *(y_dstpos);                       \
        uint8_t  pt_srcval;                                     \
                                                                \
        if (pt_dstpos < pt_dstlen) {                            \
            pt_srcval = (uint8_t)(y_srcval);                    \
            pt_dstbuf[pt_dstpos] = pt_srcval;                   \
            ++*(y_dstpos);                                      \
        } else {                                                \
            *(y_dstpos) = pt_dstlen + 1;                        \
        }                                                       \
    } while(0)

/**
 *  Packs the uint16_t `y_srcval` into the destination data buffer `y_dstbuf`
 *  at the position (or byte-offset) stored in the referent of `y_dstpos` (an
 *  integer pointer), where `y_dstlen` is the total length of the buffer, and
 *  advances the referent of `y_dstpos` by 2.
 *
 *  If there are too few bytes to pack a uint16_t, leaves `y_dstbuf` unchanged
 *  and sets the referent of `y_dstpos` to one more than `y_dstlen`.
 *
 *  This does not byte-swap `y_srcval`.  Pass `htons(y_srcval)` if desired.
 *
 *  Although size_t is used for y_dstpos in the declaration mock-up, any
 *  integer value should work.
 *
 *  void
 *  yfPackU16(
 *      uint16_t  y_srcval,     // VALUE
 *      uint8_t  *y_dstbuf,     // DATA
 *      size_t   *y_dstpos,     // POS
 *      size_t    y_dstlen);    // LEN
 */
#define yfPackU16(y_srcval, y_dstbuf, y_dstpos, y_dstlen)               \
    yfPackType(uint16_t, y_srcval, y_dstbuf, y_dstpos, y_dstlen)

/**
 *  Packs the uint32_t `y_srcval` into the destination data buffer `y_dstbuf`
 *  at the position (or byte-offset) stored in the referent of `y_dstpos` (an
 *  integer pointer), where `y_dstlen` is the total length of the buffer, and
 *  advances the referent of `y_dstpos` by 3.
 *
 *  If there are too few bytes to pack a uint32_t, leaves `y_dstbuf` unchanged
 *  and sets the referent of `y_dstpos` to one more than `y_dstlen`.
 *
 *  This does not byte-swap `y_srcval`.  Pass `htonl(y_srcval)` if desired.
 *
 *  Although size_t is used for y_dstpos in the declaration mock-up, any
 *  integer value should work.
*
 *  void
 *  yfPackU32(
 *      uint32_t  y_srcval,     // VALUE
 *      uint8_t  *y_dstbuf,     // DATA
 *      size_t   *y_dstpos,     // POS
 *      size_t    y_dstlen);    // LEN
 */
#define yfPackU32(y_srcval, y_dstbuf, y_dstpos, y_dstlen)               \
    yfPackType(uint32_t, y_srcval, y_dstbuf, y_dstpos, y_dstlen)

/**
 *  Puts (or packs) the uint8_t `y_srcval` into the destination data buffer
 *  `y_dstbuf` at the position (or byte-offset) `y_dstpos` (an integer)
 *  without regard to whether the destination has enough available octets to
 *  store the value.
 *
 *  Although size_t is used for y_dstpos in the declaration mock-up, any
 *  integer value should work.
 *
 *  void
 *  yfPackU8(
 *      uint8_t   y_srcval,     // VALUE
 *      uint8_t  *y_dstbuf,     // DATA
 *      size_t    y_dstpos);    // POS
 */
#define yfPutRiskyU8(y_srcval, y_dstbuf, y_dstpos)      \
    do {                                                \
        uint8_t *pt_dstbuf = (uint8_t *)y_dstbuf;       \
        size_t   pt_dstpos = y_dstpos;                  \
        uint8_t  pt_srcval;                             \
                                                        \
        pt_srcval = (uint8_t)(y_srcval);                \
        pt_dstbuf[pt_dstpos] = pt_srcval;               \
    } while(0)

/**
 *  Puts (or packs) the uin16_t `y_srcval` into the destination data buffer
 *  `y_dstbuf` at the position (or byte-offset) `y_dstpos` (an integer)
 *  without regard to whether the destination has enough available octets to
 *  store the value.
 *
 *  This does not byte-swap `y_srcval`.  Pass `htons(y_srcval)` if desired.
 *
 *  Although size_t is used for y_dstpos in the declaration mock-up, any
 *  integer value should work.
 *
 *  void
 *  yfPackU16(
 *      uint16_t  y_srcval,     // VALUE
 *      uint8_t  *y_dstbuf,     // DATA
 *      size_t    y_dstpos);    // POS
 */
#define yfPutRiskyU16(y_srcval, y_dstbuf, y_dstpos)             \
    yfPutRiskyType(uint16_t, y_srcval, y_dstbuf, y_dstpos)

/**
 *  Puts (or packs) the uin32_t `y_srcval` into the destination data buffer
 *  `y_dstbuf` at the position (or byte-offset) `y_dstpos` (an integer)
 *  without regard to whether the destination has enough available octets to
 *  store the value.
 *
 *  This does not byte-swap `y_srcval`.  Pass `htonl(y_srcval)` if desired.
 *
 *  Although size_t is used for y_dstpos in the declaration mock-up, any
 *  integer value should work.
 *
 *  void
 *  yfPackU32(
 *      uint32_t  y_srcval,     // VALUE
 *      uint8_t  *y_dstbuf,     // DATA
 *      size_t    y_dstpos);    // POS
 */
#define yfPutRiskyU32(y_srcval, y_dstbuf, y_dstpos)             \
    yfPutRiskyType(uint32_t, y_srcval, y_dstbuf, y_dstpos)

/**
 *  Helper for the uint16_t and uint32_t versions.
 *
 *  @param y_type   TYPE:  the type of integer to pack (uint8_t, uint16_t, etc)
 *  @param y_srcval VALUE: the value to be copied (uint32_t; not a pointer)
 *  @param y_dstbuf DATA:  start of data buffer to store the value
 *  @param y_dstpos POS:   the position or offset within DATA, a pointer
 *  @param y_dstlen LEN:   the total length of the data buffer
 */
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED

#define yfPutRiskyType(y_type, y_srcval, y_dstbuf, y_dstpos)            \
    do {                                                                \
        uint8_t *pt_dstbuf = (uint8_t *)y_dstbuf;                       \
        size_t   pt_dstpos = y_dstpos;                                  \
        y_type   pt_srcval;                                             \
                                                                        \
        pt_srcval = (y_type)(y_srcval);                                 \
        memcpy(&pt_dstbuf[pt_dstpos], &pt_srcval, sizeof(pt_srcval));   \
    } while(0)

#define yfPackType(y_type, y_srcval, y_dstbuf, y_dstpos, y_dstlen)      \
    do {                                                                \
        uint8_t *pt_dstbuf = (uint8_t *)y_dstbuf;                       \
        size_t   pt_dstlen = y_dstlen;                                  \
        size_t   pt_dstpos = *(y_dstpos);                               \
        y_type   pt_srcval;                                             \
                                                                        \
        if (pt_dstpos + sizeof(y_type) <= pt_dstlen) {                  \
            pt_srcval = (y_type)(y_srcval);                             \
            memcpy(&pt_dstbuf[pt_dstpos], &pt_srcval, sizeof(pt_srcval)); \
            *(y_dstpos) += sizeof(y_type);                              \
        } else {                                                        \
            *(y_dstpos) = pt_dstlen + 1;                                \
        }                                                               \
    } while(0)

#else  /* #ifdef HAVE_ALIGNED_ACCESS_REQUIRED */

#define yfPutRiskyType(y_type, y_srcval, y_dstbuf, y_dstpos)            \
    do {                                                                \
        uint8_t *pt_dstbuf = (uint8_t *)y_dstbuf;                       \
        size_t   pt_dstpos = y_dstpos;                                  \
        y_type   pt_srcval;                                             \
        y_type  *pt_dest;                                               \
                                                                        \
        pt_srcval = (y_type)(y_srcval);                                 \
        pt_dest  = (y_type *)(&pt_dstbuf[pt_dstpos]);                   \
        *pt_dest = pt_srcval;                                           \
    } while(0)

#define yfPackType(y_type, y_srcval, y_dstbuf, y_dstpos, y_dstlen)      \
    do {                                                                \
        uint8_t *pt_dstbuf = (uint8_t *)y_dstbuf;                       \
        size_t   pt_dstlen = y_dstlen;                                  \
        size_t   pt_dstpos = *(y_dstpos);                               \
        y_type   pt_srcval;                                             \
        y_type  *pt_dest;                                               \
                                                                        \
        if (pt_dstpos + sizeof(y_type) <= pt_dstlen) {                  \
            pt_srcval = (y_type)(y_srcval);                             \
            pt_dest  = (y_type *)(&pt_dstbuf[pt_dstpos]);               \
            *pt_dest = pt_srcval;                                       \
            *(y_dstpos) += sizeof(y_type);                              \
        } else {                                                        \
            *(y_dstpos) = pt_dstlen + 1;                                \
        }                                                               \
    } while(0)

#endif  /* #else of #ifdef HAVE_ALIGNED_ACCESS_REQUIRED */



typedef struct yfDPIContext_st {
    GHashTable  *dpiActiveHash;
    uint16_t     dpi_user_limit;
    uint16_t     dpi_total_limit;
    gboolean     dpiInitialized;
    gboolean     dpiApplabelOnly;
} yfDPIContext_t;

typedef struct pluginRegex_st {
    char  *ruleName;
    char  *ruleRegex;
} pluginRegex_t;

typedef struct pluginTemplate_st {
    char *templateName;
    GArray *templateElements;
} pluginTemplate_t;

typedef struct pluginExtras_st {
    GArray  *pluginRegexes;
    GArray  *pluginTemplates;
} pluginExtras_t;

/**
 * A YAF Deep Packet Inspection Structure.  Holds offsets in the payload as to
 * important stuff that we want to capture (see protocol PCRE rule files)
 *
 */

typedef struct yfDPIData_st {
    /* offset in the payload to the good stuff */
    unsigned int   dpacketCapt;
    /* id of the field we found */
    uint16_t       dpacketID;
    /* length of good stuff */
    uint16_t       dpacketCaptLen;
} yfDPIData_t;

typedef struct ypDPIFlowCtx_st {
    /* this plugin's yaf context */
    yfDPIContext_t  *yfctx;
    yfDPIData_t     *dpi;
    /* keep track of how much we're exporting per flow */
    size_t           dpi_len;
    /* For Bi-Directional - need to know how many in fwd payload */
    uint8_t          captureFwd;
    /* Total Captures Fwd & Rev */
    uint8_t          dpinum;
    /* Primarily for Uniflow - Since we don't know if it's a FWD or REV flow
     * this is set to know where to start in the dpi array */
    uint8_t          startOffset;
    /* For Lists - we need to keep a ptr around so we can free it after
     * fBufAppend */
    void            *rec;
    /* extra buffer mainly for DNS stuff for now */
    uint8_t         *exbuf;
} ypDPIFlowCtx_t;


/*
 *  Defines the prototype signature of the function that each appLabel plug-in
 *  function must define.  The function scans the payload and returns an
 *  appLabel or returns 0 if the payload does not match its rules.
 *
 *  The function's parameters are:
 *
 *  -- payload the packet payload
 *  -- payloadSize size of the packet payload
 *  -- flow a pointer to the flow state structure
 *  -- val a pointer to biflow state (used for forward vs reverse)
 *
 */
uint16_t
ydpScanPayload(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val);

/*
 *  The type of the ydpScanPayload() function.
 */
typedef uint16_t (*ydpScanPayload_fn)(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val);

/*
 *  Defines the prototype signature of an optional function that each appLabel
 *  plug-in may define.  The function is called when the plugin is first
 *  loaded and allows the plugin to initialize itself.
 *
 *  The function is passed the name and the arguments that were provided in
 *  the configuration file.  This is the only time the plug-in has access to
 *  the arguments, and the plug-in must use them at this time or store the
 *  them for later use.
 *
 *  The configuration file allows multiple applabel rules to reference the
 *  same plugin.  When that happens, this function is called for each.  The
 *  plugin can use the applabel parameter to know which applabel is being
 *  initialized.
 *
 *  The function should return a positive value if it is ready to process
 *  data, zero if the plug-in wants to be ignored, and a negative value to
 *  indicate an error.  When returning a negative value, the plug-in should
 *  also provide an error message via the `err` parameter; if not, a generic
 *  error message is generated.
 *
 *  The function's parameters are:
 *
 *  -- argc number of string arguments in argv (always >= 1)
 *  -- argv string arguments for this plugin (the first is the library name)
 *  -- applabel the number of the applabel (port) that is being initialized
 *  -- applabelOnly TRUE if only application labeling was requested
 *  -- err a parameter used to return error information back to the caller
 *
 */
int
ydpInitialize(
    int        argc,
    char      *argv[],
    uint16_t   applabel,
    gboolean   applabelOnly,
    void      *extra,
    GError   **err);

/*
 *  The type of the ydpInitialize() function.
 */
typedef int (*ydpInitialize_fn)(
    int        argc,
    char      *argv[],
    uint16_t   applabel,
    gboolean   applabelOnly,
    void      *extra,
    GError   **err);


/**
 *  Calls pcre_compile() on `regexString` with `options` and returns the
 *  result.
 *
 *  If compilation succeeds, the compiled regex is returned.
 *
 *  If compilation fails and `err` is not NULL, its referent is set and will
 *  contain the error message from PCRE, a newline, `regexString`, another
 *  newline, and a pointer to the location in the regex of the error.  The
 *  function returns NULL.
 *
 *  @param regexString The PCRE regular expression to be compiled
 *  @param options The PCRE flags to pass to pcre_compile()
 *  @param err An error location or NULL.
 *  @return The compiled regex or NULL on error.
 */
pcre *
ydPcreCompile(
    const char  *regexString,
    int          options,
    GError     **err);

/**
 * @brief Find a Regex. Used by plugins.
 *
 * @param g GArray to search
 * @param target The target string to search for
 * @param err GError in case of error. Bad regex or not found
 * @return String on success, NULL on failure. Sets GError with more details.
 */
char *
ycFindPluginRegex(
    const GArray   *g,
    const char     *target,
    GError        **err);

/**
 * @brief Find and compile a Regex. Used by plugins.
 *
 * @param g GArray to search
 * @param target The target string to search for
 * @param options options to be used in PCRE compilation
 * @param err GError in case of error. Bad regex or not found
 * @return pcre* on success, NULL on failure. Sets GError with more details.
 */
pcre *
ycFindCompilePluginRegex(
    const GArray   *g,
    const char     *target,
    int             options,
    GError        **err);

/*
 *  Prints the forward and reverse payloads stored on `flow`, but no more than
 *  `maxBytes` for each direction.  If `maxBytes` is less than 0, the entire
 *  payload is printed.
 */
void
ydHexdumpPayload(
    const yfFlow_t *flow,
    int             maxBytes,
    const char     *title);

#ifdef YAF_ENABLE_DPI
int16_t
ycEnableElement(
    fbInfoElementSpec_t  *spec,
    const char           *elementName);

int16_t
ycEnableElements(
    fbInfoElementSpec_t  *spec,
    const GArray         *pluginTemplates,
    const char           *templateName);

/**
 * token concatinates to get the spec and stringifys to get the dpi templates'
 * name. runs ycEnableLements
 *
 */
#define YC_ENABLE_ELEMENTS(TEMPLATE, PLUGINTEMPLATES)                   \
    ycEnableElements(TEMPLATE ## _spec, PLUGINTEMPLATES, #TEMPLATE)




/*
 *  Defines the prototype signature of the function that each DPI plug-in must
 *  provide.
 */
void *
ydpProcessDPI(
    ypDPIFlowCtx_t       *flowContext,
    fbSubTemplateList_t  *stl,
    yfFlow_t             *flow,
    uint8_t               fwdcap,
    uint8_t               totalcap);

/*
 *  The type of the ydpProcessDPI() function.
 */
typedef void *(*ydpProcessDPI_fn)(
    ypDPIFlowCtx_t       *flowContext,
    fbSubTemplateList_t  *stl,
    yfFlow_t             *flow,
    uint8_t               fwdcap,
    uint8_t               totalcap);

/*
 *  Defines the prototype signature of the function that each DPI plug-in must
 *  provide.
 */
gboolean
ydpAddTemplates(
    fbSession_t  *session,
    GError      **err);

/*
 *  The type of the ydpAddTemplates() function.
 */
typedef gboolean (*ydpAddTemplates_fn)(
    fbSession_t  *session,
    GError      **err);

/*
 *  Defines the prototype signature of the function that each DPI plug-in must
 *  provide.
 */
void
ydpFreeRec(
    ypDPIFlowCtx_t  *flowContext);

/*
 *  The type of the ydpFreeRec() function.
 */
typedef void (*ydpFreeRec_fn)(
    ypDPIFlowCtx_t  *flowContext);

fbInfoModel_t *
ydGetDPIInfoModel(
    void);

void
ydRunPluginRegex(
    yfFlow_t       *flow,
    const uint8_t  *pkt,
    size_t          caplen,
    pcre           *expression,
    uint32_t        offset,
    uint16_t        elementID,
    uint16_t        applabel);

uint16_t
ydInitTemplate(
    fbTemplate_t              **newTemplate,
    fbSession_t                *session,
    const fbInfoElementSpec_t  *spec,
    fbTemplateInfo_t           *mdInfo,
    uint16_t                    tid,
    uint32_t                    flags,
    GError                    **err);

void *
ydProcessGenericPlugin(
    ypDPIFlowCtx_t       *flowContext,
    fbSubTemplateList_t  *stl,
    yfFlow_t             *flow,
    uint8_t               fwdcap,
    uint8_t               totalcap,
    uint16_t              stlTID,
    const fbTemplate_t   *stlTemplate,
    const char           *blIEName);

const fbInfoElement_t *
ydLookupNamedBlByName(
    const fbInfoElement_t  *ie);

const fbInfoElement_t *
ydLookupNamedBlByID(
    uint32_t   ent,
    uint16_t   id);

#endif /* #if YAF_ENABLE_APPLABEL */
#endif  /* YAF_ENABLE_DPI */
#endif /* _YAF_DPI_PUBLIC_H_ */
