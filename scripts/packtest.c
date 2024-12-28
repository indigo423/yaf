/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  packtest.c
 *
 *  A simple program to test the yfPack*() and yfUnpack*() macros in
 *  yafDPIPlugin.h
 *
 *  ------------------------------------------------------------------------
 *  Authors: Mark Thomas
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
#include <yaf/yafcore.h>

/* Comment/Uncomment this to test the other form of the macros */
#define HAVE_ALIGNED_ACCESS_REQUIRED 1

#include <yaf/yafDPIPlugin.h>

#ifdef   YAF_ENABLE_APPLABEL

/* YAF_ENABLE_APPLABEL required for this test */

/* Type of the local `pos` variable. */
typedef int    bufpos_t;

/* Whether to use the yfPack() and yfUnpack() macros or use local
 * implementaitons of those functions.  This is useful for comparing the
 * output of the assembler.  gcc -S ... */

#ifndef USE_PACK_UNPACK_MACROS
#define USE_PACK_UNPACK_MACROS  0
#endif

/* To compare the output of the assembler, it is also possible to compile a
 * single function */

#ifndef COMPILE_ONLY_pack_uint32
#define COMPILE_ONLY_pack_uint32    0
#endif

#ifndef COMPILE_ONLY_unpack_uint32
#define COMPILE_ONLY_unpack_uint32  0
#endif

#ifndef COMPILE_ONLY_pack_uint16
#define COMPILE_ONLY_pack_uint16    0
#endif

#ifndef COMPILE_ONLY_unpack_uint16
#define COMPILE_ONLY_unpack_uint16  0
#endif

#ifndef COMPILE_ONLY_pack_uint8
#define COMPILE_ONLY_pack_uint8     0
#endif

#ifndef COMPILE_ONLY_unpack_uint8
#define COMPILE_ONLY_unpack_uint8   0
#endif

#ifndef COMPILE_ONLY_pack_array
#define COMPILE_ONLY_pack_array     0
#endif

#ifndef COMPILE_ONLY_putrisky_uint32
#define COMPILE_ONLY_putrisky_uint32    0
#endif

#ifndef COMPILE_ONLY_getrisky_uint32
#define COMPILE_ONLY_getrisky_uint32    0
#endif

#ifndef COMPILE_ONLY_putrisky_uint16
#define COMPILE_ONLY_putrisky_uint16    0
#endif

#ifndef COMPILE_ONLY_getrisky_uint16
#define COMPILE_ONLY_getrisky_uint16    0
#endif

#ifndef COMPILE_ONLY_putrisky_uint8
#define COMPILE_ONLY_putrisky_uint8     0
#endif

#ifndef COMPILE_ONLY_getrisky_uint8
#define COMPILE_ONLY_getrisky_uint8     0
#endif

#define ANY_COMPILE_ONLY                                                \
    (COMPILE_ONLY_pack_uint32 || COMPILE_ONLY_unpack_uint32 ||          \
     COMPILE_ONLY_pack_uint16 || COMPILE_ONLY_unpack_uint16 ||          \
     COMPILE_ONLY_pack_uint8  || COMPILE_ONLY_unpack_uint8  ||          \
     COMPILE_ONLY_pack_array ||                                         \
     COMPILE_ONLY_putrisky_uint32 || COMPILE_ONLY_getrisky_uint32 ||    \
     COMPILE_ONLY_putrisky_uint16 || COMPILE_ONLY_getrisky_uint16 ||    \
     COMPILE_ONLY_putrisky_uint8  || COMPILE_ONLY_getrisky_uint8)


/* declarations */
void
pack_uint32(
    const uint32_t  value,
    uint8_t        *dstbuf,
    bufpos_t       *dstpos,
    size_t          dstlen);
void
unpack_uint32(
    uint32_t       *value,
    const uint8_t  *srcbuf,
    bufpos_t       *srcpos,
    size_t          srclen);
void
pack_uint16(
    const uint16_t  value,
    uint8_t        *dstbuf,
    bufpos_t       *dstpos,
    size_t          dstlen);
void
unpack_uint16(
    uint16_t       *value,
    const uint8_t  *srcbuf,
    bufpos_t       *srcpos,
    size_t          srclen);
void
pack_uint8(
    const uint8_t   value,
    uint8_t        *dstbuf,
    bufpos_t       *dstpos,
    size_t          dstlen);
void
unpack_uint8(
    uint8_t        *value,
    const uint8_t  *srcbuf,
    bufpos_t       *srcpos,
    size_t          srclen);
void
pack_array(
    const uint8_t  *srcbuf,
    size_t          srclen,
    uint8_t        *dstbuf,
    bufpos_t       *dstpos,
    size_t          dstlen);
void
putrisky_uint32(
    const uint32_t  value,
    uint8_t        *dstbuf,
    bufpos_t        dstpos);
void
getrisky_uint32(
    uint32_t       *value,
    const uint8_t  *srcbuf,
    bufpos_t        srcpos);
void
putrisky_uint16(
    const uint16_t  value,
    uint8_t        *dstbuf,
    bufpos_t        dstpos);
void
getrisky_uint16(
    uint16_t       *value,
    const uint8_t  *srcbuf,
    bufpos_t        srcpos);
void
putrisky_uint8(
    const uint8_t   value,
    uint8_t        *dstbuf,
    bufpos_t        dstpos);
void
getrisky_uint8(
    uint8_t        *value,
    const uint8_t  *srcbuf,
    bufpos_t        srcpos);


#if !ANY_COMPILE_ONLY

/* print an error message and exit */
static void
fatal(
    int         line,
    const char *format,
    ...
) __attribute__((format (printf, 2, 3)));



/* values to copy into the buffer */
#define TEST_U32  0x1a2b3c4d
#define TEST_U16  0x7698
#define TEST_U8   0xd3

/* report a fatal error on a particular line */
#define FATAL(...)                              \
    fatal(__LINE__, __VA_ARGS__)

/* fatal error if (buffer[position] != expected) */
#define CHECK_BUF(buffer, position, expected)                           \
    do {                                                                \
        if (buffer[position] != expected) {                             \
            FATAL("%s[%u] has value %#02x; expect value was %#02x",     \
                  #buffer, (unsigned int)position,                      \
                  buffer[position], expected);                          \
        }                                                               \
    } while(0)


/* print an error message and exit */
static void
fatal(
    int         line,
    const char *format,
    ...)
{
    va_list args;

    va_start(args, format);
    fprintf(stderr, "Fatal error on line %d: ", line);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);

    exit(EXIT_FAILURE);
}

#endif  /* ANY_COMPILE_ONLY */



#if !ANY_COMPILE_ONLY || COMPILE_ONLY_pack_uint32
void
pack_uint32(
    const uint32_t  value,
    uint8_t        *dstbuf,
    bufpos_t       *dstpos,
    size_t          dstlen)
{
#if   USE_PACK_UNPACK_MACROS

    yfPackU32(value, dstbuf, dstpos, dstlen);

#else

    if (*dstpos + sizeof(value) > dstlen) {
        *dstpos = 1 + dstlen;
    } else {
        *((uint32_t *)(dstbuf + *dstpos)) = value;
        *dstpos += sizeof(value);
    }

#endif  /* USE_PACK_UNPACK_MACROS */
}
#endif  /* !ANY_COMPILE_ONLY || COMPILE_ONLY_pack_uint32 */



#if !ANY_COMPILE_ONLY || COMPILE_ONLY_unpack_uint32
void
unpack_uint32(
    uint32_t       *value,
    const uint8_t  *srcbuf,
    bufpos_t       *srcpos,
    size_t          srclen)
{
#if   USE_PACK_UNPACK_MACROS

    yfUnpackU32(value, srcbuf, srcpos, srclen);

#else

    if (*srcpos + sizeof(*value) > srclen) {
        *value = 0;
        *srcpos = 1 + srclen;
    } else {
        *value = ntohl(*((uint32_t *)(srcbuf + *srcpos)));
        *srcpos += sizeof(*value);
    }

#endif  /* USE_PACK_UNPACK_MACROS */
}
#endif  /* #if !ANY_COMPILE_ONLY || COMPILE_ONLY_unpack_uint32 */



#if !ANY_COMPILE_ONLY || COMPILE_ONLY_pack_uint16
void
pack_uint16(
    const uint16_t  value,
    uint8_t        *dstbuf,
    bufpos_t       *dstpos,
    size_t          dstlen)
{
#if   USE_PACK_UNPACK_MACROS

    yfPackU16(value, dstbuf, dstpos, dstlen);

#else

    if (*dstpos + sizeof(value) > dstlen) {
        *dstpos = 1 + dstlen;
    } else {
        *((uint16_t *)(dstbuf + *dstpos)) = value;
        *dstpos += sizeof(value);
    }

#endif  /* USE_PACK_UNPACK_MACROS */
}
#endif  /* #if !ANY_COMPILE_ONLY || COMPILE_ONLY_pack_uint16 */



#if !ANY_COMPILE_ONLY || COMPILE_ONLY_unpack_uint16
void
unpack_uint16(
    uint16_t       *value,
    const uint8_t  *srcbuf,
    bufpos_t       *srcpos,
    size_t          srclen)
{
#if   USE_PACK_UNPACK_MACROS

    yfUnpackU16(value, srcbuf, srcpos, srclen);

#else

    if (*srcpos + sizeof(*value) > srclen) {
        *value = 0;
        *srcpos = 1 + srclen;
    } else {
        *value = ntohs(*((uint16_t *)(srcbuf + *srcpos)));
        *srcpos += sizeof(*value);
    }

#endif  /* USE_PACK_UNPACK_MACROS */
}
#endif  /* #if !ANY_COMPILE_ONLY || COMPILE_ONLY_unpack_uint16 */



#if !ANY_COMPILE_ONLY || COMPILE_ONLY_pack_uint8
void
pack_uint8(
    const uint8_t   value,
    uint8_t        *dstbuf,
    bufpos_t       *dstpos,
    size_t          dstlen)
{
#if   USE_PACK_UNPACK_MACROS

    yfPackU8(value, dstbuf, dstpos, dstlen);

#else

    if (*dstpos + sizeof(value) > dstlen) {
        *dstpos = 1 + dstlen;
    } else {
        *((uint8_t *)(dstbuf + *dstpos)) = value;
        *dstpos += sizeof(value);
    }

#endif  /* USE_PACK_UNPACK_MACROS */
}
#endif  /* #if !ANY_COMPILE_ONLY || COMPILE_ONLY_pack_uint8 */



#if !ANY_COMPILE_ONLY || COMPILE_ONLY_unpack_uint8
void
unpack_uint8(
    uint8_t        *value,
    const uint8_t  *srcbuf,
    bufpos_t       *srcpos,
    size_t          srclen)
{
#if   USE_PACK_UNPACK_MACROS

    yfUnpackU8(value, srcbuf, srcpos, srclen);

#else

    if (*srcpos + sizeof(*value) > srclen) {
        *value = 0;
        *srcpos = 1 + srclen;
    } else {
        *value = (*((uint8_t *)(srcbuf + *srcpos)));
        *srcpos += sizeof(*value);
    }

#endif  /* USE_PACK_UNPACK_MACROS */
}
#endif  /* #if !ANY_COMPILE_ONLY || COMPILE_ONLY_unpack_uint8 */



#if !ANY_COMPILE_ONLY || COMPILE_ONLY_pack_array
void
pack_array(
    const uint8_t  *srcbuf,
    size_t          srclen,
    uint8_t        *dstbuf,
    bufpos_t       *dstpos,
    size_t          dstlen)
{
#if   USE_PACK_UNPACK_MACROS

    yfPackArrayU8(srcbuf, srclen, dstbuf, dstpos, dstlen);

#else

    if (*dstpos + srclen > dstlen) {
        *dstpos = 1 + dstlen;
    } else {
        memcpy(dstbuf + *dstpos, srcbuf, srclen);
        *dstpos += srclen;
    }

#endif  /* USE_PACK_UNPACK_MACROS */
}
#endif  /* #if !ANY_COMPILE_ONLY || COMPILE_ONLY_pack_array */



#if !ANY_COMPILE_ONLY || COMPILE_ONLY_putrisky_uint32
void
putrisky_uint32(
    const uint32_t  value,
    uint8_t        *dstbuf,
    bufpos_t        dstpos)
{
#if   USE_PACK_UNPACK_MACROS

    yfPutRiskyU32(value, dstbuf, dstpos);

#else

    *((uint32_t *)(dstbuf + dstpos)) = value;

#endif  /* USE_PACK_UNPACK_MACROS */
}
#endif  /* !ANY_COMPILE_ONLY || COMPILE_ONLY_putrisky_uint32 */



#if !ANY_COMPILE_ONLY || COMPILE_ONLY_getrisky_uint32
void
getrisky_uint32(
    uint32_t       *value,
    const uint8_t  *srcbuf,
    bufpos_t        srcpos)
{
#if   USE_PACK_UNPACK_MACROS

    yfGetRiskyU32(value, srcbuf, srcpos);

#else

    *value = ntohl(*((uint32_t *)(srcbuf + srcpos)));

#endif  /* USE_PACK_UNPACK_MACROS */
}
#endif  /* !ANY_COMPILE_ONLY || COMPILE_ONLY_getrisky_uint32 */



#if !ANY_COMPILE_ONLY || COMPILE_ONLY_putrisky_uint16
void
putrisky_uint16(
    const uint16_t  value,
    uint8_t        *dstbuf,
    bufpos_t        dstpos)
{
#if   USE_PACK_UNPACK_MACROS

    yfPutRiskyU16(value, dstbuf, dstpos);

#else

    *((uint16_t *)(dstbuf + dstpos)) = value;

#endif  /* USE_PACK_UNPACK_MACROS */
}
#endif  /* !ANY_COMPILE_ONLY || COMPILE_ONLY_putrisky_uint16 */



#if !ANY_COMPILE_ONLY || COMPILE_ONLY_getrisky_uint16
void
getrisky_uint16(
    uint16_t       *value,
    const uint8_t  *srcbuf,
    bufpos_t        srcpos)
{
#if   USE_PACK_UNPACK_MACROS

    yfGetRiskyU16(value, srcbuf, srcpos);

#else

    *value = ntohs(*((uint16_t *)(srcbuf + srcpos)));

#endif  /* USE_PACK_UNPACK_MACROS */
}
#endif  /* !ANY_COMPILE_ONLY || COMPILE_ONLY_getrisky_uint16 */



#if !ANY_COMPILE_ONLY || COMPILE_ONLY_putrisky_uint8
void
putrisky_uint8(
    const uint8_t   value,
    uint8_t        *dstbuf,
    bufpos_t        dstpos)
{
#if   USE_PACK_UNPACK_MACROS

    yfPutRiskyU8(value, dstbuf, dstpos);

#else

    *((uint8_t *)(dstbuf + dstpos)) = value;

#endif  /* USE_PACK_UNPACK_MACROS */
}
#endif  /* !ANY_COMPILE_ONLY || COMPILE_ONLY_putrisky_uint8 */



#if !ANY_COMPILE_ONLY || COMPILE_ONLY_getrisky_uint8
void
getrisky_uint8(
    uint8_t        *value,
    const uint8_t  *srcbuf,
    bufpos_t        srcpos)
{
#if   USE_PACK_UNPACK_MACROS

    yfGetRiskyU8(value, srcbuf, srcpos);

#else

    *value = *((uint8_t *)(srcbuf + srcpos));

#endif  /* USE_PACK_UNPACK_MACROS */
}
#endif  /* !ANY_COMPILE_ONLY || COMPILE_ONLY_getrisky_uint8 */



#if !ANY_COMPILE_ONLY

int
main(
    int     argc,
    char   *argv[])
{
    /* to test yfPackArrayU8() */
    const uint8_t data[] = {0x1a, 0x2b, 0x3c, 0x4d, 0x69, 0x78};

    /* the buffer to be used for pack/unpack */
    uint8_t buf[127];

    /* position into buf */
    bufpos_t pos;

    /* initial values */
    uint8_t initval = 0x5e;
    uint8_t numfill = 0xc8;

    /* number to packed / unpacked */
    union number_un {
        uint8_t   array[4];
        uint32_t  u32;
        uint16_t  u16;
        uint8_t   u8;
    } number;

    /* counters; loopers */
    unsigned int count;
    unsigned int i;


#if USE_PACK_UNPACK_MACROS
    printf("Macros are enabled\n");
#else
    printf("Macros are disabled\n");
#endif
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
    printf("Aligned access is required\n");
#else
    printf("Aligned access is not required\n");
#endif



    /*  **********************************************************  */

    /* Test packing / unpacking a uint32_t */

    memset(buf, initval, sizeof(buf));

    memset(&number, numfill, sizeof(number));
    number.u32 = TEST_U32;

    /* pack */
    count = 0;
    pos = 0;
    for (;;) {
        pack_uint32(number.u32, buf, &pos, sizeof(buf));
        if (1 + sizeof(buf) == pos) {
            break;
        }
        if (pos < (int)sizeof(buf)) {
            CHECK_BUF(buf, pos, initval);
        }
        ++count;
    }

    if (count != sizeof(buf) / sizeof(uint32_t)) {
        FATAL("Packed %u uin32_t values; expected to pack %lu",
              count, sizeof(buf) / sizeof(uint32_t));
    }

    /* check buffer contents */
    pos = 0;
    for (i = 0; i < count; ++i) {
        /* Since we do not byte swap when packing, we can check the buffer's
         * contents without needing to know the byte order; the #else branch
         * should always be used */
#if   0 && G_BYTE_ORDER == LITTLE_ENDIAN
        CHECK_BUF(buf, pos, number.array[3]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[2]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[1]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[0]);
        ++pos;
#else  /* G_BYTE_ORDER */
        CHECK_BUF(buf, pos, number.array[0]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[1]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[2]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[3]);
        ++pos;
#endif  /* G_BYTE_ORDER */
    }
    /* leftover should be untouched */
    while (pos < (int)sizeof(buf)) {
        CHECK_BUF(buf, pos, initval);
        ++pos;
    }

    /* unpack */
    count = 0;
    pos = 0;
    for (;;) {
        memset(&number, numfill, sizeof(number));
        unpack_uint32(&number.u32, buf, &pos, sizeof(buf));
        if (1 + sizeof(buf) == pos) {
            break;
        }
        /* Since packing does not byte-swap but unpacking does, we byte-swap
         * the value to check its value */
        if (ntohl(number.u32) != TEST_U32) {
            FATAL("Value #%u at pos %u has value %#x; expected to get %#x",
                  count, (unsigned int)pos, ntohl(number.u32), TEST_U32);
        }
        ++count;
    }

    if (number.u32 != 0) {
        FATAL("At end of buffer, unpacked value %#x; expected 0",
              number.u32);
    }

    if (count != sizeof(buf) / sizeof(uint32_t)) {
        FATAL("Unpacked %u uin32_t values; expected to unpack %lu",
              count, sizeof(buf) / sizeof(uint32_t));
    }



    /*  **********************************************************  */

    /* Test packing / unpacking a uint16_t */

    memset(buf, initval, sizeof(buf));

    memset(&number, numfill, sizeof(number));
    number.u16 = TEST_U16;

    /* pack */
    count = 0;
    pos = 0;
    for (;;) {
        pack_uint16(number.u16, buf, &pos, sizeof(buf));
        if (1 + sizeof(buf) == pos) {
            break;
        }
        if (pos < (int)sizeof(buf)) {
            CHECK_BUF(buf, pos, initval);
        }
        ++count;
    }

    if (count != sizeof(buf) / sizeof(uint16_t)) {
        FATAL("Packed %u uin16_t values; expected to pack %lu",
              count, sizeof(buf) / sizeof(uint16_t));
    }

    /* check buffer contents */
    pos = 0;
    for (i = 0; i < count; ++i) {
        /* Since we do not byte swap when packing, we can check the buffer's
         * contents without needing to know the byte order; the #else branch
         * should always be used */
#if   0 && G_BYTE_ORDER == LITTLE_ENDIAN
        CHECK_BUF(buf, pos, number.array[1]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[0]);
        ++pos;
#else  /* G_BYTE_ORDER */
        CHECK_BUF(buf, pos, number.array[0]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[1]);
        ++pos;
#endif  /* G_BYTE_ORDER */
    }
    /* leftover should be untouched */
    while (pos < (int)sizeof(buf)) {
        CHECK_BUF(buf, pos, initval);
        ++pos;
    }

    /* unpack */
    count = 0;
    pos = 0;
    for (;;) {
        memset(&number, numfill, sizeof(number));
        unpack_uint16(&number.u16, buf, &pos, sizeof(buf));
        if (1 + sizeof(buf) == pos) {
            break;
        }
        /* Since packing does not byte-swap but unpacking does, we byte-swap
         * the value to check its value */
        if (ntohs(number.u16) != TEST_U16) {
            FATAL("Value #%u at pos %u has value %#x; expected to get %#x",
                  count, (unsigned int)pos, ntohs(number.u16), TEST_U16);
        }
        CHECK_BUF(number.array, 2, numfill);
        CHECK_BUF(number.array, 3, numfill);
        ++count;
    }

    if (number.u16 != 0) {
        FATAL("At end of buffer, unpacked value %#x; expected 0",
              number.u16);
    }
    CHECK_BUF(number.array, 2, numfill);
    CHECK_BUF(number.array, 3, numfill);

    if (count != sizeof(buf) / sizeof(uint16_t)) {
        FATAL("Unpacked %u uin16_t values; expected to unpack %lu",
              count, sizeof(buf) / sizeof(uint16_t));
    }



    /*  **********************************************************  */

    /* Test packing / unpacking a uint8_t */

    memset(buf, initval, sizeof(buf));

    memset(&number, numfill, sizeof(number));
    number.u8 = TEST_U8;

    /* pack */
    count = 0;
    pos = 0;
    for (;;) {
        pack_uint8(number.u8, buf, &pos, sizeof(buf));
        if (1 + sizeof(buf) == pos) {
            break;
        }
        if (pos < (int)sizeof(buf)) {
            CHECK_BUF(buf, pos, initval);
        }
        ++count;
    }

    if (count != sizeof(buf) / sizeof(uint8_t)) {
        FATAL("Packed %u uint8_t values; expected to pack %lu",
              count, sizeof(buf) / sizeof(uint8_t));
    }

    /* check buffer contents */
    pos = 0;
    for (i = 0; i < count; ++i) {
        CHECK_BUF(buf, pos, number.array[0]);
        ++pos;
    }
    /* leftover should be untouched */
    while (pos < (int)sizeof(buf)) {
        CHECK_BUF(buf, pos, initval);
        ++pos;
    }

    /* unpack */
    count = 0;
    pos = 0;
    for (;;) {
        memset(&number, numfill, sizeof(number));
        unpack_uint8(&number.u8, buf, &pos, sizeof(buf));
        if (1 + sizeof(buf) == pos) {
            break;
        }
        if (number.u8 != TEST_U8) {
            FATAL("Value #%u at pos %u has value %#x; expected to get %#x",
                  count, (unsigned int)pos, number.u8, TEST_U8);
        }
        CHECK_BUF(number.array, 1, numfill);
        CHECK_BUF(number.array, 2, numfill);
        CHECK_BUF(number.array, 3, numfill);
        ++count;
    }

    if (number.u8 != 0) {
        FATAL("At end of buffer, unpacked value %#x; expected 0",
              number.u8);
    }
    if (count != sizeof(buf) / sizeof(uint8_t)) {
        FATAL("Unpacked %u uin8_t values; expected to unpack %lu",
              count, sizeof(buf) / sizeof(uint8_t));
    }



    /*  **********************************************************  */

    /* Test packing an array */

    memset(buf, initval, sizeof(buf));

    /* pack */
    count = 0;
    pos = 0;
    for (;;) {
        pack_array(data, sizeof(data), buf, &pos, sizeof(buf));
        if (1 + sizeof(buf) == pos) {
            break;
        }
        if (pos < (int)sizeof(buf)) {
            CHECK_BUF(buf, pos, initval);
        }
        ++count;
    }

    if (count != sizeof(buf) / sizeof(data)) {
        FATAL("Packed %u arry values; expected to pack %lu",
              count, sizeof(buf) / sizeof(data));
    }

    /* check buffer contents */
    pos = 0;
    for (i = 0; i < count; ++i) {
        size_t j;
        for (j = 0; j < sizeof(data); ++j) {
            if (buf[pos] != data[j]) {
                FATAL("Value #%u[%zu] at pos %u has value %#02x;"
                      " expected to get %#02x",
                      count, j, (unsigned int)pos, buf[pos], data[j]);
            }
            ++pos;
        }
    }
    /* leftover should be untouched */
    while (pos < (int)sizeof(buf)) {
        CHECK_BUF(buf, pos, initval);
        ++pos;
    }



    /*  **********************************************************  */

    /* Test putting / getting a uint32_t */

    memset(buf, initval, sizeof(buf));

    memset(&number, numfill, sizeof(number));
    number.u32 = TEST_U32;

    /* put */
    count = 0;
    pos = 0;
    while (pos <= (int)(sizeof(buf) - sizeof(uint32_t))) {
        putrisky_uint32(number.u32, buf, pos);
        pos += sizeof(uint32_t);
        if (pos < (int)sizeof(buf)) {
            CHECK_BUF(buf, pos, initval);
        }
        ++count;
    }

    if (count != sizeof(buf) / sizeof(uint32_t)) {
        FATAL("Packed %u uin32_t values; expected to pack %lu",
              count, sizeof(buf) / sizeof(uint32_t));
    }

    /* check buffer contents */
    pos = 0;
    for (i = 0; i < count; ++i) {
        /* Since we do not byte swap when packing, we can check the buffer's
         * contents without needing to know the byte order; the #else branch
         * should always be used */
#if   0 && G_BYTE_ORDER == LITTLE_ENDIAN
        CHECK_BUF(buf, pos, number.array[3]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[2]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[1]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[0]);
        ++pos;
#else  /* G_BYTE_ORDER */
        CHECK_BUF(buf, pos, number.array[0]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[1]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[2]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[3]);
        ++pos;
#endif  /* G_BYTE_ORDER */
    }
    /* leftover should be untouched */
    while (pos < (int)sizeof(buf)) {
        CHECK_BUF(buf, pos, initval);
        ++pos;
    }

    /* get */
    count = 0;
    pos = 0;
    while (pos <= (int)(sizeof(buf) - sizeof(uint32_t))) {
        memset(&number, numfill, sizeof(number));
        getrisky_uint32(&number.u32, buf, pos);
        /* Since packing does not byte-swap but unpacking does, we byte-swap
         * the value to check its value */
        if (ntohl(number.u32) != TEST_U32) {
            FATAL("Value #%u at pos %u has value %#x; expected to get %#x",
                  count, (unsigned int)pos, ntohl(number.u32), TEST_U32);
        }
        pos += sizeof(uint32_t);
        ++count;
    }

    if (count != sizeof(buf) / sizeof(uint32_t)) {
        FATAL("Unpacked %u uin32_t values; expected to unpack %lu",
              count, sizeof(buf) / sizeof(uint32_t));
    }



    /*  **********************************************************  */

    /* Test putting / getting a uint16_t */

    memset(buf, initval, sizeof(buf));

    memset(&number, numfill, sizeof(number));
    number.u16 = TEST_U16;

    /* put */
    count = 0;
    pos = 0;
    while (pos <= (int)(sizeof(buf) - sizeof(uint16_t))) {
        putrisky_uint16(number.u16, buf, pos);
        pos += sizeof(uint16_t);
        if (pos < (int)sizeof(buf)) {
            CHECK_BUF(buf, pos, initval);
        }
        ++count;
    }

    if (count != sizeof(buf) / sizeof(uint16_t)) {
        FATAL("Packed %u uin16_t values; expected to pack %lu",
              count, sizeof(buf) / sizeof(uint16_t));
    }

    /* check buffer contents */
    pos = 0;
    for (i = 0; i < count; ++i) {
        /* Since we do not byte swap when packing, we can check the buffer's
         * contents without needing to know the byte order; the #else branch
         * should always be used */
#if   0 && G_BYTE_ORDER == LITTLE_ENDIAN
        CHECK_BUF(buf, pos, number.array[1]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[0]);
        ++pos;
#else  /* G_BYTE_ORDER */
        CHECK_BUF(buf, pos, number.array[0]);
        ++pos;
        CHECK_BUF(buf, pos, number.array[1]);
        ++pos;
#endif  /* G_BYTE_ORDER */
    }
    /* leftover should be untouched */
    while (pos < (int)sizeof(buf)) {
        CHECK_BUF(buf, pos, initval);
        ++pos;
    }

    /* get */
    count = 0;
    pos = 0;
    while (pos <= (int)(sizeof(buf) - sizeof(uint16_t))) {
        memset(&number, numfill, sizeof(number));
        getrisky_uint16(&number.u16, buf, pos);
        /* Since packing does not byte-swap but unpacking does, we byte-swap
         * the value to check its value */
        if (ntohs(number.u16) != TEST_U16) {
            FATAL("Value #%u at pos %u has value %#x; expected to get %#x",
                  count, (unsigned int)pos, ntohs(number.u16), TEST_U16);
        }
        CHECK_BUF(number.array, 2, numfill);
        CHECK_BUF(number.array, 3, numfill);
        pos += sizeof(uint16_t);
        ++count;
    }

    if (count != sizeof(buf) / sizeof(uint16_t)) {
        FATAL("Unpacked %u uin16_t values; expected to unpack %lu",
              count, sizeof(buf) / sizeof(uint16_t));
    }



    /*  **********************************************************  */

    /* Test putting / getting a uint8_t */

    memset(buf, initval, sizeof(buf));

    memset(&number, numfill, sizeof(number));
    number.u8 = TEST_U8;

    /* put */
    count = 0;
    pos = 0;
    while (pos <= (int)(sizeof(buf) - sizeof(uint8_t))) {
        putrisky_uint8(number.u8, buf, pos);
        pos += sizeof(uint8_t);
        if (pos < (int)sizeof(buf)) {
            CHECK_BUF(buf, pos, initval);
        }
        ++count;
    }

    if (count != sizeof(buf) / sizeof(uint8_t)) {
        FATAL("Packed %u uin8_t values; expected to pack %lu",
              count, sizeof(buf) / sizeof(uint8_t));
    }

    /* check buffer contents */
    pos = 0;
    for (i = 0; i < count; ++i) {
        CHECK_BUF(buf, pos, number.array[0]);
        ++pos;
    }
    /* leftover should be untouched */
    while (pos < (int)sizeof(buf)) {
        CHECK_BUF(buf, pos, initval);
        ++pos;
    }

    /* get */
    count = 0;
    pos = 0;
    while (pos <= (int)(sizeof(buf) - sizeof(uint8_t))) {
        memset(&number, numfill, sizeof(number));
        getrisky_uint8(&number.u8, buf, pos);
        if (number.u8 != TEST_U8) {
            FATAL("Value #%u at pos %u has value %#x; expected to get %#x",
                  count, (unsigned int)pos, ntohs(number.u8), TEST_U8);
        }
        CHECK_BUF(number.array, 1, numfill);
        CHECK_BUF(number.array, 2, numfill);
        CHECK_BUF(number.array, 3, numfill);
        pos += sizeof(uint8_t);
        ++count;
    }

    if (count != sizeof(buf) / sizeof(uint8_t)) {
        FATAL("Unpacked %u uin8_t values; expected to unpack %lu",
              count, sizeof(buf) / sizeof(uint8_t));
    }



    /*  **********************************************************  */

    return 0;
}

#endif  /* !ANY_COMPILE_ONLY */

#else  /* #ifdef YAF_ENABLE_APPLABEL -- just after the #includes */

/* macros are only defined when YAF_ENABLE_APPLABEL is defined */

int
main(
    int     argc,
    char   *argv[])
{
    void(argc);

    printf("%s: configured without applabel. nothing to do\n",
          argv[0]);
    return 0;
}

#endif  /* #else of #ifdef YAF_ENABLE_APPLABEL */
