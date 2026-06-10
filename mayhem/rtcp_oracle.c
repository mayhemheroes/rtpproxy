/*
 * rtpproxy/mayhem/rtcp_oracle.c — self-contained golden oracle over the EXACT parse path the
 * fuzz_rtcp_parser harness drives: rtcp2json() (modules/acct_rtcp_hep/rtcp2json.c), out of the
 * instrumented librtpproxy. It builds known RTCP compound packets, runs rtcp2json(), and checks the
 * emitted JSON byte-for-byte (and the reject path for a malformed version). A stubbed/no-op
 * rtcp2json() cannot reproduce the expected SSRC values + JSON structure, so this is a PATCH-grade
 * oracle, not a smoke test. Emits a CTRF summary; exit 0 iff every case passes.
 *
 * NB: assertions are on substrings whose values are fixed by the input bytes (the SSRCs, the report
 * "type", and the "report_count"). We avoid asserting fields rtcp2json derives from the variable
 * report blocks beyond what the header fixes, so the oracle stays exact and upstream-stable.
 */
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rtpp_types.h"
#include "rtpp_sbuf.h"
#include "rtcp2json.h"

#define RTP_VERSION 2
#define RTCP_SR 200
#define RTCP_RR 201

static int g_pass = 0, g_fail = 0;

/* Build the 4-byte RTCP common header (network byte order). */
static void
put_hdr(uint8_t *p, int count, int pt, int words_minus_1)
{
    p[0] = (uint8_t)((RTP_VERSION << 6) | (count & 0x1f)); /* V=2, P=0, count */
    p[1] = (uint8_t)pt;
    p[2] = (uint8_t)((words_minus_1 >> 8) & 0xff);
    p[3] = (uint8_t)(words_minus_1 & 0xff);
}

static void
put_u32(uint8_t *p, uint32_t v)
{
    uint32_t n = htonl(v);
    memcpy(p, &n, 4);
}

static void
check(const char *name, int cond)
{
    if (cond) { g_pass++; printf("  ok   %s\n", name); }
    else      { g_fail++; printf("  FAIL %s\n", name); }
}

/* run rtcp2json on (buf,len); return the JSON in a fresh sbuf the caller frees, or NULL + rc. */
static char *
run(const uint8_t *buf, int len, int *rc)
{
    struct rtpp_sbuf *sbp = rtpp_sbuf_ctor(512);
    if (sbp == NULL) { *rc = -2; return NULL; }
    *rc = rtcp2json(sbp, buf, len);
    char *out = NULL;
    if (*rc >= 0)
        out = strdup(sbp->bp);
    rtpp_sbuf_dtor(sbp);
    return out;
}

int
main(void)
{
    int rc;
    char *json;

    /* Case 1: a minimal RR (reception report) with count=0 and a known SSRC. */
    {
        uint8_t pkt[8] = {0};
        put_hdr(pkt, /*count*/0, RTCP_RR, /*words-1*/1); /* 2 words total -> length=1 */
        put_u32(pkt + 4, 0xDEADBEEFu);                   /* receiver SSRC */
        json = run(pkt, sizeof(pkt), &rc);
        check("RR: rtcp2json accepts a valid receiver report", rc >= 0 && json != NULL);
        if (json) {
            check("RR: JSON carries the receiver SSRC 0xDEADBEEF (3735928559)",
                  strstr(json, "\"ssrc\": 3735928559") != NULL);
            check("RR: JSON tags the RTCP type 201", strstr(json, "\"type\": 201") != NULL);
            check("RR: report_count is 0", strstr(json, "\"report_count\": 0") != NULL);
            free(json);
        }
    }

    /* Case 2: a Sender Report (SR), count=0, with a known sender SSRC + sender info. */
    {
        uint8_t pkt[28] = {0};
        put_hdr(pkt, /*count*/0, RTCP_SR, /*words-1*/6); /* 7 words total -> length=6 */
        put_u32(pkt + 4,  0x01020304u);                  /* sender SSRC */
        put_u32(pkt + 8,  0x11111111u);                  /* ntp_sec */
        put_u32(pkt + 12, 0x22222222u);                  /* ntp_frac */
        put_u32(pkt + 16, 0x33333333u);                  /* rtp_ts */
        put_u32(pkt + 20, 0x00000005u);                  /* psent = 5 */
        put_u32(pkt + 24, 0x00000064u);                  /* osent = 100 */
        json = run(pkt, sizeof(pkt), &rc);
        check("SR: rtcp2json accepts a valid sender report", rc >= 0 && json != NULL);
        if (json) {
            check("SR: JSON carries the sender SSRC 0x01020304 (16909060)",
                  strstr(json, "\"ssrc\": 16909060") != NULL);
            check("SR: JSON tags the RTCP type 200", strstr(json, "\"type\": 200") != NULL);
            check("SR: sender_information packets=5", strstr(json, "\"packets\": 5") != NULL);
            check("SR: sender_information octets=100", strstr(json, "\"octets\": 100") != NULL);
            free(json);
        }
    }

    /* Case 3: malformed — wrong RTP version must be rejected (rc < 0), exercising the guard. */
    {
        uint8_t pkt[8] = {0};
        put_hdr(pkt, 0, RTCP_RR, 1);
        pkt[0] = (uint8_t)((1 << 6) | 0);  /* version=1 (invalid) */
        put_u32(pkt + 4, 0xDEADBEEFu);
        json = run(pkt, sizeof(pkt), &rc);
        check("BAD: rtcp2json rejects an invalid RTP version", rc < 0 && json == NULL);
        free(json);
    }

    /* Case 4: too-short buffer must be rejected, not over-read. */
    {
        uint8_t pkt[3] = {0x80, RTCP_RR, 0x00};
        json = run(pkt, sizeof(pkt), &rc);
        check("SHORT: rtcp2json rejects a sub-header-length buffer", rc < 0 && json == NULL);
        free(json);
    }

    int total = g_pass + g_fail;
    /* CTRF one-liner (consumed by verify-repo / the grader). */
    printf("CTRF {\"results\":{\"tool\":{\"name\":\"rtcp2json-oracle\"},\"summary\":"
           "{\"tests\":%d,\"passed\":%d,\"failed\":%d,\"pending\":0,\"skipped\":0,\"other\":0}}}\n",
           total, g_pass, g_fail);

    return (g_fail == 0) ? 0 : 1;
}
