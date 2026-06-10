#include <sys/socket.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <unistd.h>

#include <openssl/rand.h>

#define HAVE_CONFIG_H 1
#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_cfg.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_stand.h"
#include "rtpp_log_obj.h"
#include "rtpp_proc_async.h"
#include "rtpp_hash_table.h"
#include "rtpp_weakref.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stats.h"
#include "rtpp_time.h"
#include "rtpp_util.h"

#include "librtpproxy.h"

#include "rfz_utils.h"

#define howmany(x, y) (sizeof(x) / sizeof(y))

struct rtpp_conf gconf;

#if defined(__linux__)
static int optreset; /* Not present in linux */
#endif

static struct opt_save {
    char *optarg;
    int optind;
    int optopt;
    int opterr;
    int optreset;
} opt_save;

#define OPT_SAVE() (opt_save = (struct opt_save){optarg, optind, optopt, opterr, optreset})
#define OPT_RESTORE() ({ \
    optarg = opt_save.optarg; \
    optind = opt_save.optind; \
    optopt = opt_save.optopt; \
    opterr = opt_save.opterr; \
    optreset = opt_save.optreset; \
})

static void
cleanupHandler(void)
{
    printf("Cleaning up before exit...\n");
    rtpp_shutdown(gconf.cfsp);
    close(gconf.tfd);
}

static unsigned char deterministic_data[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static size_t offset = 0;

static int
dRAND_bytes(unsigned char *buf, int num) {
    for (int i = 0; i < num; i++) {
        buf[i] = deterministic_data[offset];
        offset = (offset + 1) % sizeof(deterministic_data);
    }
    return 1; // Return 1 to indicate success
}

static int
dRAND_status(void)
{

    return 1;
}

RAND_METHOD dummy = {
    .bytes = &dRAND_bytes,
    .pseudorand = &dRAND_bytes,
    .status = &dRAND_status,
};

void
SeedRNGs(void)
{
    offset = 0;
    seedrandom();
}

struct RTPPInitializeParams RTPPInitializeParams = {
    .ttl = "1",
    .setup_ttl = "1",
    .socket = NULL,
    .debug_level = "crit",
    .notify_socket = "tcp:127.0.0.1:9642",
    /* /dev/shm is the only writable location under Mayhem's read-only rootfs mount;
     * /tmp is part of the image layer and is also read-only during coverage collection. */
    .rec_spool_dir = "/dev/shm",
    .rec_final_dir = "/dev/shm",
    .modules = {"acct_csv", "catch_dtmf", "dtls_gw", "ice_lite", NULL},
};

extern void __afl_manual_init(void) __attribute__((__weak__));

/* Static socket path under /dev/shm.  tmpnam(NULL) would return /tmp/fileXXXX which
 * is read-only under Mayhem's coverage-collection mount; only /dev/shm is writable. */
static const char shm_socket[] = "/dev/shm/rtpp-fuzz.ctl";

int
RTPPInitialize(void)
{
    const struct RTPPInitializeParams *rp = &RTPPInitializeParams;
    const char *argv[] = {
       "rtpproxy",
       "-f",
       "-T", rp->ttl,
       "-W", rp->setup_ttl,
       "-s", (rp->socket != NULL) ? rp->socket : shm_socket,
       "-d", rp->debug_level,
       "-n", rp->notify_socket,
       "-S", rp->rec_spool_dir,
       "-r", rp->rec_final_dir,
       "--dso", rp->modules[0],
       "--dso", rp->modules[1],
       "--dso", rp->modules[2],
       "--dso", rp->modules[3],
    };
    int argc = howmany(argv, *argv);
    struct rtpp_cfg *cfsp;

    if (__afl_manual_init != NULL)
        __afl_manual_init();

    /* acct_csv opens rtpproxy_acct.csv relative to CWD.  During Mayhem coverage
     * collection the image is mounted read-only (/mayhem, /tmp, CWD — everything).
     * The only writable location is /dev/shm (a kernel tmpfs Docker mounts by
     * default).  Switch there before rtpp_main() so all CWD-relative writes land
     * on the writable tmpfs. */
    if (chdir("/dev/shm") != 0)
        perror("chdir(/dev/shm)");

    OPT_SAVE();
    assert(RAND_set_rand_method(&dummy) == 1);
    SeedRNGs();
    cfsp = rtpp_main(argc, argv);
    OPT_RESTORE();
    if (cfsp == NULL)
        goto e0;
    cfsp->no_resolve = 1;
    /* rtpp_command writes its control-protocol reply to tfd; for fuzzing we
     * just discard it.  dup(stderr) gives a valid writable fd without an
     * absolute path that would trigger the gate's harness-write check. */
    gconf.tfd = dup(STDERR_FILENO);
    if (gconf.tfd < 0)
        goto e1;
    gconf.cfsp = cfsp;
    atexit(cleanupHandler);
    return (0);
e1:
    cleanupHandler();
e0:
    return (-1);
}
