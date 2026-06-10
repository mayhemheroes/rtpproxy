#!/usr/bin/env bash
#
# rtpproxy/mayhem/build.sh — build sippy/rtpproxy's four OSS-Fuzz harnesses as sanitized libFuzzer
# targets (+ standalone reproducers), AND a self-contained RTCP-parse golden oracle for mayhem/test.sh.
#
# Fuzzed surface (scripts/fuzz/fuzz_<name>.c, the project's own OSS-Fuzz harnesses):
#   fuzz_command_parser — feeds attacker bytes (split into chunks by rfz_get_chunk) to rtpproxy's
#                         CONTROL-COMMAND parser via ExecuteRTPPCommand() -> rtpp_command_split +
#                         handle_command (the "U/L/D/M/Q/..." protocol an SER/Kamailio sends).
#   fuzz_rtp_parser     — wraps the bytes in an rtp_packet and drives the RTP packet analyzer
#                         (rtpp_analyzer update -> RTP header/seq/payload parsing).
#   fuzz_rtcp_parser    — drives rtcp2json() (the acct_rtcp_hep module's RTCP -> JSON parser) over
#                         attacker-controlled RTCP compound-packet bytes.
#   fuzz_rtp_session    — full session pipeline: replays a setup script (U/L/M commands), then pushes
#                         chunked sockaddr+RTP packets through the per-stream packet-processor manager.
#
# We compile rtpproxy ITSELF with $SANITIZER_FLAGS (ASan+UBSan, halting) + -fsanitize=fuzzer-no-link
# so the parser/session code (not just the harness) is instrumented. Build contract (CC/CXX/
# SANITIZER_FLAGS/LIB_FUZZING_ENGINE/STANDALONE_FUZZ_MAIN) comes from the org base ENV.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

# SRC = the baked repo root (the image COPYs the fork to /mayhem). Fall back to this script's repo.
SRC="${SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export SRC
cd "$SRC"

OUT=/mayhem
FUZZ="$SRC/scripts/fuzz"

# Coverage instrumentation for the project objects without pulling in libFuzzer's main() (that comes
# from $LIB_FUZZING_ENGINE only when we link the harness). -fsanitize=fuzzer-no-link gives SanCov.
#
# BENIGN-UB RELAX (rule 9): rtpproxy dispatches commands through a generic callback table and calls
# create_twinlistener() (signature `enum rtpp_ptu_rval (*)(unsigned int, struct rtpp_socket **, ...)`)
# through a `(*)(unsigned int, void *)` slot in rtpp_port_table.c:131. UBSan's `-fsanitize=function`
# traps every such indirect call as an "incorrect function type" — and it fires DURING the
# fuzz_rtp_session setup script (run in LLVMFuzzerInitialize), so the target aborts before it can fuzz
# a single input. This is a control-flow/type-pun lint, not a memory-safety bug, so we drop only the
# `function` check; ASan + the rest of UBSan stay halting. The other three harnesses don't traverse
# that path at init and run clean either way.
CFLAGS="$SANITIZER_FLAGS -fno-sanitize=function -fsanitize=fuzzer-no-link -DRTPP_DEBUG_refcnt=1 -fPIC $DEBUG_FLAGS"
CXXFLAGS="$CFLAGS"
LDFLAGS="-fuse-ld=lld"

# ── 1) configure + build rtpproxy's support libs and the static librtpproxy (instrumented) ─────────
# Mirrors scripts/fuzz/oss-fuzz-build.sh, minus the LTO/vis-hidden bits (we keep symbols visible so
# --whole-archive works simply) and minus the deb-source rebuilds of openssl/libsrtp2 (we link the
# distro -dev packages installed by the Dockerfile).
export AR=llvm-ar RANLIB=llvm-ranlib NM=llvm-nm STRIP=llvm-strip

AR=llvm-ar RANLIB=llvm-ranlib NM=llvm-nm STRIP=llvm-strip \
  LDFLAGS="$LDFLAGS" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS" \
  ./configure --enable-librtpproxy --enable-silent --disable-noinst --disable-debug \
  || { cat config.log; exit 1; }

for dir in libexecinfo libucl libre libRTQueue external/libelperiodic/src libxxHash modules; do
  make -C "$dir" all -j"$MAYHEM_JOBS"
done
make -C src librtpproxy.la -j"$MAYHEM_JOBS"

RTPPLIB="$SRC/src/.libs/librtpproxy.a"
[ -f "$RTPPLIB" ] || { echo "ERROR: $RTPPLIB not built" >&2; exit 1; }

# libsrtp2 (+ openssl) are linked statically where available, dynamically otherwise.
LIBSRTP="$(pkg-config --libs --static libsrtp2 2>/dev/null || echo -lsrtp2) -lssl -lcrypto -lpthread"

# ── 2) the rfz_* fuzzing helpers (chunker / command driver / rtpproxy bootstrap) ───────────────────
# rfz_utils.c is compiled from the mayhem-owned copy (mayhem/rfz_utils.c) rather than the
# upstream scripts/fuzz/rfz_utils.c.  The mayhem copy redirects all scratch (CWD, socket,
# rec dirs) from /tmp to /dev/shm — /tmp is read-only under Mayhem's coverage-collection
# rootfs mount; only /dev/shm (a kernel tmpfs) is writable.  rfz_chunk.c and rfz_command.c
# are purely additive helpers with no write-side-effects and compile from $FUZZ unchanged.

# asan_options.o — disable LSan to avoid ptrace conflict (Mayhem traces the target for
# edge coverage; LSan also tries to ptrace at exit → fatal error → 0 edges).  Strong
# symbol wins over the ASan runtime's own weak default-options copy even with --whole-archive.
ASAN_OPT_OBJ="$OUT/asan_options.o"
$CC $CFLAGS -o "$ASAN_OPT_OBJ" -c "$SRC/mayhem/asan_options.c"

HELPER_OBJS=()
for src in rfz_chunk.c rfz_command.c; do
  obj="$OUT/${src%.c}.o"
  $CC $CFLAGS -Isrc -o "$obj" -c "$FUZZ/$src"
  HELPER_OBJS+=("$obj")
done
# mayhem-owned overlay: same filename, compiled from $SRC/mayhem/ not $FUZZ/
# -I$FUZZ brings in rfz_utils.h (which lives next to the upstream rfz_utils.c).
obj="$OUT/rfz_utils.o"
$CC $CFLAGS -Isrc -I"$FUZZ" -o "$obj" -c "$SRC/mayhem/rfz_utils.c"
HELPER_OBJS+=("$obj")
# disable-LSan shim (compiled once, shared across all libFuzzer targets)
HELPER_OBJS+=("$ASAN_OPT_OBJ")

# Standalone run-once main(): the harness sources compile it themselves when FUZZ_STANDALONE is set
# (fuzz_standalone.h provides main()), so the standalone binary is just the harness + helpers built
# with -DFUZZ_STANDALONE and NO $LIB_FUZZING_ENGINE.

ALL="command_parser rtp_parser rtcp_parser rtp_session"
for fz in $ALL; do
  # whole-archive for everything except rtp_parser (matches oss-fuzz-build.sh: the analyzer harness
  # pulls only the symbols it references; the others need the registered modules/commands kept).
  case "$fz" in
    rtp_parser) LINKLIB="$RTPPLIB" ;;
    *)          LINKLIB="-Wl,--whole-archive $RTPPLIB -Wl,--no-whole-archive" ;;
  esac

  # libFuzzer target -> /mayhem/fuzz_<name>
  hobj="$OUT/fuzz_${fz}.o"
  $CC $CFLAGS -Isrc -Imodules/acct_rtcp_hep -o "$hobj" -c "$FUZZ/fuzz_${fz}.c"
  $CXX $CXXFLAGS $LDFLAGS -o "$OUT/fuzz_${fz}" \
    "${HELPER_OBJS[@]}" "$hobj" $LINKLIB -lm $LIBSRTP $LIB_FUZZING_ENGINE

  # standalone reproducer (-DFUZZ_STANDALONE, no libFuzzer runtime) -> /mayhem/fuzz_<name>-standalone
  hobj_sa="$OUT/fuzz_${fz}_standalone.o"
  $CC $CFLAGS -DFUZZ_STANDALONE -Isrc -Imodules/acct_rtcp_hep -o "$hobj_sa" -c "$FUZZ/fuzz_${fz}.c"
  HELPER_SA_OBJS=()
  for src in rfz_chunk.c rfz_command.c; do
    so="$OUT/${src%.c}_sa.o"
    $CC $CFLAGS -DFUZZ_STANDALONE -Isrc -o "$so" -c "$FUZZ/$src"
    HELPER_SA_OBJS+=("$so")
  done
  # mayhem-owned overlay for standalone too
  so="$OUT/rfz_utils_sa.o"
  $CC $CFLAGS -DFUZZ_STANDALONE -Isrc -I"$FUZZ" -o "$so" -c "$SRC/mayhem/rfz_utils.c"
  HELPER_SA_OBJS+=("$so")
  # disable-LSan shim for standalone too
  HELPER_SA_OBJS+=("$ASAN_OPT_OBJ")
  $CXX $CXXFLAGS $LDFLAGS -o "$OUT/fuzz_${fz}-standalone" \
    "${HELPER_SA_OBJS[@]}" "$hobj_sa" $LINKLIB -lm $LIBSRTP

  # ship the harness's dictionary next to the binary (build.sh-relative, also copied by Mayhemfile ref)
  [ -e "$FUZZ/fuzz_${fz}.dict" ] && cp "$FUZZ/fuzz_${fz}.dict" "$OUT/" || true
  echo "built fuzz_${fz} (+ standalone)"
done

# ── 3) the RTCP-parse golden oracle (test.sh runs it). Links the SAME rtcp2json() the rtcp_parser
#       fuzzer drives, out of the instrumented librtpproxy, and checks BYTE-EXACT JSON on known RTCP
#       packets — a no-op/exit(0) patch to rtcp2json cannot reproduce the expected JSON. ────────────
$CC $CFLAGS -Isrc -Imodules/acct_rtcp_hep \
    -o "$OUT/rtcp_oracle.o" -c "$SRC/mayhem/rtcp_oracle.c"
$CXX $CXXFLAGS $LDFLAGS -o "$OUT/rtcp_oracle" \
    "$OUT/rtcp_oracle.o" -Wl,--whole-archive "$RTPPLIB" -Wl,--no-whole-archive \
    -lm $LIBSRTP
echo "built rtcp_oracle"

echo "build.sh complete:"
ls -la "$OUT"/fuzz_command_parser "$OUT"/fuzz_rtp_parser "$OUT"/fuzz_rtcp_parser "$OUT"/fuzz_rtp_session \
       "$OUT"/fuzz_command_parser-standalone "$OUT"/fuzz_rtp_parser-standalone \
       "$OUT"/fuzz_rtcp_parser-standalone "$OUT"/fuzz_rtp_session-standalone \
       "$OUT"/rtcp_oracle 2>&1 || true
