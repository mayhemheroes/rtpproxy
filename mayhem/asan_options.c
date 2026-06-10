/* mayhem/asan_options.c — disable LeakSanitizer for Mayhem coverage runs.
 *
 * Building with -fsanitize=address enables LSan by default.  Mayhem runs targets
 * under ptrace to collect coverage edges; LSan also ptrace-attaches its own threads
 * at exit to scan for leaks, but Linux allows only ONE tracer → LSan prints
 * "LeakSanitizer has encountered a fatal error … does not work under ptrace" and
 * the process exits non-zero BEFORE any edges are recorded → 0-edge "Run Failed".
 *
 * Fix: bake detect_leaks=0 into the binary so it holds regardless of ASAN_OPTIONS
 * in the runtime environment.  We use STRONG symbols (no __attribute__((weak)))
 * because command_parser + rtp_session link librtpproxy with --whole-archive, which
 * can pull in the ASan runtime's own weak default-options copy and win over a weak
 * definition here.  A strong symbol always overrides.
 *
 * Leak detection is not useful for fuzzing (short iterations leak by design, and
 * leaks are not crashes); we keep the high-value detectors: out-of-bounds /
 * use-after-free via ASan and undefined behaviour via UBSan.
 */
const char *__asan_default_options(void) { return "detect_leaks=0"; }
const char *__lsan_default_options(void) { return "detect_leaks=0"; }
