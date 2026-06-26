/*
 * fuzz_elf2cpe.c — in-process libFuzzer harness for elf2cpe's ELF->CPE converter.
 *
 * Why libFuzzer (not a file-input @@ target): elf2cpe's bug — a stack-buffer overflow when the ELF's
 * prg_entry_count exceeds the fixed prg_heads[128] — is trivially reachable, so as a file-input (mfuzz)
 * target Mayhem's corpus saturates with crashing inputs and its post-run coverage-FINALIZATION phase
 * never completes (edges_covered finalizes to 0). An in-process libFuzzer target instead reports edge
 * coverage from in-process SanitizerCoverage during the run, which finalizes reliably.
 *
 * elf2cpe reads its input from a NAMED FILE (global in_file) and writes to a named file (global
 * out_file). To avoid touching disk (Mayhem's coverage sandbox is read-only), we back the input with an
 * in-memory memfd referenced via /proc/self/fd/N, and send output to /dev/null (always writable). We
 * link elf2cpe.c with its main() renamed (-Dmain=...) so convertELF()/in_file/out_file/quiet are reused
 * verbatim — no upstream edits.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/* Provided by tools/util/elf2cpe.c (compiled with -Dmain=... so its main is inert). */
extern int   convertELF(void);
extern char *in_file;
extern char *out_file;
extern int   quiet;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int fd = memfd_create("elf2cpe_input", 0);
    if (fd < 0)
        return 0;

    /* Write the fuzz input into the in-memory fd; a fresh fopen() of /proc/self/fd/N reads from 0. */
    size_t off = 0;
    while (off < size) {
        ssize_t w = write(fd, data + off, size - off);
        if (w <= 0) { close(fd); return 0; }
        off += (size_t)w;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    in_file  = path;
    out_file = (char *)"/dev/null";  /* explicit output => skip elf2cpe's output-name derivation */
    quiet    = 1;

    convertELF();

    close(fd);
    return 0;
}
