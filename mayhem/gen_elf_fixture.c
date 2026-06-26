/*
 * gen_elf_fixture.c — write a tiny, deterministic MIPS little-endian 32-bit executable ELF that
 * elf2cpe accepts, for use as the known-answer input in mayhem/test.sh.
 *
 * Layout mirrors tools/util/elf.h exactly (packed). One LOAD program header (flags != 4, so it is
 * copied into the CPE) carrying 4 bytes of payload. Run at build time by mayhem/build.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;            /* 0-3   */
    uint8_t  word_size;        /* 4     */
    uint8_t  endianness;       /* 5     */
    uint8_t  elf_version;      /* 6     */
    uint8_t  os_abi;           /* 7     */
    uint32_t unused[2];        /* 8-15  */
    uint16_t type;             /* 16-17 */
    uint16_t instr_set;        /* 18-19 */
    uint32_t elf_version2;     /* 20-23 */
    uint32_t prg_entry_addr;   /* 24-27 */
    uint32_t prg_head_pos;     /* 28-31 */
    uint32_t sec_head_pos;     /* 32-35 */
    uint32_t flags;            /* 36-39 */
    uint16_t head_size;        /* 40-41 */
    uint16_t prg_entry_size;   /* 42-43 */
    uint16_t prg_entry_count;  /* 44-45 */
    uint16_t sec_entry_size;   /* 46-47 */
    uint16_t sec_entry_count;  /* 48-49 */
    uint16_t sec_names_index;  /* 50-51 */
} ELF_HEADER;

typedef struct {
    uint32_t seg_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t undefined;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t flags;
    uint32_t alignment;
} PRG_HEADER;
#pragma pack(pop)

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <out.elf>\n", argv[0]);
        return 2;
    }

    const uint32_t ENTRY  = 0x80010000u;
    const uint8_t  PAYLOAD[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

    ELF_HEADER h;
    memset(&h, 0, sizeof(h));
    h.magic          = 0x464c457fu; /* 0x7f 'E' 'L' 'F' */
    h.word_size      = 1;           /* 32-bit            */
    h.endianness     = 1;           /* little endian     */
    h.elf_version    = 1;
    h.type           = 2;           /* executable        */
    h.instr_set      = 8;           /* MIPS              */
    h.prg_entry_addr = ENTRY;
    h.prg_head_pos   = sizeof(ELF_HEADER);          /* program headers right after the ELF header */
    h.head_size      = sizeof(ELF_HEADER);
    h.prg_entry_size = sizeof(PRG_HEADER);
    h.prg_entry_count = 1;

    PRG_HEADER p;
    memset(&p, 0, sizeof(p));
    p.seg_type  = 1;                                /* LOAD */
    p.p_offset  = sizeof(ELF_HEADER) + sizeof(PRG_HEADER); /* payload after the program header */
    p.p_vaddr   = ENTRY;
    p.p_filesz  = sizeof(PAYLOAD);
    p.p_memsz   = sizeof(PAYLOAD);
    p.flags     = 5;                                /* != 4, so elf2cpe copies it */
    p.alignment = 4;

    FILE *f = fopen(argv[1], "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(&h, 1, sizeof(h), f);
    fwrite(&p, 1, sizeof(p), f);
    fwrite(PAYLOAD, 1, sizeof(PAYLOAD), f);
    fclose(f);
    return 0;
}
