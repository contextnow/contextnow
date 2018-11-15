#ifndef _NOSPEC_H_
#define _NOSPEC_H_

#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/resource.h>

#include "module/ptedit_header.h"

#ifndef PARANOID
#define PARANOID 0
#endif

#define DEBUG printf

#define EI_NIDENT 16

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    uint16_t      e_type;
    uint16_t      e_machine;
    uint32_t      e_version;
    size_t        e_entry;
    size_t        e_phoff;
    size_t        e_shoff;
    uint32_t      e_flags;
    uint16_t      e_ehsize;
    uint16_t      e_phentsize;
    uint16_t      e_phnum;
    uint16_t      e_shentsize;
    uint16_t      e_shnum;
    uint16_t      e_shstrndx;
} ElfN_Ehdr;

typedef struct {
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint64_t   sh_flags;
    size_t     sh_addr;
    size_t     sh_offset;
    uint64_t   sh_size;
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint64_t   sh_addralign;
    uint64_t   sh_entsize;
} Elf64_Shdr;


#if PARANOID
#include <signal.h>
#include <setjmp.h>

static jmp_buf specfence_buf;

void unblock_signal(int signum __attribute__((__unused__))) {
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, signum);
  sigprocmask(SIG_UNBLOCK, &sigs, NULL);
}

// ---------------------------------------------------------------------------
void specfence_segfault_handler(int signum) {
  (void)signum;
  unblock_signal(SIGSEGV);
  longjmp(specfence_buf, 1);
}

#endif

uint64_t nospecrdtsc() {
  uint64_t a, d;
  asm volatile("mfence");
  asm volatile("rdtsc" : "=a"(a), "=d"(d));
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

void __attribute__((section(".specfence"), constructor)) init_nospec() {
    size_t start = nospecrdtsc();
    size_t stack = 0;
    FILE* f = fopen("/proc/self/exe", "rb");
    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* elf = (char*)malloc(fsize);
    (void)fread(elf, 1, fsize, f);
    fclose(f);

    ptedit_init();
    int uc_mt = ptedit_find_first_mt(PTEDIT_MT_UC);
    if(uc_mt == -1) {
        printf("[ERROR] Uncachable not supported on this kernel/machine\n");
        ptedit_cleanup();
    }

    ElfN_Ehdr* hdr = (ElfN_Ehdr*)elf;

    Elf64_Shdr* shdr = (Elf64_Shdr*)(elf + hdr->e_shoff);
    Elf64_Shdr symtab = shdr[hdr->e_shstrndx];

    // get relocation offset
    size_t offset = 0;
    for(int i = 0; i < hdr->e_shnum; i++) {
        if(strcmp((char*)(elf + symtab.sh_offset + shdr[i].sh_name), ".specfence") == 0) {
                DEBUG("init_nospec @ %zx / %zx\n", shdr[i].sh_addr, (size_t)init_nospec);
                offset = (size_t)init_nospec - shdr[i].sh_addr;
        }
    }

    // set "secret" section to uncachable
    for(int i = 0; i < hdr->e_shnum; i++) {
        if(strcmp((char*)(elf + symtab.sh_offset + shdr[i].sh_name), ".secret") == 0) {
            DEBUG("Secret @ %zx (len: %zd)\n", shdr[i].sh_addr + offset, shdr[i].sh_size);
            for(int j = 0; j < (shdr[i].sh_size + 4095) / 4096; j++) {
                void* addr = (void*)(shdr[i].sh_addr + offset + j * 4096);
                *(volatile char*)addr;
                DEBUG(" - Setting %p to uncachable\n", addr);
                ptedit_entry_t entry = ptedit_resolve(addr, 0);
                entry.pte = ptedit_apply_mt(entry.pte, uc_mt);
                entry.valid = PTEDIT_VALID_MASK_PTE;
                ptedit_update(addr, 0, &entry);
            }
        }

    }

#if PARANOID
    size_t stack_start = (size_t)&stack & ~0xfff;
    struct rlimit rlim;
    getrlimit(RLIMIT_STACK, &rlim);
    size_t stack_size = (size_t)rlim.rlim_cur;
    DEBUG("start: %zx, size: %zd\n", stack_start, stack_size / 1024);
    signal(SIGSEGV, specfence_segfault_handler);
    if (!setjmp(specfence_buf)) {
        for(int i = 0; i < stack_size / 4096; i++) {
            void* addr = (void*)(stack_start - i * 4096);
            DEBUG("%p\n", addr);
            *(volatile char*)addr;
            ptedit_entry_t entry = ptedit_resolve(addr, 0);
            if((entry.valid & PTEDIT_VALID_MASK_PTE) && entry.pte & (1 << PTEDIT_PAGE_BIT_PRESENT)) {
                entry.pte = ptedit_apply_mt(entry.pte, uc_mt);
                entry.valid = PTEDIT_VALID_MASK_PTE;
                ptedit_update(addr, 0, &entry);
                DEBUG(" -> UC\n");
            }
        }
    }
    signal(SIGSEGV, SIG_DFL);
#endif

    printf("[specfence] active, took %zd cycles\n", nospecrdtsc() - start);

    ptedit_cleanup();
}

#define nospec __attribute__((section(".secret")))

void* malloc_nospec(size_t len) {
    ptedit_init();
    int uc_mt = ptedit_find_first_mt(PTEDIT_MT_UC);
    if(uc_mt == -1) {
        printf("[ERROR] Uncachable not supported on this kernel/machine\n");
        ptedit_cleanup();
    }
    size_t len_aligned = ((len + 4095) / 4096) * 4096;
    void* mem = mmap(0, len_aligned + 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    for(int j = 1; j < len_aligned / 4096 + 1; j++) {
        DEBUG(" - Setting %p to uncachable\n", mem + j * 4096);
        ptedit_entry_t entry = ptedit_resolve(mem + j * 4096, 0);
        entry.pte = ptedit_apply_mt(entry.pte, uc_mt);
        entry.valid = PTEDIT_VALID_MASK_PTE;
        ptedit_update(mem + j * 4096, 0, &entry);
    }
    ptedit_cleanup();
    *(size_t*)mem = len;
    return mem + 4096;
}

void free_nospec(void* addr) {
    munmap((char*)addr - 4096, *(size_t*)((char*)addr - 4096));
}

#endif
