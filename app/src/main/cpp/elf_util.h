/*
 * Copyright (c) 2018 lbtrace (coder.wlb@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef HOOKDEMO_ELF_UTIL_H
#define HOOKDEMO_ELF_UTIL_H

#include <elf.h>

#if defined(__LP64__)
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Addr Elf_Addr;
typedef Elf64_Dyn Elf_Dyn;
typedef Elf64_Rela Elf_Rela;
typedef Elf64_Sym Elf_Sym;
typedef Elf64_Off Elf_Off;

#define ELF_R_SYM(i) ELF64_R_SYM(i)
#else
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Addr Elf_Addr;
typedef Elf32_Dyn Elf_Dyn;
typedef Elf32_Rel Elf_Rela;
typedef Elf32_Sym Elf_Sym;
typedef Elf32_Off Elf_Off;

#define ELF_R_SYM(i) ELF32_R_SYM(i)
#endif

#define NAME_SIZE 32
#define NR_SH 6
#define MAX_FUNC_NAME 128

typedef struct section_info {
    char name[NAME_SIZE];
    Elf_Off offset;
} section_info_t;

typedef struct elf_info {
    int fd;
    long base;
    Elf_Ehdr ehdr;
    section_info_t sections[NR_SH];
} elf_info_t;

const char sec_names[NR_SH][NAME_SIZE] = {
        ".shstrtab",
        ".got",
#if defined(__LP64__)
        ".rela.plt",
#else
        ".rel.plt",
#endif
        ".dynsym",
        ".dynstr",
        ".dynamic"
};

elf_info_t *open_elf(const char *elf_path);
Elf_Addr get_got_of_sym(elf_info_t *elf, const char *func_name);
void close_elf(elf_info_t *elf);

#endif //HOOKDEMO_ELF_UTIL_H
