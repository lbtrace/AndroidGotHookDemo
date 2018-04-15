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

#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <string.h>

#include <android/log.h>


#include "elf_util.h"

// Note: if you use checked_read(), please define read_fail lable.
#define checked_read(fd, buf, count) \
do {                  \
    if (read(fd, buf, count) != count) \
        goto read_fail; \
} while (0)

static Elf_Addr get_elf_load_addr(const char *elf_name)
{
    char base_name[128];
    const char *src = strrchr(elf_name, '/');
    FILE *map_file;
    char buf[256];
    char *addr;
    Elf_Addr ret = 0;

    if (src) {
        src += 1;
    } else {
        src = elf_name;
    }
    strncpy(base_name, src, 128);

    if (!(map_file = fopen("/proc/self/maps", "r")))
        return ret;

    while (!feof(map_file)) {
        fgets(buf, 256, map_file);

        if (strstr(buf, base_name)) {
            addr = strtok(buf, "-");
            ret = strtoul(addr, NULL, 16);
            break;
        }
    }

    fclose(map_file);
    return ret;
}

void get_string_by_index(const unsigned int fd, const unsigned int str_offset,
                         const unsigned int index, char *name, int size)
{
    lseek(fd, str_offset + index, SEEK_SET);
    while (size--) {
        checked_read(fd, name, 1);

        if (*name == 0)
            break;
        name++;
    }

    read_fail:
    return;
}

elf_info_t *open_elf(const char *elf_path)
{
    elf_info_t *elf_ptr;
    Elf_Shdr shdr;
    int i, j;

    if (!(elf_ptr = (elf_info_t *)calloc(1, sizeof(elf_info_t))))
        goto no_mem;

    if ((elf_ptr->fd = open(elf_path, O_RDONLY)) < 0)
        goto open_fail;


    elf_ptr->base = get_elf_load_addr(elf_path);

    checked_read(elf_ptr->fd, &(elf_ptr->ehdr), sizeof(Elf_Ehdr));

    // get section header string table
    lseek(elf_ptr->fd, elf_ptr->ehdr.e_shoff + elf_ptr->ehdr.e_shstrndx * sizeof(Elf_Shdr),
          SEEK_SET);
    checked_read(elf_ptr->fd, &shdr, sizeof(Elf_Shdr));

    strncpy(elf_ptr->sections[0].name, sec_names[0], NAME_SIZE);
    elf_ptr->sections[0].offset = shdr.sh_offset;

    // get .got/.rela.plt/.dynsym/.dynstr sections
    for (i = 0; i < elf_ptr->ehdr.e_shnum; i++) {
        char name[NAME_SIZE];

        lseek(elf_ptr->fd, elf_ptr->ehdr.e_shoff + i * sizeof(Elf_Shdr), SEEK_SET);
        checked_read(elf_ptr->fd, &shdr, sizeof(Elf_Shdr));

        get_string_by_index(elf_ptr->fd, elf_ptr->sections[0].offset, shdr.sh_name,
                            name, NAME_SIZE);
        for (j = 1; j < NR_SH; j++) {
            if (!strncmp(sec_names[j], name, NAME_SIZE)) {
                elf_ptr->sections[j].offset = shdr.sh_offset;
                strncpy(elf_ptr->sections[j].name, sec_names[j], NAME_SIZE);
            }
        }
    }

    return elf_ptr;
    read_fail:
    open_fail:
    free(elf_ptr);
    no_mem:
    return NULL;
}

void close_elf(elf_info_t *elf)
{
    if (elf) {
        close(elf->fd);
        free(elf);
    }
}

Elf_Addr get_got_of_sym(elf_info_t *elf, const char *func_name)
{
    Elf_Dyn dyn;
    Elf_Rela rela;
    int nr_rela_plt_item;
    int i;
    long ret = 0;

    if (strlen(func_name) >= MAX_FUNC_NAME)
        return ret;

    // calculate item nubmer of .rela.plt section
    lseek(elf->fd, elf->sections[5].offset, SEEK_SET);
    checked_read(elf->fd, &dyn, sizeof(Elf_Dyn));

    while (dyn.d_tag != DT_PLTRELSZ) {
        checked_read(elf->fd, &dyn, sizeof(Elf_Dyn));
    }

    nr_rela_plt_item = dyn.d_un.d_val / sizeof(Elf_Dyn);

    // find rela item of func_name
    for (i = 0; i < nr_rela_plt_item; i++) {
        Elf_Off off;
        Elf_Sym sym;
        char func[MAX_FUNC_NAME];

        lseek(elf->fd, elf->sections[2].offset + sizeof(Elf_Rela) * i, SEEK_SET);
        checked_read(elf->fd, &rela, sizeof(Elf_Rela));
        off = ELF_R_SYM(rela.r_info) * sizeof(Elf_Sym) + elf->sections[3].offset;
        lseek(elf->fd, off, SEEK_SET);
        checked_read(elf->fd, &sym, sizeof(Elf_Sym));
        get_string_by_index(elf->fd, elf->sections[4].offset, sym.st_name,
                            func, MAX_FUNC_NAME);
        if (!strncmp(func, func_name, MAX_FUNC_NAME)) {
            ret = rela.r_offset;
            break;
        }
    }

    read_fail:
    return ret;
}