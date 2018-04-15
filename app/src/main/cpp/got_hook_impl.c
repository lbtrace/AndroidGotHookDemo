/*
 * A Simple GOT Hook Implement in Arm32 or Arm64
 *
 * Copyright (C) 2018 lbtrace(coder.wlb@gmail.com)
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

#include <android/log.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>


#include "got_hook.h"
#include "elf_util.h"

#define DEBUG_GOT_HOOK

static const char *log_tag = "GOT_HOOK";
static const char *lib_name = "libgot_hook.so";
static hook_t hook_handle;
static Elf_Addr g_ori_func_addr;


void arm32_got_hook_stub(void)
{
    __android_log_print(ANDROID_LOG_INFO, log_tag, "Woo! This is arm32 hook log");
}

void arm64_got_hook_stub(void)
{
    __android_log_print(ANDROID_LOG_INFO, log_tag, "Woo! This is arm64 hook log");
}

static int modify_mem_prop(Elf_Addr target_addr)
{
    u_long page_size = sysconf(_SC_PAGE_SIZE);
    Elf_Addr start = target_addr / page_size * page_size;

    if (mprotect(start, page_size * 2, PROT_READ | PROT_WRITE) == -1)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

/**
 * Got hook core implement.
 *
 * @param lib_path the library which GOT belongs
 * @param ori_func_name hooked function name
 * @param handle handle function for modify original function actions
 */
void got_hook(const char *lib_path, const char *ori_func_name, hook_t handle)
{
    elf_info_t *elf_ptr = open_elf(lib_path);
    Elf_Addr got_addr;

    if (!elf_ptr)
        return;

    if (!handle || !ori_func_name)
        return;

    hook_handle = handle;
    got_addr = elf_ptr->base + get_got_of_sym(elf_ptr, ori_func_name);
    g_ori_func_addr = *((Elf_Addr *)got_addr);

    // Todo
    // invoke handle function
    if (!modify_mem_prop(got_addr)) {
#if defined(__LP64__)
        *((Elf_Addr *)got_addr) = (Elf_Addr)arm64_got_hook_stub;
#else
        *((Elf_Addr *)got_addr) = (Elf_Addr *)arm32_got_hook_stub;
#endif
    }

    close_elf(elf_ptr);
}
