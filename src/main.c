/*
 * Copyright (C) 2022 xmmword
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <uapi/linux/utsname.h>

#include "dpatch.h"
#include "kstatus.h"

MODULE_LICENSE("GPL");


/*
    *    src/main.c
    *    Date: 10/13/22
    *    Author: @xmmword
*/


extern dpatch_ctx_t dpatch_ctx; /* Structure containing important data related to the current dpatch context. */

/**
 * @brief A sample 'sys_uname' hook for demonstration.
 * @param buf A structure containing information about the machine/platform.
 * @returns 0 on success, -1 on failure.
 */

int hooked_uname(struct new_utsname *buf) {
  dpatch_kern_log("[sys_uname] hook called!");

  int (*original_uname)(struct new_utsname *buf) = (void *)return_syscall_table_ptr(__NR_uname);
  if (!original_uname)
    return -1;

  return original_uname(buf);
}

/**
 * @brief Entry point for dpatch.
 * @returns KERN_SUCCESS on success, KERN_FAILURE on failure.
 */

static int __init dpatch_main(void) {
  dpatch_kern_log("dpatch driver has been loaded!");

  dpatch_ctx.kallsyms_lookup_name = (kallsyms_ptr_t)return_symbol_address("kallsyms_lookup_name");
  if (!dpatch_ctx.kallsyms_lookup_name)
    return KERN_FAILURE;

  dpatch_kern_log("Resolved [kallsyms_lookup_name] @ 0x%lx", (uintptr_t)dpatch_ctx.kallsyms_lookup_name);

  if (!(dpatch_ctx.do_syscall_64 = (syscall_dispatcher_ptr_t)dpatch_ctx.kallsyms_lookup_name("do_syscall_64")))
    return KERN_FAILURE;

  dpatch_kern_log("Resolved [do_syscall_64] @ 0x%lx", (uintptr_t)dpatch_ctx.do_syscall_64);

  if (!(dpatch_ctx.syscall_enter_from_user_mode = (syscall_enter_usermode_ptr_t)dpatch_ctx.kallsyms_lookup_name("syscall_enter_from_user_mode")))
    return KERN_FAILURE;

  dpatch_kern_log("Resolved [syscall_enter_from_user_mode] @ 0x%lx", (uintptr_t)dpatch_ctx.syscall_enter_from_user_mode);

  if (!(dpatch_ctx.__x64_sys_ni_syscall = (sys_ni_ptr_t)dpatch_ctx.kallsyms_lookup_name("__x64_sys_ni_syscall")))
    return KERN_FAILURE;

  dpatch_kern_log("Resolved [__x64_sys_ni_syscall] @ 0x%lx", (uintptr_t)dpatch_ctx.__x64_sys_ni_syscall);

  if (!(dpatch_ctx.syscall_exit_to_user_mode = (syscall_exit_usermode_ptr_t)dpatch_ctx.kallsyms_lookup_name("syscall_exit_to_user_mode")))
    return KERN_FAILURE;

  dpatch_kern_log("Resolved [syscall_exit_to_user_mode] @ 0x%lx", (uintptr_t)dpatch_ctx.syscall_exit_to_user_mode);

  if (!(dpatch_ctx.syscall_table = return_syscall_table())) {
    dpatch_kern_log("Failed to copy [sys_call_table]!");

    return KERN_FAILURE;
  }

  dpatch_kern_log("Copied the contents of [sys_call_table]");
  dpatch_kern_log("Overwriting [sys_call_table] addresses...");

  if (!install_table_hook(hooked_uname, __NR_uname)) {
    dpatch_kern_log("Failed to overwrite [sys_uname] address!");

    return KERN_FAILURE;
  }

  dpatch_kern_log("Successfully overwritten [sys_uname] address!");

  if (dpatch_hook_dispatcher(hooked_syscall_dispatcher, dpatch_ctx.do_syscall_64) == DPATCH_HOOK_FAILURE) {
    dpatch_kern_log("Failed to patch [do_syscall_64]");

    return KERN_FAILURE;
  }

  dpatch_kern_log("Successfully patched [do_syscall_64]");
  return KERN_SUCCESS;
}

/**
 * @brief Exit point for dpatch.
 */

static void __exit dpatch_exit(void) {
  if (!uninstall_table_hook(__NR_uname))
    return;

  dpatch_kern_log("Successfully unhooked [sys_uname]");

  /*
    Note: After several tests, I have been able to reduce the amount of crashes
          that occur via 'unpatching' the system call dispatcher, but there is
          NO guarantee that your system will be in a stable state once the kernel
          driver has been unloaded. You have been warned. */

  /* Please remember, this is just a PoC. */

  disable_memory_protection();
  memcpy(*(uint64_t *)dpatch_ctx.do_syscall_64, dpatch_ctx.bytes, sizeof(*(uint64_t *)dpatch_ctx.bytes));

  enable_memory_protection();
  dpatch_kern_log("dpatch driver has been unloaded!");
}

module_init(dpatch_main); /* Start-up routine. */
module_exit(dpatch_exit); /* Exit routine. */