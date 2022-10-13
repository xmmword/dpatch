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

#ifndef __DPATCH_H
#define __DPATCH_H

#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <asm/syscall.h>
#include <linux/nospec.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/compiler.h>
#include <linux/irqflags.h>
#include <linux/thread_info.h>
#include <linux/stop_machine.h>
#include <linux/entry-common.h>
#include <asm-generic/rwonce.h>
#include <asm/syscall_wrapper.h>
#include <linux/instrumentation.h>
#include <linux/randomize_kstack.h>

#define BUFSIZ 1024 /* Maximum size of buffer. */


/*
    *    src/dpatch.h
    *    Date: 10/13/22
    *    Author: @xmmword
*/


typedef uintptr_t (*kallsyms_ptr_t)(const char *name);

typedef long (*sys_ni_ptr_t)(const struct pt_regs *regs);
typedef long (*syscall_enter_usermode_ptr_t)(struct pt_regs *regs, long syscall);

typedef void (*syscall_exit_usermode_ptr_t)(struct pt_regs *regs);
typedef void (*syscall_dispatcher_ptr_t)(struct pt_regs *regs, int nr);

/* Structure containing JMP-hook data. */
typedef union _jmp_hook {
  uint8_t instr[8]; /* Overwritten instructions. */
  uint64_t tmp; /* Temporary value. */
} jmp_hook_t;

/* Structure containing function pointers and other important data related to the current dpatch context. */
typedef struct _dpatch_ctx {
  uint8_t bytes[8]; /* Original function bytes. (For unpatching..) */
  sys_call_ptr_t *syscall_table; /* sys_call_table pointer. */

  sys_ni_ptr_t __x64_sys_ni_syscall; /* Cached __x64_sys_ni_syscall function pointer. */
  kallsyms_ptr_t kallsyms_lookup_name; /* Cached kallsyms_lookup_name function pointer. */

  syscall_dispatcher_ptr_t do_syscall_64; /* Pointer to the x64 system call dispatcher. */

  syscall_exit_usermode_ptr_t syscall_exit_to_user_mode; /* Cached syscall_exit_to_user_mode function pointer. */
  syscall_enter_usermode_ptr_t syscall_enter_from_user_mode; /* Cached syscall_exit_from_user_mode function pointer. */
} dpatch_ctx_t;

void __visible dpatch_kern_log(const char *message, ...);

inline void write_to_cr0(unsigned long val);
uintptr_t return_symbol_address(const char *symbol);

void enable_memory_protection(void);
void disable_memory_protection(void);

bool uninstall_table_hook(const int entry);
bool install_table_hook(void *hook, const int entry);

sys_call_ptr_t *return_syscall_table(void);
sys_call_ptr_t return_syscall_table_ptr(const int entry);

void hooked_syscall_dispatcher(struct pt_regs *regs, int nr);
int dpatch_hook_dispatcher(void *hook, void *syscall_dispatcher);

#endif