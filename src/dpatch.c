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

#include "dpatch.h"
#include "kstatus.h"


/*
    *    src/dpatch.c
    *    Date: 10/13/22
    *    Author: @xmmword
*/


dpatch_ctx_t dpatch_ctx = {0}; /* Structure containing important data related to the current dpatch context. */

EXPORT_SYMBOL(dpatch_ctx); /* Exporting [dpatch_ctx] to make it accessible to 'main.c'. */

/**
 * @brief Writes data to the 'cr0' register.
 * @param val The data.
 */

void write_to_cr0(unsigned long val) {
  asm volatile("mov %0, %%cr0":"+r"(val), "+m"((unsigned long){0}));
}

/**
 * @brief Enables memory protections.
 */

void enable_memory_protection(void) {
  write_to_cr0(read_cr0());
}

/**
 * @brief Disables memory protections.
 */

void disable_memory_protection(void) {
  write_to_cr0((read_cr0() & ~0x00010000));
}

/**
 * @brief Outputs a formatted log.
 * @param message The message that will be outputted.
 */

void __visible dpatch_kern_log(const char *message, ...) {
  va_list arguments = {0};
  char buffer[BUFSIZ] = {0};

  snprintf(buffer, sizeof(buffer), "[dpatch]: %s\n", message);
  va_start(arguments, buffer);

  vprintk(buffer, arguments);
  va_end(arguments);
}

/**
 * @brief Resolves the address of a given symbol.
 * @param symbol The name of the symbol.
 * @returns The address of the symbol.
 */

uintptr_t return_symbol_address(const char *symbol) {
  uintptr_t address = 0;

  struct kprobe probe = {
    .symbol_name = (char *)symbol
  };

  if (register_kprobe(&probe) < 0)
    return 0;

  address = (uintptr_t)probe.addr;

  unregister_kprobe(&probe);
  return address;
}

/**
 * @brief Returns a mutable/patchable copy of the system call table.
 * @returns A copy of the system call table.
 */

sys_call_ptr_t *return_syscall_table(void) {
  sys_call_ptr_t *syscall_table = NULL, *resolved_syscall_table = (sys_call_ptr_t *)dpatch_ctx.kallsyms_lookup_name("sys_call_table");
  if (!resolved_syscall_table)
    return NULL;

  if(!(syscall_table = vmalloc((sizeof(sys_call_ptr_t) * NR_syscalls))))
    return NULL;

  memcpy(syscall_table, resolved_syscall_table, (sizeof(sys_call_ptr_t) * NR_syscalls));
  return syscall_table;
}

/**
 * @brief Returns a function pointer associated with a given system call number within the original system call table.
 * @param entry The system call table index.
 * @returns The function pointer associated with the index/system call number.
 */

sys_call_ptr_t return_syscall_table_ptr(const int entry) {
  if (entry < 0 || entry > NR_syscalls)
    return NULL;

  sys_call_ptr_t *original_syscall_table = (sys_call_ptr_t *)dpatch_ctx.kallsyms_lookup_name("sys_call_table");
  if (!original_syscall_table)
    return NULL;

  return original_syscall_table[entry];
}

/**
 * @brief Installs a hook within a given system call table entry.
 * @param hook The pointer to the hook function.
 * @param entry The system call table index.
 * @returns True if the system call could be hooked, false if otherwise.
 */

bool install_table_hook(void *hook, const int entry) {
  if (entry < 0 || entry > NR_syscalls)
    return false;

  dpatch_ctx.syscall_table[entry] = hook;
  return true;
}

/**
 * @brief Uninstalls a hook within a given system call table entry.
 * @param entry The system call table index.
 * @returns True if the system call could be unhooked, false if otherwise.
 */

bool uninstall_table_hook(const int entry) {
  if (entry < 0 || entry > NR_syscalls)
    return false;

  sys_call_ptr_t *original_syscall_table = (sys_call_ptr_t *)dpatch_ctx.kallsyms_lookup_name("sys_call_table");
  if (!original_syscall_table)
    return false;

  dpatch_ctx.syscall_table[entry] = original_syscall_table[entry];
  return true;
}

/**
 * @brief Dispatches a system call for x86-32.
 * @param regs A structure containing register states.
 * @param nr The system call number.
 * @returns True if the system call could be dispatched, false if otherwise.
 */

bool dispatch_syscall_x32(struct pt_regs *regs, int nr) {
  unsigned int temp = (nr - __X32_SYSCALL_BIT);

  if (IS_ENABLED(CONFIG_X86_X32_ABI) && likely(temp < X32_NR_syscalls)) {
    regs->ax = dpatch_ctx.syscall_table[(temp = array_index_nospec(temp, X32_NR_syscalls))](regs);

    return true;
  }

  return false;
}

/**
 * @brief Dispatches a system call for x86-64.
 * @param regs A structure containing register states.
 * @param nr The system call number.
 * @returns True if the system call could be dispatched, false if otherwise.
 */

bool dispatch_syscall_x64(struct pt_regs *regs, int nr) {
  unsigned int entry = nr;

  if (likely(entry < NR_syscalls)) {
    regs->ax = dpatch_ctx.syscall_table[(entry = array_index_nospec(entry, NR_syscalls))](regs);

    return true;
  }

  return false;
}

/**
 * @brief The hook for the system call dispatcher.
 * @param regs A structure containing register states.
 * @param nr The system call number.
 */

void hooked_syscall_dispatcher(struct pt_regs *regs, int nr) {
  nr = dpatch_ctx.syscall_enter_from_user_mode(regs, nr);

  instrumentation_begin();

  if (!dispatch_syscall_x64(regs, nr) && !dispatch_syscall_x32(regs, nr) && nr != -1)
    regs->ax = dpatch_ctx.__x64_sys_ni_syscall(regs);

  instrumentation_end();
  dpatch_ctx.syscall_exit_to_user_mode(regs);
}

/**
 * @brief Patches the bytes of the system call dispatcher.
 * @param hook The pointer to the system call dispatcher hook.
 * @param syscall_dispatcher The pointer to the system call dispatcher.
 */

int dpatch_hook_dispatcher(void *hook, void *syscall_dispatcher) {
  if (!syscall_dispatcher)
    return DPATCH_HOOK_FAILURE;

  disable_memory_protection();
  memcpy(dpatch_ctx.bytes, syscall_dispatcher, sizeof(*(uint64_t *)syscall_dispatcher));

  const uint32_t val = ((uint8_t *)hook - (uint8_t *)syscall_dispatcher - 5);

  const jmp_hook_t jmp_hook = {
    {0xe9, (val >> 0), (val >> 8), (val >> 16), (val >> 24)}
  };

  *(uint64_t *)syscall_dispatcher = jmp_hook.tmp;
  enable_memory_protection();

  return DPATCH_HOOK_SUCCESS;
}