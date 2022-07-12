/*
 * contains the implementation of all syscalls.
 */

#include <stdint.h>
#include <errno.h>

#include "util/types.h"
#include "syscall.h"
#include "string.h"
#include "process.h"
#include "util/functions.h"
//TODO
#include "elf.h"

#include "spike_interface/spike_utils.h"

// added for lab1_challenge1_backtrace.
//TODO
extern elf_ctx g_elfloader;

//
// implement the SYS_user_print syscall
//
ssize_t sys_user_print(const char* buf, size_t n) {
    sprint(buf);
    return 0;
}

//
// implement the SYS_user_exit syscall
//
ssize_t sys_user_exit(uint64 code) {
    sprint("User exit with code:%d.\n", code);
    // in lab1, PKE considers only one app (one process).
    // therefore, shutdown the system when the app calls exit()
    shutdown(code);
}

//
// added for lab1_challenge1_backtrace.
// checks the symbol record according to input virtual address ra. returns the index in
// g_elfloader.syms array for result symbol.
// the checking is conducted by comparing the addresses in g_elfloader.syms array and
// a given ra.
//
//TODO
int backtrace_symbol(uint64 ra) {
    uint64 closest_func = 0;
    int idx = -1;
    for (int i = 0; i < g_elfloader.syms_count; ++i) {
        if (g_elfloader.syms[i].st_info == STT_FUNC && g_elfloader.syms[i].st_value < ra &&
            g_elfloader.syms[i].st_value > closest_func) {
            closest_func = g_elfloader.syms[i].st_value;
            idx = i;
        }
    }
    return idx;
}

//
// added for lab1_challenge1_backtrace.
// the function first locates the stack of user app by current->trapframe->regs.sp, and
// then back traces the function calls via the return addresses stored in the user stack.
// Note: as we consider only functions with no parameters in this challenge, we jump for
// exactly 16 bytes during the back tracing.
//
//TODO
//
ssize_t sys_user_backtrace(int64 depth) {
    // acquire the user stack, and bypass the latest call to print_backtrace().
    // 16 means length of leaf function (i.e., print_backtrace)'s call stack frame, where
    // no return address is available, 8 means length of the margin space in previous
    // function's call stack frame.
    uint64 user_sp = current->trapframe->regs.sp + 16 + 8;

    // back trace user stack, lookup the symbol names of the return addresses.
    // Note: by principle, we should traverse the stack via "fp" here. However, as we
    // consider the simple case where functions in the path have NO parameters, we can do
    // it by simply bypassing 16 bytes at each depth.
    // the traverse direction is from lower addresses to higher addresses.
    int64 actual_depth=0;
    for (uint64 p = user_sp; actual_depth<depth; ++actual_depth, p += 16) {
        // the return address is stored in (uint64*)p
        if (*(uint64*)p == 0) break; // end of user stack?
        // look up the symbol name of the given return address
        int symbol_idx = backtrace_symbol(*(uint64*)p);
        if (symbol_idx == -1) {
            sprint("fail to backtrace symbol %lx\n", *(uint64*)p);
            continue;
        }
        // print the function name.
        sprint("%s\n", &g_elfloader.strtb[g_elfloader.syms[symbol_idx].st_name]);
    }

    return 0;
}

//
// [a0]: the syscall number; [a1] ... [a7]: arguments to the syscalls.
// returns the code of success, (e.g., 0 means success, fail for otherwise)
//
long do_syscall(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7) {
    switch (a0) {
        case SYS_user_print:
            return sys_user_print((const char*)a1, a2);
        case SYS_user_exit:
            return sys_user_exit(a1);
            //TODO
        case SYS_user_backtrace:
            return sys_user_backtrace(a1);
        default:
            panic("Unknown syscall %ld \n", a0);
    }
}
