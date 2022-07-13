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
#include "elf.h"

#include "spike_interface/spike_utils.h"

//外部定义的变量
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


//根据输入的虚拟地址，返回在符号表中的索引
//思路为遍历符号表，如果该符号代表一个函数，且该符号的value值比传入的返回地址低且距离最近，该符号即为对应函数的名字。
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


//通过当前trapframe的sp寄存器确定用户栈中print_backtrace()之前最先调用函数的栈帧地址，用来确定函数的返回地址，得到该返回地址后即可
//通过backtrace_symbol函数确定函数符号在符号表的索引
ssize_t sys_user_backtrace(int64 depth) {
//确定f8（）函数的返回地址保存位置，这里print_backtrace()为函数调用的叶子结点，没有函数的返回地址
  uint64 user_sp = current->trapframe->regs.sp + 16 + 8;


  //从低地址到高地址遍历，因为函数可以简化为不带参数的函数，所以每个函数的栈帧只占16个字节。每次向前遍历16个字节。遍历次数为深度，或者如果提前遇到用户栈栈底就停止。
  int64 actual_depth=0;
  for (uint64 p = user_sp; actual_depth<depth; ++actual_depth, p += 16) {
   // (uint64*)p 存储了函数的返回地址
    if (*(uint64*)p == 0) break; // end of user stack?
 //根据返回地址查找对应的符号（遍历符号表）
    int symbol_idx = backtrace_symbol(*(uint64*)p);
    if (symbol_idx == -1) {
      sprint("fail to backtrace symbol %lx\n", *(uint64*)p);
      continue;
    }
 //打印函数名称，根据符号表索引获得在字符串的偏移，然后获得该符号
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
    case SYS_user_backtrace:
      return sys_user_backtrace(a1);
    default:
      panic("Unknown syscall %ld \n", a0);
  }
}
