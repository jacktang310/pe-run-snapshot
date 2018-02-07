#ifndef __SYSCALL_MACRO__H__

#define __SYSCALL_MACRO__H__

#include <map>
#include <string>
#include <unicorn/unicorn.h>

// typedef unsigned int (*syscall_func_t)(unsigned int a1, 
// 										unsigned int a2, 
// 										 unsigned int a3, 
// 										 unsigned int a4, 
// 										 unsigned int a5, 
// 										 unsigned int a6, 
// 										 unsigned int a7, 
// 										 unsigned int a8, 
// 										 unsigned int a9, 
// 										 unsigned int a10, 
// 										 unsigned int a11, 
// 										 unsigned int a12, 
// 										 unsigned int a13, 
// 										 unsigned int a14, 
// 										 unsigned int a15, 
// 										 unsigned int a16, 
// 										 unsigned int a17, 
// 										 unsigned int a18, 
// 										 unsigned int a19, 
// 										 unsigned int a20
// 										 );

typedef unsigned int (*syscall_func_t)(uc_engine *uc, uint32_t* args, uint32_t len);

typedef struct _ice_syscall_entry_t
{
	unsigned int syscall_id;
	std::string syscall_name;
	unsigned int args_count;
	syscall_func_t  syscall_func;
	
} ice_syscall_entry_t;


extern std::map<std::string, ice_syscall_entry_t> g_mp_syscalls;

extern std::map<unsigned int, ice_syscall_entry_t> g_mp_syscalls_id;

void ice_sys_call_add(std::string syscall_name, unsigned int syscall_id, uint32_t args_count);

uint32_t ice_sys_call_add_callback(std::string syscall_name, syscall_func_t callback);

int ice_get_syscall_by_id(unsigned int syscall_id , ice_syscall_entry_t* entry);

int ice_get_syscall_by_name(std::string syscall_name , ice_syscall_entry_t* entry);

uint32_t ice_syscall(uc_engine *uc , uint32_t service_id, uint32_t * args, uint32_t len);


#define _ICE_SYS_CALL(name, ID, args_count)  ice_sys_call_add(name, ID, args_count);     
		          

#endif