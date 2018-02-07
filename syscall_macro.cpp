#include "syscall_macro.h"

std::map<std::string , ice_syscall_entry_t> g_mp_syscalls;

std::map<unsigned int , ice_syscall_entry_t> g_mp_syscalls_id;

uint32_t fk_default_syscall(uc_engine *uc, uint32_t* args, uint32_t len)
{
	return 0;
}


void ice_sys_call_add(std::string syscall_name, unsigned int syscall_id , uint32_t args_count)
{
	ice_syscall_entry_t entry;
	entry.syscall_id = syscall_id;
	entry.syscall_name = syscall_name;
	entry.args_count = args_count;
	entry.syscall_func = fk_default_syscall;
	g_mp_syscalls[syscall_name] = entry;
	g_mp_syscalls_id[syscall_id] = entry;

}

uint32_t ice_sys_call_add_callback(std::string syscall_name, syscall_func_t callback)
{
	std::map<std::string , ice_syscall_entry_t>::iterator it;


	it = g_mp_syscalls.find(syscall_name);
	
	if(it == g_mp_syscalls.end())
	{
		printf("service name doesn't exist\n");
		return -1;

	}

	ice_syscall_entry_t entry;
	entry = g_mp_syscalls[syscall_name];
	entry.syscall_func = callback;

	g_mp_syscalls[syscall_name] = entry;
	
	g_mp_syscalls_id[entry.syscall_id] = entry;

	return 0;
}

extern FILE *log_file;

uint32_t ice_syscall(uc_engine *uc , uint32_t service_id, uint32_t * args, uint32_t len)
{

	std::map<uint32_t , ice_syscall_entry_t>::iterator it;

	fprintf(log_file, "enter ice_syscall 0x%x\n", service_id);

	it = g_mp_syscalls_id.find(service_id);
	
	if(it == g_mp_syscalls_id.end())
	{
		printf("service id doesn't exist\n");
		return -1;

	}

	
	uint32_t ret;

	ret = it->second.syscall_func(uc, args, it->second.args_count);

	uc_reg_write(uc, UC_X86_REG_EAX, &ret);

	fprintf(log_file, "exit ice_syscall 0x%x\n", service_id);


	return ret;

}



int ice_get_syscall_by_id(unsigned int syscall_id , ice_syscall_entry_t* entry)
{
	std::map<unsigned int , ice_syscall_entry_t>::iterator it;



	it = g_mp_syscalls_id.find(syscall_id);
	
	if(it == g_mp_syscalls_id.end())
	{
		return -1;

	}

	entry->syscall_id = it->second.syscall_id;

	entry->syscall_name = it->second.syscall_name;

	entry->syscall_func = it->second.syscall_func;
	

	return 0;
}



int ice_get_syscall_by_name(std::string syscall_name , ice_syscall_entry_t* entry)
{

	std::map<std::string , ice_syscall_entry_t>::iterator it;

	it = g_mp_syscalls.find(syscall_name);
	
	if(it == g_mp_syscalls.end())
	{
		return -1;

	}

	entry->syscall_id = it->second.syscall_id;

	entry->syscall_name = it->second.syscall_name;

	entry->syscall_func = it->second.syscall_func;


	return 0;

}