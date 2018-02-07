#include "syscall_win7.h"
#include "fk.h"

#include <memory>

#define TEST_EMU(ret,txt) if(ret) { printf("%s fail! errno: 0x%x\n" , txt, ret ); return -1;}


void ice_syscall_deinit_win7()
{
	fk_memory_mgr_t::free();

}


uint32_t fk_NtAllocateVirtualMemory(uc_engine *uc, uint32_t* args, uint32_t len)
{
	uint32_t ProcessHandle = args[0];
	uint32_t BaseAddress = args[1];
	uint32_t ZeroBits = args[2];
	uint32_t RegionSize = args[3];
	uint32_t AllocationType = args[4];
	uint32_t Protect = args[5];

	uint32_t BaseAddress_content = 0;
	uint32_t RegionSize_content = 0;

	printf("hit fk_NtAllocateVirtualMemory\n");

	uc_err err;

	err = uc_mem_read(uc, BaseAddress, &BaseAddress_content, 4);

	TEST_EMU(err, "uc_mem_read(BaseAddress) failed");

	
	err = uc_mem_read(uc, RegionSize, &RegionSize_content, 4);

	TEST_EMU(err, "uc_mem_read(RegionSize) failed");

	if(RegionSize_content == 0)
		return -1;

	FK_MEMORY_ROUND_UP_PAGE(RegionSize_content);

	
	
	if(BaseAddress_content != 0)
	{

		FK_MEMORY_ROUND_UP_PAGE(BaseAddress_content);

		err = uc_mem_write(uc, BaseAddress, &BaseAddress_content, 4);

		TEST_EMU(err, "uc_mem_write(BaseAddress) failed");

		err = uc_mem_write(uc, RegionSize, &RegionSize_content, 4);

		TEST_EMU(err, "uc_mem_write(RegionSize) failed");

		return 0;
		
	}



	uint32_t ret;

	
	ret = fk_memory_mgr_t::get()->alloc(&BaseAddress_content, &RegionSize_content);

	if(ret < 0)
	{
		return -1;
	}

	err = uc_mem_write(uc, BaseAddress, &BaseAddress_content, 4);

	TEST_EMU(err, "uc_mem_write(BaseAddress) failed");

	err = uc_mem_write(uc, RegionSize, &RegionSize_content, 4);

	TEST_EMU(err, "uc_mem_write(RegionSize) failed");


	return 0;
	
}

uint32_t fk_NtProtectVirtualMemory(uc_engine *uc, uint32_t* args, uint32_t len)
{
	uint32_t ProcessHandle = args[0];
	uint32_t BaseAddress = args[1];
	uint32_t NumberOfBytesToProtect = args[2];
	uint32_t NewAccessProtection = args[3];
	uint32_t OldAccessProtection = args[4];

	uint32_t BaseAddress_content= 0;
	uint32_t NumberOfBytesToProtect_content = 0;

	printf("hit fk_NtProtectVirtualMemory\n");


	uc_err err;
	err = uc_mem_read(uc, BaseAddress, &BaseAddress_content, 4);
	TEST_EMU(err, "uc_mem_read(BaseAddress) failed");

	if(!BaseAddress_content)
		return -1;

	FK_MEMORY_ROUND_DOWN_PAGE(BaseAddress_content);
	err = uc_mem_write(uc, BaseAddress, &BaseAddress_content, 4);
	TEST_EMU(err, "uc_mem_write(BaseAddress) failed");

	err = uc_mem_read(uc, NumberOfBytesToProtect, &NumberOfBytesToProtect_content, 4);
	TEST_EMU(err, "uc_mem_read(NumberOfBytesToProtect) failed");
	
	if(!NumberOfBytesToProtect_content)
		return -1;

	FK_MEMORY_ROUND_UP_PAGE(NumberOfBytesToProtect_content);
	err = uc_mem_write(uc, NumberOfBytesToProtect, &NumberOfBytesToProtect_content, 4);
	TEST_EMU(err, "uc_mem_write(NumberOfBytesToProtect) failed");
	
	err = uc_mem_write(uc, OldAccessProtection, &NewAccessProtection, 4);
	TEST_EMU(err, "uc_mem_write(OldAccessProtection) failed");


	return 0;

}


uint32_t fk_NtReadVirtualMemory(uc_engine *uc, uint32_t* args, uint32_t len)
{
	uint32_t ProcessHandle = args[0];
	uint32_t BaseAddress = args[1];
	uint32_t Buffer = args[2];
	uint32_t NumberOfBytesToRead = args[3];
	uint32_t NumberOfBytesReaded = args[4];

	printf("hit fk_NtReadVirtualMemory\n");

	if (!NumberOfBytesToRead)
		return -1;

	std::shared_ptr<uint8_t>  buf ( new uint8_t[NumberOfBytesToRead], fk_array_deleter<uint8_t>());

	uc_err err;
	err = uc_mem_read(uc, BaseAddress, buf.get(), NumberOfBytesToRead);
	TEST_EMU(err, "uc_mem_read(BaseAddress) failed");

	err = uc_mem_write(uc, Buffer, buf.get() , NumberOfBytesToRead);
	TEST_EMU(err, "uc_mem_write(Buffer) failed");


	if(NumberOfBytesReaded)
	{
		err = uc_mem_write(uc, NumberOfBytesReaded, &NumberOfBytesToRead , sizeof(NumberOfBytesToRead));
		TEST_EMU(err, "uc_mem_write(NumberOfBytesReaded) failed");	

	}

	

	return 0;
}


uint32_t fk_NtWriteVirtualMemory(uc_engine *uc, uint32_t* args, uint32_t len)
{
	uint32_t ProcessHandle = args[0];
	uint32_t BaseAddress = args[1];
	uint32_t Buffer = args[2];
	uint32_t NumberOfBytesToWrite = args[3];
	uint32_t NumberOfBytesWritten = args[4];


	printf("hit fk_NtWriteVirtualMemory\n");

	if(!NumberOfBytesToWrite)
	    return -1;


	std::shared_ptr<uint8_t>  buf ( new uint8_t[NumberOfBytesToWrite], fk_array_deleter<uint8_t>());
	
	uc_err err;
	err = uc_mem_read(uc, Buffer, buf.get(), NumberOfBytesToWrite);
	TEST_EMU(err, "uc_mem_read(BaseAddress) failed");

	err = uc_mem_write(uc, BaseAddress, buf.get() , NumberOfBytesToWrite);
	TEST_EMU(err, "uc_mem_write(BaseAddress) failed");


	if(NumberOfBytesWritten )
	{

		err = uc_mem_write(uc, NumberOfBytesWritten, &NumberOfBytesToWrite , sizeof(NumberOfBytesToWrite));
		TEST_EMU(err, "uc_mem_write(NumberOfBytesWritten) failed");


	}


	return 0;
}


uint32_t fk_NtCreateFile(uc_engine *uc, uint32_t* args, uint32_t len)
{
	uint32_t ret;

	printf("hit fk_NtCreateFile\n");
	
	ret = fk_file_mgr_t::get()->create_file(args[0], args[1],args[2],args[3],args[4],
											args[5], args[6], args[7], args[8], args[9], args[10]);
	if(ret < 0)
	{
		return -1;
	}
	

	return 0;
}

uint32_t fk_NtOpenFile(uc_engine *uc, uint32_t* args, uint32_t len)
{
	uint32_t ret;

	printf("hit fk_NtOpenFile\n");

	ret = fk_file_mgr_t::get()->open_file(args[0], args[1],args[2],args[3],args[4],
											args[5]);
	if(ret < 0)
	{
		return -1;
	}
	

	return 0;

}

uint32_t fk_NtReadFile(uc_engine *uc, uint32_t* args, uint32_t len)
{

	uint32_t ret;

	printf("hit fk_NtReadFile\n");

	ret = fk_file_mgr_t::get()->read_file(args[0], args[1],args[2],args[3],args[4],
											args[5], args[6],args[7],args[8]);	

	if(ret < 0)
	{
		return -1;
	}

	return 0;

}

uint32_t fk_NtWriteFile(uc_engine *uc, uint32_t* args, uint32_t len)
{
	uint32_t ret;

	printf("hit fk_NtWriteFile\n");

	ret = fk_file_mgr_t::get()->write_file(args[0], args[1],args[2],args[3],args[4],
											args[5], args[6],args[7],args[8]);	

	if(ret < 0)
	{
		return -1;
	}

	return 0;
}



////////// init service call /////////////////

void ice_syscall_init_win7(uc_engine *uc)
{
	#include "syscall_win7.inc"


	
	ice_sys_call_add_callback("NtAllocateVirtualMemory", fk_NtAllocateVirtualMemory);

	ice_sys_call_add_callback("NtProtectVirtualMemory", fk_NtProtectVirtualMemory);

	ice_sys_call_add_callback("NtReadVirtualMemory", fk_NtReadVirtualMemory);

	ice_sys_call_add_callback("NtWriteVirtualMemory", fk_NtWriteVirtualMemory);

	ice_sys_call_add_callback("NtCreateFile", fk_NtCreateFile);

	ice_sys_call_add_callback("NtOpenFile", fk_NtOpenFile);

	ice_sys_call_add_callback("NtReadFile", fk_NtReadFile);

	ice_sys_call_add_callback("NtWriteFile", fk_NtWriteFile);


	fk_memory_mgr_t::create(uc);

	fk_file_mgr_t::create(uc);



}





