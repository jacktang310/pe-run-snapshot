#include "fk_memory.h"

#define TEST_EMU(ret,txt) if(ret) { printf("%s fail! errno: 0x%x\n" , txt, ret ); }

fk_memory_mgr_t * fk_memory_mgr_t::_this = NULL;

fk_memory_mgr_t::fk_memory_mgr_t(uc_engine * uc)
{
    _uc = uc;
    _init_map_start = FK_MEMORY_MEMORY_START;
    _current_map_start = _init_map_start;
    _total_size = FK_MEMORY_MAP_UNIT;
    _current_available_addr = FK_MEMORY_MEMORY_START;
    _last_alloc_addr = 0;
    _last_alloc_len = 0;
    
    
    uc_err err;
    err = uc_mem_map(uc, _init_map_start, FK_MEMORY_MAP_UNIT, UC_PROT_ALL);
    TEST_EMU(err, "uc_mem_map(FK_MEMORY_START)");
}

uint32_t fk_memory_mgr_t::alloc( uint32_t* addr, uint32_t* len)
{
    printf("hit %s\n", __func__);
    if(*addr)
    {
        return 0;
        
    }

    if ((*len) & FK_MEMORY_PAGE_MASK )
    {
        *len = *len + FK_MEMORY_PAGE_SIZE;
    }

    //only handle *addr == 0 condition

    if((_current_available_addr + *len + FK_MEMORY_PAGE_SIZE) >  (_init_map_start + _total_size))
    {
        printf("need to enlarge mapping. _current_available_addr: %x *len: %x\n", _current_available_addr, *len );

        //current size of memory mapping doesn't fulfil this allocation

        _current_map_start = _current_map_start+ FK_MEMORY_MAP_UNIT;

        uc_err err;

        printf("uc_mem_map(%x, %x)\n", _current_map_start,  FK_MEMORY_MAP_UNIT);

        err = uc_mem_map(_uc, _current_map_start, FK_MEMORY_MAP_UNIT, UC_PROT_ALL);

        TEST_EMU(err, "uc_mem_map(_current_map_start) fail!");

        if(err)
        {
            return -1;
            
        }

        _total_size += FK_MEMORY_MAP_UNIT;
        
        
    }

    _last_alloc_addr = _current_available_addr;

    _last_alloc_len = *len;


    _current_available_addr +=  (*len +  FK_MEMORY_PAGE_SIZE);

    *addr = _last_alloc_addr;


    printf("sysenter: %s: _last_alloc_addr: %x\n", __func__, _last_alloc_addr);

    return 0;
}