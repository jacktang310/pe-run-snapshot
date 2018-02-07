#ifndef __FK_MEMORY_H__
#define __FK_MEMORY_H__

#include <stdint.h>
#include <map>
#include <unicorn/unicorn.h>

#define FK_MEMORY_MEMORY_START 0x90000000

#define FK_MEMORY_MAP_UNIT 0x10000000

#define FK_MEMORY_PAGE_MASK 0xfff

#define FK_MEMORY_PAGE_ALIGN_MASK 0xfffff000

#define FK_MEMORY_PAGE_SIZE 0x1000

#define FK_MEMORY_ROUND_DOWN_PAGE(dest)  dest = dest & FK_MEMORY_PAGE_ALIGN_MASK
    

#define FK_MEMORY_ROUND_UP_PAGE(dest)  \
    if(dest & FK_MEMORY_PAGE_MASK) {\
    dest = (dest+FK_MEMORY_PAGE_SIZE) & FK_MEMORY_PAGE_ALIGN_MASK; \
    }
    


typedef struct _fk_region 
{
    uint32_t start;
    uint32_t size;

}fk_region;

template< typename T >
struct fk_array_deleter
{
  void operator ()( T const * p)
  { 
    delete[] p; 
  }
};

class fk_memory_mgr_t 
{
    public:
        static fk_memory_mgr_t * create(uc_engine * uc)
        {
            if (_this)
                return _this;

            _this = new fk_memory_mgr_t(uc);

            return _this;
            
        }


        static fk_memory_mgr_t * get()
        {
            return _this;
            
        }





        static fk_memory_mgr_t * free()
        {
            if(!_this)
                delete  _this;
            
            _this = NULL;
        }


    protected:
        fk_memory_mgr_t(uc_engine * uc);

        
    public:
        uint32_t alloc( uint32_t* addr, uint32_t* len);
                

    private:
        static fk_memory_mgr_t * _this;
        uc_engine * _uc;

        uint32_t _init_map_start;

        uint32_t _current_map_start; 

        uint32_t _total_size;

        uint32_t _current_available_addr;

        uint32_t _last_alloc_addr;

        uint32_t _last_alloc_len;

        

    private:
        //std::map< uint32_t , fk_region> _mpRegions;

};




#endif 