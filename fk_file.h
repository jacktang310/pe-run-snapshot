#ifndef __FK_FILE_H__

#define __FK_FILE_H__

#include <stdint.h>
#include <unicorn/unicorn.h>

#include "fk_windows.h"


#define FK_FILE_HANDLE_START 0x100

#define FK_FILE_HANDLE_END 0x6FF



class fk_file_mgr_t
{
    public:
        static fk_file_mgr_t * create(uc_engine * uc)
        {


            if (_this)
                return _this;

            _this = new fk_file_mgr_t(uc);

            

            return _this;
            
        }


        static fk_file_mgr_t * get()
        {
            
            return _this;
            
        }


        static fk_file_mgr_t * free()
        {
            if(!_this)
                delete  _this;
            
            _this = NULL;
        }

    public:
        uint32_t create_file( uint32_t            FileHandle,
                            uint32_t        DesiredAccess,
                            uint32_t ObjectAttributes,
                            uint32_t   IoStatusBlock,
                            uint32_t     AllocationSize,
                            uint32_t              FileAttributes,
                             uint32_t              ShareAccess,
                             uint32_t              CreateDisposition,
                             uint32_t              CreateOptions,
                             uint32_t              EaBuffer,
                             uint32_t              EaLength

                            );

        uint32_t open_file( uint32_t            FileHandle,
                            uint32_t        DesiredAccess,
                            uint32_t ObjectAttributes,
                            uint32_t   IoStatusBlock,
                            uint32_t              ShareAccess,
                            uint32_t              OpenOptions);

        uint32_t read_file(uint32_t           FileHandle,
                            uint32_t           Event,
                            uint32_t          ApcRoutine,
                            uint32_t            ApcContext,
                            uint32_t IoStatusBlock,
                            uint32_t            Buffer,
                            uint32_t           Length,
                            uint32_t   ByteOffset,
                            uint32_t           Key

                            );

        
        uint32_t write_file(  uint32_t         FileHandle,
                            uint32_t               Event,
                            uint32_t      ApcRoutine ,
                            uint32_t                ApcContext,
                            uint32_t    IoStatusBlock,
                            uint32_t                Buffer,
                            uint32_t                Length,
                            uint32_t       ByteOffset ,
                            uint32_t               Key
        );


    protected:
        fk_file_mgr_t(uc_engine * uc);

    private:
        static fk_file_mgr_t * _this;
        uc_engine * _uc;

    private:
        uint32_t _current_available_handle;
        uint32_t _last_handle;
        
}; 



#endif