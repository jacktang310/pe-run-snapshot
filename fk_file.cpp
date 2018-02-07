#include "fk_file.h"
#include <ctype.h>

extern FILE *log_file;
#define OUT_LOG (0)
#define OUT_TRACE (1)

#define out_string(TYPE, ...) {                 \
    if (TYPE == OUT_TRACE) {                    \
        if (log_file == NULL)                   \
            printf(__VA_ARGS__);                \
        else                                    \
            fprintf(log_file, __VA_ARGS__);     \
    } else {                                    \
        printf(__VA_ARGS__);                    \
    }                                           \
}                           




#define TEST_EMU(ret,txt) if(ret) { printf("%s fail! errno: 0x%x\n" , txt, ret ); return -1;}


fk_file_mgr_t * fk_file_mgr_t::_this = NULL;

fk_file_mgr_t::fk_file_mgr_t(uc_engine * uc)
{
    _uc = uc;

    _current_available_handle = 0;

    _last_handle = 0;

}


uint32_t fk_file_mgr_t::create_file( uint32_t            FileHandle,
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
                            )
{
    if(!FileHandle )
        return -1;

    if(!IoStatusBlock)
        return -1;

    printf("hit fk_file_mgr_t::create_file\n");

    uint32_t FileHandle_content = 0;


    FileHandle_content = _current_available_handle;


    _last_handle = _current_available_handle;


    _current_available_handle = _current_available_handle+1;



    uc_err err;
    err = uc_mem_write(_uc, FileHandle, &FileHandle_content, sizeof(FileHandle_content));
    TEST_EMU(err, "uc_mem_write(FileHandle) failed");

    
    FK_IO_STATUS_BLOCK IoStatusBlock_content;
    IoStatusBlock_content.Status = 0;
    IoStatusBlock_content.Information = FK_FILE_CREATED;

    err = uc_mem_write(_uc, IoStatusBlock, &IoStatusBlock_content, sizeof(IoStatusBlock_content));
    TEST_EMU(err, "uc_mem_write(IoStatusBlock) failed");

    printf("ObjectAttributes: %x\n", ObjectAttributes );

    // for(int j = 0; j<0x10; j++)
    // {
    //     uint8_t ch = 0;
    //     uc_mem_read(_uc , ObjectAttributes+j, &ch, sizeof(ch));

    //     printf("%x\n", ch); 

    // }

    uint32_t filename_len;
    err = uc_mem_read(_uc , ObjectAttributes+0x4, &filename_len ,sizeof(filename_len));
    TEST_EMU(err, "uc_mem_read(ObjectAttributes+0x4) failed");

    
    uint32_t filename_ptr;
    err = uc_mem_read(_uc,ObjectAttributes+0x8, &filename_ptr ,sizeof(filename_ptr));
    TEST_EMU(err, "uc_mem_read(ObjectAttributes+0xc) failed"); 

    err = uc_mem_read(_uc,filename_ptr+0x4, &filename_ptr ,sizeof(filename_ptr));
    TEST_EMU(err, "uc_mem_read(filename_ptr+0x8) failed"); 


    char filename[0x100] = {0};
    //err= uc_mem_read(_uc, filename_ptr, filename, filename_len <= sizeof(filename[0x100]) ? filename_len : sizeof(filename[0x100]));

    err= uc_mem_read(_uc, filename_ptr, filename, 0x100);
    TEST_EMU(err, "uc_mem_read(filename_ptr) failed"); 

    out_string(OUT_TRACE, "sysenter:NtCreateFile: ");

    

    for(int i = 0; i<0x100; i++)
    {
       //if(i%2 ==0) 
         //printf("%c", filename[i]);   

        if(isprint(filename[i]))
            out_string(OUT_TRACE, "%c", filename[i]);
    }

    out_string(OUT_TRACE, "\n");

    return 0;

}



uint32_t fk_file_mgr_t::open_file( uint32_t            FileHandle,
                            uint32_t        DesiredAccess,
                            uint32_t ObjectAttributes,
                            uint32_t   IoStatusBlock,
                            uint32_t              ShareAccess,
                            uint32_t              OpenOptions)
{
    if(!FileHandle )
        return -1;

    if(!IoStatusBlock)
        return -1;

       uint32_t FileHandle_content = 0;

    FileHandle_content = _current_available_handle;

    _last_handle = _current_available_handle;

    _current_available_handle = _current_available_handle+1;
    
    uc_err err;
    err = uc_mem_write(_uc, FileHandle, &FileHandle_content, sizeof(FileHandle_content));
    TEST_EMU(err, "uc_mem_write(FileHandle) failed");

    FK_IO_STATUS_BLOCK IoStatusBlock_content;
    IoStatusBlock_content.Status = 0;
    IoStatusBlock_content.Information = FK_FILE_OPENED;

    err = uc_mem_write(_uc, IoStatusBlock, &IoStatusBlock_content, sizeof(IoStatusBlock_content));
    TEST_EMU(err, "uc_mem_write(IoStatusBlock) failed");

    return 0;

}

uint32_t fk_file_mgr_t::read_file(uint32_t           FileHandle,
                            uint32_t           Event,
                            uint32_t          ApcRoutine,
                            uint32_t            ApcContext,
                            uint32_t IoStatusBlock,
                            uint32_t            Buffer,
                            uint32_t           Length,
                            uint32_t   ByteOffset,
                            uint32_t           Key
                            )
{
    if(!FileHandle )
        return -1;

    if(!Buffer)
        return -1;

    if(!Length)
        return -1;

    
    uc_err err;

    FK_IO_STATUS_BLOCK IoStatusBlock_content;
    IoStatusBlock_content.Status = 0;
    IoStatusBlock_content.Information = Length;

    err = uc_mem_write(_uc, IoStatusBlock, &IoStatusBlock_content, sizeof(IoStatusBlock_content));
    TEST_EMU(err, "uc_mem_write(IoStatusBlock) failed");

    return 0;

}


uint32_t fk_file_mgr_t::write_file(uint32_t         FileHandle,
                            uint32_t               Event,
                            uint32_t      ApcRoutine ,
                            uint32_t                ApcContext,
                            uint32_t    IoStatusBlock,
                            uint32_t                Buffer,
                            uint32_t                Length,
                            uint32_t       ByteOffset ,
                            uint32_t               Key
                            )
{
    if(!FileHandle )
        return -1;

    if(!Buffer)
        return -1;

    if(!Length)
        return -1;

    uc_err err;

    FK_IO_STATUS_BLOCK IoStatusBlock_content;
    IoStatusBlock_content.Status = 0;
    IoStatusBlock_content.Information = Length;   

    err = uc_mem_write(_uc, IoStatusBlock, &IoStatusBlock_content, sizeof(IoStatusBlock_content));
    TEST_EMU(err, "uc_mem_write(IoStatusBlock) failed");

    return 0;
}


