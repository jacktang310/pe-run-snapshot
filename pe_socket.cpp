#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "pe_socket.h"
#include <vector>

#define DEFAULT_PORT 6789
#define MAXPENDING 20
#define BUFFERSIZE 0x2000
#define END_OF_PACKAGE "chengguo_hongfan"
#include <netinet/tcp.h>

unsigned long long num = 0ll;
extern void unpackage(char *buf);


std::vector<unsigned char> vec_buf;
void Die(char* mess){
    perror(mess);
    exit(1);
}

void parse_buf(unsigned char* total_buf,size_t total_size){
    unsigned char * cur_pos = total_buf;
    int pack_code ;
    int pack_length ;
    size_t index = 0;
    bool not_done = true;
    while (not_done){
        pack_code = ((int*)(total_buf+index))[0];
        pack_length = ((int*)(total_buf+index))[1];
        printf("code = 0x%08x , length = 0x%08x \n",pack_code,pack_length);
        
        if (index + 8 + pack_length +16+8 == total_size){
            printf("all parse done\n");
            not_done = false;
        }
        unpackage((char*)(cur_pos+index));
        index = index + 8 + pack_length + 16;
        if (pack_length == 0 ){
            printf("packet length == 0 \n");
            break;
        }
    }
}
long long cur_index_beg = 0;
long long cur_index_end = 0;
void recv_buf_by_length(unsigned char* recv_buf,int length){
    cur_index_end += length;
    while (true){
        if (cur_index_end > vec_buf.size()){
            //printf("cur_index_end = %d , need length = %d\n",cur_index_end,length);
            sleep(1);
            continue;
        }
        std::copy(vec_buf.begin()+cur_index_beg,vec_buf.begin()+cur_index_end,recv_buf);
        break;
    }
    cur_index_beg = cur_index_end;

}


//// temp solution 2 time  fork
void HandleClient(int sock) {
    unsigned char buffer[BUFFERSIZE] = { 0 };
    int received = -1;
    int i,j;
    if ((received = recv(sock, buffer, BUFFERSIZE, 0)) < 0) {
        Die("Failed to receive initial bytes from client \n");
    }
    //FILE* f_eli = NULL;
    //f_eli = fopen("recv_res.txt","wb");

    while (received > 0) {
        //printf("Recv : %d bytes ", received);
        for(i = 0 ; i < received; ++i){
            vec_buf.push_back(buffer[i]);
        }
        //fwrite(buffer, 1, received, f_eli);

        //fflush(f_eli);

        memset(buffer, 0, BUFFERSIZE);
        
        if ((received = recv(sock, buffer, BUFFERSIZE, 0)) < 0) {
            Die("Failed to receive additional bytes from client \n");
        }
    }


    // printf("size of vec_buf = %d \n",vec_buf.size());
    // unsigned char * buf_unpack = new unsigned char[vec_buf.size()];
    // if (buf_unpack == NULL){
    //     printf("allocate buf_unpack failed!\n");
    //     exit(1);
    // }
    // std::copy(vec_buf.begin(),vec_buf.end(),buf_unpack);
    

    // parse_buf(buf_unpack,vec_buf.size());

    // free(buf_unpack);
    // vec_buf.clear();
    close(sock);

}

void* pe_recv_buf(void* arg){
    int socket_fd,connect_fd;
    struct sockaddr_in servaddr,clientaddr;
    int n;

    if((socket_fd = socket(AF_INET,SOCK_STREAM,0)) == -1){
        Die("Failed to create socket \n");
    }
    memset(&servaddr,0,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(DEFAULT_PORT);

    // int yes = 1;
    // int result = setsockopt(socket_fd,
    //                         IPPROTO_TCP,
    //                         TCP_NODELAY,
    //                         &yes, 
    //                         sizeof(int));    // 1 - on, 0 - off
    // if (result < 0){
    //     printf("setsockopt error!\n");
    //     exit(1);
    // }

    if (bind(socket_fd,(struct sockaddr*)&servaddr,sizeof(servaddr)) == -1){
        Die("Failed to bind the server socket \n");
    }
    if(listen(socket_fd,MAXPENDING) == -1)
    {
        Die("Failed to listen on server socket \n");
    }

    printf("=======waiting for client's request=======\n");
    vec_buf.clear();
    while(1){
        unsigned int clientlen = sizeof(clientaddr);
        if ((connect_fd = accept(socket_fd,(struct sockaddr*)&clientaddr,&clientlen)) == -1){
            printf("accept socket error : %s (errno: %d)",strerror(errno),errno);
            continue;
        }
        fprintf(stdout,"client connected : %s \n",inet_ntoa(clientaddr.sin_addr));
        HandleClient(connect_fd);
    }
}