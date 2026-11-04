// Optional Android instrumentation fixture; never packaged in normal builds.
#include "mint/plugin/sdk.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int probe(const MintPluginHostV1* host,const char* args) {
    if(!host || !args || strlen(args)>4096)return -1;
    char path[4097];snprintf(path,sizeof(path),"%s",args);char* newline=strrchr(path,'\n');
    if(!newline)return -1;*newline++=0;int port=atoi(newline);if(port<1||port>65535)return -1;
    FILE* private_file=fopen(path,"rb");int private_allowed=private_file!=NULL;if(private_file)fclose(private_file);
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK,0),network=0;
    if(fd<0 && errno!=EPERM && errno!=EACCES)network=-1;
    if(fd>=0){struct sockaddr_in address={0};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons((unsigned short)port);
        int result=connect(fd,(const struct sockaddr*)&address,sizeof(address));
        int failure=result==0?0:errno;
        if(result<0&&failure==EINPROGRESS){struct pollfd pending={fd,POLLOUT,0};if(poll(&pending,1,1000)>0){socklen_t length=sizeof(failure);if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&failure,&length))failure=errno;}else failure=ETIMEDOUT;}
        network=failure==0?1:(failure==EPERM||failure==EACCES)?0:-1;close(fd);}
    char result[256];int size=snprintf(result,sizeof(result),"uid=%u private=%s network=%s allow_edits=%u\n",(unsigned)getuid(),private_allowed?"allowed":"denied",network<0?"unknown":network?"allowed":"denied",host->allow_edits);
    return size>0?host->output(host->context,result,(size_t)size):-1;
}
static int edit(const MintPluginHostV1* host,const char* args){
    (void)args;MintPluginFunctionV1 function;uint64_t count=0;
    if(host->function_count(host->context,&count)||!count||host->function_at(host->context,0,&function))return -1;
    return host->edit(host->context,function.entry,"name","must_not_escape");
}
static int crash(const MintPluginHostV1* host,const char* args){(void)host;(void)args;abort();return -1;}
static int hang(const MintPluginHostV1* host,const char* args){(void)host;(void)args;for(;;)pause();return -1;}
static const MintPluginCommandV1 commands[]={{"probe","Isolation probe",probe},{"edit","Attempt forbidden edit",edit},{"crash","Crash worker",crash},{"hang","Hang worker",hang}};
static const MintPluginV1 plugin={MINT_PLUGIN_ABI_V1,sizeof(MintPluginV1),"sandbox_probe","Device isolation test fixture",4,commands};
MINT_PLUGIN_EXPORT const MintPluginV1* mint_plugin_v1(void){return &plugin;}
