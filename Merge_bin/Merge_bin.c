#include "stdafx.h"
#include "openssl/sha.h"
#include "string.h"

#include <stdio.h>  
#include <stdlib.h> 
#include "scalarmult.h"

long int size = 0;  
char *ar ;  
 
void APAC_write_pubkey(unsigned char * buffer , int size )  
{  
    FILE *fp;  
	int i=0;
    //二进制方式打开文件  
    fp = fopen("APAC_pubkey.bin","wb");  
    if(NULL == fp)  
    {  
        printf("Error:Open input.c file fail!\n");  
        return;  
    }  

    //读文件  
    fwrite(buffer,1,size,fp);//每次读一个，共读size次  
  

	for(i=0;i<size;i++){
		//printf("%02X\n",ar[i]);
	}
    fclose(fp);  
    //free(ar);  
}  

void APAC_write_sharekey(unsigned char * buffer , int size )  
{  
    FILE *fp;  
	int i=0;
    //二进制方式打开文件  
    fp = fopen("APAC_sharekey.bin","wb");  
    if(NULL == fp)  
    {  
        printf("Error:Open input.c file fail!\n");  
        return;  
    }  

    //读文件  
    fwrite(buffer,1,size,fp);//每次读一个，共读size次  
  

	for(i=0;i<size;i++){
		//printf("%02X\n",ar[i]);
	}
    fclose(fp);  
    //free(ar);  
}  



void APAC_read(char * fileaddr)  
{  
    FILE *fp;  
  	int i=0;
    //二进制方式打开文件  
    fp = fopen(fileaddr,"rb");  
    if(NULL == fp)  
    {  
        printf("Error:Open input.c file fail!\n");  
        return;  
    }  

    //求得文件的大小  
    fseek(fp, 0, SEEK_END);  
    size = ftell(fp);  
    rewind(fp); 
	printf("size=%d\n",size);

    //申请一块能装下整个文件的空间  
    ar = (char*)malloc(sizeof(char)*size);  

    //读文件  
    fread(ar,1,size,fp);//每次读一个，共读size次  
	for(i=0;i<size;i++){
		//printf("%02X\n",ar[i]);
	}
    fclose(fp);  
}  

void APAC_write_sha256(unsigned char * buffer , int size )  
{  
    FILE *fp;
	int i=0;
    //二进制方式打开文件  
    fp = fopen("APAC_SHA256.bin","wb");  
    if(NULL == fp)  
    {  
        printf("Error:Open input.c file fail!\n");  
        return;  
    }  

    //读文件  
    fwrite(buffer,1,size,fp);//每次读一个，共读size次  
  

	for(i=0;i<size;i++){
		//printf("%02X\n",ar[i]);
	}
    fclose(fp);  
    free(ar);  
}  

//合并文件组
void MergeFiles(char** sFiles,int nFileCount,char* _target)
{   
    int i = 0;
    //当前文件，目标文件 
    FILE *current,*target;
    int length = 0;
    char* s;
    target = fopen(_target,"wb");           //以可写的二进制模式打开目标文件 
    for(i = 0; i < nFileCount ; i++)        //根据文件个数遍历源文件组 
    {
        current = fopen(sFiles[i],"rb");    //以二进制只读模式打开当前源文件 
        fseek(current,0,SEEK_END);          //定位到当前源文件末尾 
        length = ftell(current);            //获取当前源文件指针的位置，即获取了文件长度
        if(!length)
            return;
        fseek(current,0,SEEK_SET);          //定位到当前源文件开头 
        s = (char*)malloc(length);          //读取源文件的缓存区 
        fread(s,1,length,current);          //将源文件的内容读至缓存区 
        fwrite(s,1,length,target);          //将缓存区里的内容写至目标文件 
        fclose(current);                    //关闭当前源文件，开始进行下一个源文件的读取 
    }
    fclose(target);                         //关闭目标文件 
}


int buffer[10]={0};

int main(int argc, char* argv[])
{  
	char** p=(char**)malloc(100);
	int j=0;

	char* target_rfm= "ota_rfm.bin";
	char* target_lock= "ota_lock.bin";
	char * addr;
	
	unsigned char md[32];  
	// AES_SHA256
    unsigned char AES_SHA256[32] = {0x11, 0x22, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
                           0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
                           0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
                           0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x33};

	// RANDOM_SECKEY
    unsigned char RANDOM_SECKEY[32] = {0x12, 0x23, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
                           0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
                           0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
                           0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x34};

	// PUB_KEY_1
    unsigned char PUB_KEY_1[32] = {0};

	// PUB_KEY_2
    unsigned char PUB_KEY_2[32] = {0};

	// SHARE_KEY
    unsigned char SHARE_KEY[32] = {0};	

	for(j=0;j<argc-1;j++){
		p[j]=argv[j+1];
	}
	addr = argv[2];
	if(argc==5){
		APAC_read(addr);	
		SHA256((const unsigned char *)ar, size, md); 
		printf("Start compute.......................\n");
		scalarmult(PUB_KEY_1, RANDOM_SECKEY, AES_SHA256);
		printf("PUB_KEY_1 has ok\n");
		scalarmult(PUB_KEY_2, md, AES_SHA256);
		printf("PUB_KEY_2 has ok\n");
		scalarmult(SHARE_KEY, RANDOM_SECKEY, PUB_KEY_2);
		printf("SHare key has ok\n");

		APAC_write_pubkey(PUB_KEY_1,32);
		printf("APAC_write_pubkey ok\n");
		APAC_write_sharekey(SHARE_KEY,32);
		printf("APAC_write_sharekey ok\n");
		
 
		APAC_write_sha256(md,32);		
		MergeFiles(p,argc-1,target_rfm);
	}else if(argc==3)
		MergeFiles(p,argc-1,target_lock);
    return 0;  
} 

