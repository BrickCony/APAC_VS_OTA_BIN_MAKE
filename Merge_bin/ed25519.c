#include "stdafx.h"
#include "openssl/sha.h"
#include "string.h"

#include <stdio.h>  
#include <stdlib.h> 
#include "scalarmult.h"
#include <openssl/aes.h>
#include <openssl/ssl.h>

#define BLOCK_SIZE 16
#define BUF_LEN  1024 

static const char encodeCharacterTable[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char decodeCharacterTable[256] = {
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
	,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21
	,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
	,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1
};


void base64_encode(unsigned char *input, unsigned input_length, unsigned char *output)
{
	char buff1[3];
	char buff2[4];
	unsigned char i = 0, j;
	unsigned input_cnt = 0;
	unsigned output_cnt = 0;

	while (input_cnt < input_length)
	{
		buff1[i++] = input[input_cnt++];
		if (i == 3)
		{
			output[output_cnt++] = encodeCharacterTable[(buff1[0] & 0xfc) >> 2];
			output[output_cnt++] = encodeCharacterTable[((buff1[0] & 0x03) << 4) + ((buff1[1] & 0xf0) >> 4)];
			output[output_cnt++] = encodeCharacterTable[((buff1[1] & 0x0f) << 2) + ((buff1[2] & 0xc0) >> 6)];
			output[output_cnt++] = encodeCharacterTable[buff1[2] & 0x3f];
			i = 0;
		}
	}
	if (i)
	{
		for (j = i; j < 3; j++)
		{
			buff1[j] = '\0';
		}
		buff2[0] = (buff1[0] & 0xfc) >> 2;
		buff2[1] = ((buff1[0] & 0x03) << 4) + ((buff1[1] & 0xf0) >> 4);
		buff2[2] = ((buff1[1] & 0x0f) << 2) + ((buff1[2] & 0xc0) >> 6);
		buff2[3] = buff1[2] & 0x3f;
		for (j = 0; j < (i + 1); j++)
		{
			output[output_cnt++] = encodeCharacterTable[buff2[j]];
		}
		while (i++ < 3)
		{
			output[output_cnt++] = '=';
		}
	}
	output[output_cnt] = 0;
}

void base64_decode(unsigned char *input, unsigned input_length, unsigned char *output)
{
	char buff1[4];
	char buff2[4];
	unsigned char i = 0, j;
	unsigned input_cnt = 0;
	unsigned output_cnt = 0;

	while (input_cnt < input_length)
	{
		buff2[i] = input[input_cnt++];
		if (buff2[i] == '=')
		{
			break;
		}
		if (++i == 4)
		{
			for (i = 0; i != 4; i++)
			{
				buff2[i] = decodeCharacterTable[buff2[i]];
			}
			output[output_cnt++] = (char)((buff2[0] << 2) + ((buff2[1] & 0x30) >> 4));
			output[output_cnt++] = (char)(((buff2[1] & 0xf) << 4) + ((buff2[2] & 0x3c) >> 2));
			output[output_cnt++] = (char)(((buff2[2] & 0x3) << 6) + buff2[3]);
			i = 0;
		}
	}
	if (i)
	{
		for (j = i; j < 4; j++)
		{
			buff2[j] = '\0';
		}
		for (j = 0; j < 4; j++)
		{
			buff2[j] = decodeCharacterTable[buff2[j]];
		}
		buff1[0] = (buff2[0] << 2) + ((buff2[1] & 0x30) >> 4);
		buff1[1] = ((buff2[1] & 0xf) << 4) + ((buff2[2] & 0x3c) >> 2);
		buff1[2] = ((buff2[2] & 0x3) << 6) + buff2[3];
		for (j = 0; j < (i - 1); j++)
		{
			output[output_cnt++] = (char)buff1[j];
		}
	}
	output[output_cnt] = 0;
}

int aes_encrypt_PKCS5Padding(unsigned char *sz_in_buff, int sz_in_len, unsigned char *key, unsigned char *iv, unsigned char *sz_out_buff)
{
	EVP_CIPHER_CTX ctx;

	int len = 0, isSuccess = 0;
	unsigned char in[BLOCK_SIZE];
	int outl = 0;
	int outl_total = 0;

	EVP_CIPHER_CTX_init(&ctx);

	EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);

	while (sz_in_len >= BLOCK_SIZE)
	{
		memcpy(in, sz_in_buff, BLOCK_SIZE);
		sz_in_len -= BLOCK_SIZE;
		sz_in_buff += BLOCK_SIZE;
		isSuccess = EVP_EncryptUpdate(&ctx, sz_out_buff + outl_total, &outl, in, BLOCK_SIZE);
		if (!isSuccess)
		{
			printf("EVP_EncryptUpdate() failed");
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
		outl_total += outl;
	}

	if (sz_in_len > 0)
	{
		memcpy(in, sz_in_buff, sz_in_len);
		isSuccess = EVP_EncryptUpdate(&ctx, sz_out_buff + outl_total, &outl, in, sz_in_len);
		outl_total += outl;

		isSuccess = EVP_EncryptFinal_ex(&ctx, sz_out_buff + outl_total, &outl);
		if (!isSuccess)
		{
			printf("EVP_EncryptFinal_ex() failed");
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
		outl_total += outl;
	}

	EVP_CIPHER_CTX_cleanup(&ctx);
	return outl_total;
}


int aes_decrypt_PKCS5Padding(unsigned char *sz_in_buff, int sz_in_length, unsigned char *key, unsigned char *iv, unsigned char *sz_out_buff)
{
	unsigned char in[BLOCK_SIZE];
	int outl = 0;
	int outl_total = 0;
	int isSuccess;

	EVP_CIPHER_CTX ctx;

	//初始化ctx，加密算法初始化  
	EVP_CIPHER_CTX_init(&ctx);
	isSuccess = EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);
	if (!isSuccess)
	{
		printf("EVP_DecryptInit_ex() failed");
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	}

	//解密数据  
	while (sz_in_length > BLOCK_SIZE)
	{
		memcpy(in, sz_in_buff, BLOCK_SIZE);
		sz_in_length -= BLOCK_SIZE;
		sz_in_buff += BLOCK_SIZE;

		isSuccess = EVP_DecryptUpdate(&ctx, sz_out_buff + outl_total, &outl, in, BLOCK_SIZE);
		if (!isSuccess)
		{
			printf("EVP_DecryptUpdate() failed");
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
		outl_total += outl;
	}


	if (sz_in_length > 0)
	{
		memcpy(in, sz_in_buff, sz_in_length);
		isSuccess = EVP_DecryptUpdate(&ctx, sz_out_buff + outl_total, &outl, in, sz_in_length);
		outl_total += outl;
	}

	/*解密数据块不为16整数倍时执行 */
	if (sz_in_length % BLOCK_SIZE != 0)
	{
		isSuccess = EVP_DecryptFinal_ex(&ctx, sz_out_buff + outl_total, &outl);
		if (!isSuccess)
		{
			printf("EVP_DecryptFinal_ex() failed\n");
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
		outl_total += outl;
	}

	EVP_CIPHER_CTX_cleanup(&ctx);
	return outl_total;
}








long int size_fp = 0;  
char *ar ;  
char* target_rfm= "ota_rfm.bin";
char* target_lock= "ota_lock.bin";
char* target_patch = "ota_patch.bin";
char* target_pubkey= "APAC_pubkey.bin";
char* target_sharekey= "APAC_sharekey.bin";
char* lock_para ="-lock";
char* rfm_para = "-rfm" ;
char* patch_para = "-patch";
void APAC_write_pubkey(unsigned char * buffer , int size )  
{  
    FILE *fp;  
	int i=0;
    //二进制方式打开文件  
    fp = fopen(target_pubkey,"wb");  
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
    fp = fopen(target_sharekey,"wb");  
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
    size_fp = ftell(fp);  
    rewind(fp); 
	printf("size_fp=%d\n",size_fp);

    //申请一块能装下整个文件的空间  
    ar = (char*)malloc(sizeof(char)*size_fp);  

    //读文件  
    fread(ar,1,size_fp,fp);//每次读一个，共读size次  
	for(i=0;i<size_fp;i++){
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

unsigned char ivec[16] = "0000000000000000";
unsigned char sz_sharekey[16] = { 0x03,0x4B,0x2A,0xF4,0x33,0xAF,0xDF,0xAA,0x78,0xA1,0x1B,0x77,0xD5,0xF5,0x0E,0x85 };

int main(int argc, char* argv[])
{  
	char** p=(char**)malloc(100);
	int j=0;
	char * addr;
	unsigned char md[32];  
	// AES_SHA256
    unsigned char AES_SHA256[32] = {0};

	// PUB_KEY
    unsigned char PUB_KEY[32] = {0};



	if(argc !=4){
		printf("Usage for rfm: Merge_bin.exe <-rfm> <rfm_header.bin> <app.bin> \n");
		printf("Usage for lock: Merge_bin.exe <-lock> <lock_header.bin> <app.bin> \n");
		printf("Usage for patch: Merge_bin.exe <-patch> <patch_header.bin> <patch.bin> \n");
		return;
	}
	p[0]=argv[2];//heaer.bin
	p[1]=argv[3];//app.bin
	p[2]=target_pubkey;
	//p[3]=target_sharekey;
	addr = argv[3];
	if(!strcmp(argv[1],rfm_para)){
		APAC_read(addr);	
		SHA256((const unsigned char *)ar, size_fp, md); 
		printf("Start compute.......................\n");



		int i = 0;

		for (i = 0; i < 32; i++)
		{
			printf("0x%02X,", md[i] & 0xFF);
		}
		printf("  md finish\n");

		memset(AES_SHA256, 0, sizeof(AES_SHA256));
		aes_encrypt_PKCS5Padding(md, strlen(md), sz_sharekey, ivec, AES_SHA256);

		for (i = 0; i < 32; i++)
		{
			printf("0x%02X,", AES_SHA256[i] & 0xFF);
		}
		printf("         ");
		printf("AES_SHA256 length: %d\n\n", sizeof(AES_SHA256));


		scalarmult(PUB_KEY, md , AES_SHA256);
		printf("PUB_KEY has ok\n");
		for (i = 0; i < 32; i++)
		{
			printf("0x%02X,", PUB_KEY[i] & 0xFF);
		}
		printf("         ");
		printf("PUB_KEY length: %d\n\n", sizeof(PUB_KEY));

		APAC_write_pubkey(PUB_KEY,32);
		printf("APAC_write_pubkey ok\n");

		
 
		APAC_write_sha256(md,32);		
		MergeFiles(p,3,target_rfm);
	}else if (!strcmp(argv[1], patch_para)) {
		APAC_read(addr);
		SHA256((const unsigned char *)ar, size_fp, md);
		printf("Start compute patch.......................\n");



		int i = 0;

		for (i = 0; i < 32; i++)
		{
			printf("0x%02X,", md[i] & 0xFF);
		}
		printf("  md finish\n");

		memset(AES_SHA256, 0, sizeof(AES_SHA256));
		aes_encrypt_PKCS5Padding(md, strlen(md), sz_sharekey, ivec, AES_SHA256);

		for (i = 0; i < 32; i++)
		{
			printf("0x%02X,", AES_SHA256[i] & 0xFF);
		}
		printf("         ");
		printf("AES_SHA256 length: %d\n\n", sizeof(AES_SHA256));


		scalarmult(PUB_KEY, md, AES_SHA256);
		printf("PUB_KEY has ok\n");
		for (i = 0; i < 32; i++)
		{
			printf("0x%02X,", PUB_KEY[i] & 0xFF);
		}
		printf("         ");
		printf("PUB_KEY length: %d\n\n", sizeof(PUB_KEY));

		APAC_write_pubkey(PUB_KEY, 32);
		printf("APAC_write_pubkey ok\n");



		APAC_write_sha256(md, 32);
		MergeFiles(p, 3, target_patch);
	}else if(!strcmp(argv[1],lock_para))
		MergeFiles(p,2,target_lock);

    return 0;  
} 

