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

long int size_fp = 0;

char* target_rfm = "ota_rfm.bin";
char* target_lock = "ota_lock.bin";
char* target_patch = "ota_patch.bin";
char* target_bin;
char* target_pubkey = "APAC_pubkey.bin";
char* target_sharekey = "APAC_sharekey.bin";
char* lock_para = "-lock";
char* rfm_para = "-rfm";
char* patch_para = "-patch";

int buffer[10] = { 0 };
unsigned char SHA256_IMG[32];
unsigned char AES_SHA256[32] = { 0 };
unsigned char PUB_KEY[32] = { 0 };
unsigned char ivec[16] = "0000000000000000";
unsigned char AES128_KEY[16] = { 0 };


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
    fwrite(buffer,1,size,fp); 
    fclose(fp);  
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
    fwrite(buffer,1,size,fp);
    fclose(fp);  
}  



void APAC_compute_sha256(char * fileaddr,unsigned char *sha256_img_tmp)  
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

    //申请一块能装下整个文件的空间  
    char *read_buffer = (char*)malloc(sizeof(char)*size_fp);  

    //读文件  
    fread(read_buffer,1,size_fp,fp);

	SHA256((const unsigned char *)read_buffer, size_fp, sha256_img_tmp);
	
    free(read_buffer);  
    fclose(fp);  
}  


void APAC_read(char * fileaddr, unsigned char * aes_key)
{
	FILE *fp;
	int i = 0;
	unsigned char *tmp_buffer = aes_key;
	//二进制方式打开文件  
	fp = fopen(fileaddr, "rb");
	if (NULL == fp)
	{
		printf("Error:Open input.c file fail!\n");
		return;
	}

	//求得文件的大小  
	fseek(fp, 0, SEEK_END);
	size_fp = ftell(fp);
	rewind(fp);
	

	//读文件  
	fread(tmp_buffer, 1, size_fp, fp);

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
    fwrite(buffer,1,size,fp); 
  
    fclose(fp);  
}  

//合并文件组
void MergeFiles(char** sFiles,int nFileCount,char* _target)
{   
    int i = 0;
    //当前文件，目标文件 
    FILE *current,*target;
    int length = 0;
    char* s;
    target = fopen(_target,"wb");           //open file writable binary 
    for(i = 0; i < nFileCount ; i++)        //merge file counts 
    {
        current = fopen(sFiles[i],"rb");     
        fseek(current,0,SEEK_END);          //located at the end of file
        length = ftell(current);            //get  the length
        if(!length) return;

        fseek(current,0,SEEK_SET);          //located at the beginning of the current file
        s = (char*)malloc(length);           
        fread(s,1,length,current);          //read to buffer 
        fwrite(s,1,length,target);          //write 
        fclose(current);                    
    }
    fclose(target);                         
}


int main(int argc, char* argv[])
{  
	char** merger_files=(char**)malloc(100);
	char * app_addr;
	char * aes_key_addr;

	int i = 0;


	if(argc !=6){
		printf("Usage for rfm: Merge_bin.exe <-rfm> <rfm_header.bin> <app1.bin> <aes128_key.bin> \n");
		printf("Usage for lock: Merge_bin.exe <-lock> <lock_header.bin> <app2.bin> <aes128_key.bin> \n");
		printf("Usage for patch: Merge_bin.exe <-patch> <patch_header.bin> <app3.bin> <aes128_key.bin> \n");
		return;
	}
	merger_files[0]=argv[2];//heaer.bin
	merger_files[1]=argv[3];//app.bin
	merger_files[2]=target_pubkey;
	app_addr = argv[3];
	aes_key_addr = argv[4];
	target_bin = argv[5];


	/**
	 * Merge flow
	 * 1. Get AES128_KEY from ota_sign_pubkey.bin 
	 * 2. Compute asset SHA256 
	 * 3. Encrypt SHA256 with AES128_CBC
	 * 4. Generate public key with the EN25519 algorithm
	 */


	

	//1. Get AES128_KEY from ota_sign_pubkey.bin
	APAC_read(aes_key_addr, AES128_KEY);

	//2. Compute asset SHA256 
	APAC_compute_sha256(app_addr, SHA256_IMG);

	APAC_write_sha256(SHA256_IMG, 32);




	//3. Encrypt SHA256 with AES128_CBC
	aes_encrypt_PKCS5Padding(SHA256_IMG, strlen(SHA256_IMG), AES128_KEY, ivec, AES_SHA256);


	//4. Generate public key with the EN25519 algorithm
	scalarmult(PUB_KEY, SHA256_IMG , AES_SHA256);

	APAC_write_pubkey(PUB_KEY,32);

	if (!strcmp(argv[1], rfm_para))
		MergeFiles(merger_files,3, target_bin);
	else if (!strcmp(argv[1], lock_para))
		MergeFiles(merger_files, 3, target_bin);
	else if (!strcmp(argv[1], patch_para))
		MergeFiles(merger_files, 3, target_bin);

	

    return 0;  
} 

