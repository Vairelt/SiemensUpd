#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <cstdlib>

#define BIGENDIADN(v20) *(v20+3) + ((*(v20+2) + ((*(v20+1) + (*v20 << 8)) << 8)) << 8)

typedef unsigned int uint32;
typedef unsigned short int uint16;
typedef unsigned char uint8;

#pragma pack(push, 1)
struct SiemensUpd {
    struct CompressedObjhdr {
        uint32 size;
        uint32 CRC;
        char name[6];
    };

    struct UpdHeader {
        uint32 unused[3];
        char FirmwareName[32];
        CompressedObjhdr obj[4];
    };

    UpdHeader hdr;
};

struct lzp3_chunk {
    uint32 chunk_size;
    uint8 unused;
    uint8 paddSize;
    uint8 plainText[4];
    uint8 data;
};
#pragma pack(pop)

uint32 HASHFUNC(uint32 C){
    return ((C >> 15) ^ C) & 0xFFFF;
}

static uint8* hashtable[0x10000];

uint8* getData(const char* filename) {
    FILE* file = fopen(filename, "rb+");
    if (file == NULL) return 0;
    fseek(file, 0, SEEK_END);
    long int size = ftell(file);
    fclose(file);
    // Reading data to array of unsigned chars
    file = fopen(filename, "rb+");
    uint8* in = (uint8*)malloc(size);
    if (in == NULL) return 0;
    int bytes_read = fread(in, sizeof(uint8), size, file);
    fclose(file);
    return in;
}

void addIndex(uint32 C, uint8* val) {
    hashtable[HASHFUNC(C)] = val;
}

uint8* getIndex(uint32 C) {
    if (hashtable[HASHFUNC(C)] != nullptr) {
        return hashtable[HASHFUNC(C)];
    }
    else {
        return nullptr;
    }
}

uint32 getChunksCount(lzp3_chunk* start_chunk, uint32 size_) {
    long int size = size_;
    uint32 chunksCount = 0;
    lzp3_chunk* current_chunk = start_chunk;
    while (size > 0) {
        chunksCount++;
        size -= 4;
        size -= current_chunk->chunk_size;
        current_chunk = (lzp3_chunk*)((uint8*)&current_chunk->unused + current_chunk->chunk_size);
    }
    return chunksCount;
}

#define FIRMWARE "6ES7 212-1HE40-0XB0 V04.02.00.upd"

int main()
{
    memset(hashtable, 0, sizeof(hashtable));
    uint8* in = getData(FIRMWARE);
    SiemensUpd* hdr = (SiemensUpd*)in;
    lzp3_chunk* current_chunk = (lzp3_chunk*)(in + 0x64 + 12 + hdr->hdr.obj[0].size);
    uint32 obj2size = hdr->hdr.obj[1].size;
    uint32 chunksCount = getChunksCount(current_chunk, obj2size);
    printf("chunk0 size 0x%x chunksCount %x\n", current_chunk->chunk_size, chunksCount);
    uint8* out = (uint8*)malloc((0x10000 * (size_t)chunksCount) + 0x100);
    if (out == NULL) return 0;

    memset(out, 0, (0x10000 * (size_t)chunksCount) + 0x100);
    uint8* data = (uint8 *)current_chunk;
    uint8* decoded = out;
    while(chunksCount > 0){
        current_chunk = (lzp3_chunk*)(data);
        memcpy(decoded, current_chunk->plainText, 4);
        data = &current_chunk->data;
        decoded = (decoded + 4);
        uint8* dataend = ((uint8*)&current_chunk->unused + current_chunk->chunk_size);
        uint8 shift = 7;
        while (data != dataend) {
            uint8 temp = *(data++);
            shift = 7;
            while (shift != 0xff && data != dataend) {
                uint8* src = getIndex(BIGENDIADN((decoded - 4)));
                addIndex(BIGENDIADN((decoded - 4)), decoded);
                if ((temp >> shift) & 1) {
                    if (src == 0) {
                        printf("Alert, bad compressed file\n");
                        return -1;
                    }
                    else {
                        for (uint32 i = *data; i > 0; i--) {
                            *(decoded++) = *(src++);
                        }
                    }
                }
                else {
                    *(decoded++) = *data;
                }
                if (shift == 0) shift = 0xff; else shift--;
                data++;
            }
        }
        decoded = (uint8*)((uint32)decoded&0xfffffffc);
        chunksCount--;
        printf("chunksize %x shift %x chunksCount %x sizedecoded %lx\n", current_chunk->chunk_size, shift, chunksCount,(decoded-out));
    }
	
    FILE* file = fopen(FIRMWARE ".bin", "wb+");
    int bytes_written = fwrite(out, sizeof(unsigned char), (decoded - out), file);
    fclose(file);
    free(in);
    return 0;
}

