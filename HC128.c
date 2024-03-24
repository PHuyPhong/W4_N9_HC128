#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

typedef uint32_t uint32;
typedef uint8_t uint8;

#define HC128_N 512

typedef struct {
    uint32 P[512];
    uint32 Q[512];
    uint32 cnt;
} hc128_context;

void init(hc128_context *ctx, const uint8 *key, const uint8 *iv) {
    int i;
    for (i = 0; i < 16; ++i)
        ctx->P[i] = ((uint32 *)key)[i];
    for (i = 0; i < 16; ++i)
        ctx->P[i + 16] = ((uint32 *)iv)[i];
    for (i = 16; i < HC128_N; ++i)
        ctx->P[i] = ctx->P[i - 16] + ROTL(ctx->P[i - 15], 7) + ctx->P[i - 7] + ROTL(ctx->P[i - 2], 16);

    for (i = 0; i < HC128_N; ++i)
        ctx->Q[i] = ctx->P[(ctx->P[i] & 0x3FF) + 0x400];
    
    ctx->cnt = 0;
}

uint32 f(hc128_context *ctx, uint32 x) {
    uint8 t1, t2, t3, t4;
    t1 = x & 0xFF;
    t2 = (x >> 8) & 0xFF;
    t3 = (x >> 16) & 0xFF;
    t4 = (x >> 24) & 0xFF;
    return ctx->Q[t1] + ctx->Q[256 + t2] + ctx->P[HC128_N - 1 - t3] + ctx->P[256 + HC128_N - 1 - t4];
}

uint32 g(hc128_context *ctx, uint32 x) {
    uint8 t1, t2, t3, t4;
    t1 = x & 0xFF;
    t2 = (x >> 8) & 0xFF;
    t3 = (x >> 16) & 0xFF;
    t4 = (x >> 24) & 0xFF;
    return ctx->Q[t1] + ctx->Q[256 + t2] + ctx->P[t3] + ctx->P[256 + t4];
}

void keystream(hc128_context *ctx, uint8 *out, uint32 len) {
    uint32 i;
    uint32 x, y;
    for (i = 0; i < len; ++i) {
        if (ctx->cnt % HC128_N == 0) {
            uint32 j;
            for (j = 0; j < HC128_N - 16; ++j)
                ctx->P[j] = ctx->P[j + 16];
            for (j = 0; j < 16; ++j)
                ctx->P[HC128_N - 16 + j] = f(ctx, ctx->P[j] + ctx->P[j + 1] + ctx->P[j + 14] + ctx->P[j + 15]);
            for (j = 0; j < 16; ++j)
                ctx->Q[j] = ctx->P[(ctx->P[j] & 0x3FF) + 0x400];
            for (j = 16; j < HC128_N; ++j)
                ctx->Q[j] = ctx->P[(ctx->P[j] & 0x3FF)];
            ctx->cnt = 0;
        }
        x = ctx->P[ctx->cnt % HC128_N];
        y = ctx->Q[ctx->cnt % HC128_N];
        ++(ctx->cnt);
        out[i] = x ^ (y >> 16);
    }
}

void encrypt(hc128_context *ctx, const uint8 *plaintext, uint8 *ciphertext, uint32 len) {
    keystream(ctx, ciphertext, len);
    printf("Key: ");
    for(uint32 i=0;i<len;i++){
        printf("%02X",ciphertext[i]);
    }
    for (uint32 i = 0; i < len; ++i)
        ciphertext[i] ^= plaintext[i];
}

int main() {
    hc128_context ctx;
    uint8 key[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    uint8 iv[16] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F};
    uint8 plaintext[] = "This is my program";
    uint32 len = strlen((char *)plaintext);
    uint8 ciphertext[len];

    init(&ctx, key, iv);
    encrypt(&ctx, plaintext, ciphertext, len);
    
    printf("\nPlaintext: %s\n", plaintext);
    printf("Ciphertext: ");
    for (uint32 i = 0; i < len; ++i) {
        printf("%02X", ciphertext[i]);
    }
    printf("\n");

    return 0;
}

