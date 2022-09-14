#include <stdio.h>
#include <string.h>
#include "stdint.h"

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(
        uint32_t state[5],
        const unsigned char buffer[64]
);

void SHA1Init(
        SHA1_CTX * context
);

void SHA1Update(
        SHA1_CTX * context,
        const unsigned char *data,
        uint32_t len
);

void SHA1Final(
        unsigned char digest[20],
        SHA1_CTX * context
);

void SHA1(
        char *hash_out,
        const char *str,
        int len);


#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#elif BYTE_ORDER == BIG_ENDIAN
#define blk0(i) block->l[i]
#else
#error "Endianness not defined!"
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


/* Hash a single 512-bit block. This is the core of the algorithm. */

void SHA1Transform(
        uint32_t state[5],
        const unsigned char buffer[64]
)
{
    uint32_t a, b, c, d, e;

    typedef union
    {
        unsigned char c[64];
        uint32_t l[16];
    } CHAR64LONG16;

#ifdef SHA1HANDSOFF
    CHAR64LONG16 block[1];      /* use array to appear as a pointer */

    memcpy(block, buffer, 64);
#else
    /* The following had better never be used because it causes the
     * pointer-to-const buffer to be cast into a pointer to non-const.
     * And the result is written through.  I threw a "const" in, hoping
     * this will cause a diagnostic.
     */
    CHAR64LONG16 *block = (const CHAR64LONG16 *) buffer;
#endif
    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a, b, c, d, e, 0);
    R0(e, a, b, c, d, 1);
    R0(d, e, a, b, c, 2);
    R0(c, d, e, a, b, 3);
    R0(b, c, d, e, a, 4);
    R0(a, b, c, d, e, 5);
    R0(e, a, b, c, d, 6);
    R0(d, e, a, b, c, 7);
    R0(c, d, e, a, b, 8);
    R0(b, c, d, e, a, 9);
    R0(a, b, c, d, e, 10);
    R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12);
    R0(c, d, e, a, b, 13);
    R0(b, c, d, e, a, 14);
    R0(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);
    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);
    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);
    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
#ifdef SHA1HANDSOFF
    memset(block, '\0', sizeof(block));
#endif
}


/* Run your data through this. */

void SHA1Update(
        SHA1_CTX * context,
        const unsigned char *data,
        uint32_t len
)
{
    uint32_t i;

    uint32_t j;

    j = context->count[0];
    if ((context->count[0] += len << 3) < j)
        context->count[1]++;
    context->count[1] += (len >> 29);

    j = (j >> 3) & 63;
    if ((j + len) > 63)
    {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64)
        {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else
        i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

void SHA1Final(
        unsigned char digest[20],
        SHA1_CTX * context
)
{
    unsigned i;

    unsigned char finalcount[8];

    unsigned char c;

#if 0    /* untested "improvement" by DHR */
    /* Convert context->count to a sequence of bytes
     * in finalcount.  Second element first, but
     * big-endian order within element.
     * But we do it all backwards.
     */
    unsigned char *fcp = &finalcount[8];

    for (i = 0; i < 2; i++)
    {
        uint32_t t = context->count[i];

        int j;

        for (j = 0; j < 4; t >>= 8, j++)
            *--fcp = (unsigned char) t}
#else
    for (i = 0; i < 8; i++)
    {
        finalcount[i] = (unsigned char) ((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);      /* Endian independent */
    }
#endif
    c = 0200;
    SHA1Update(context, &c, 1);
    while ((context->count[0] & 504) != 448)
    {
        c = 0000;
        SHA1Update(context, &c, 1);
    }
    SHA1Update(context, finalcount, 8); /* Should cause a SHA1Transform() */
    for (i = 0; i < 20; i++)
    {
        digest[i] = (unsigned char)
                ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
//    printf("context->count[0]: %d\n", context->count[0]);
//    printf("context->count[1]: %d\n", context->count[1]); // Check if these values are meaningful (they are!)
    /* Wipe variables */
    memset(context, '\0', sizeof(*context));
    memset(&finalcount, '\0', sizeof(finalcount));
}

void SHA1(
        char *hash_out,
        const char *str,
        int len)
{
    SHA1_CTX ctx;
    unsigned int ii;

    SHA1Init(&ctx);
    for (ii=0; ii<len; ii+=1)
        SHA1Update(&ctx, (const unsigned char*)str + ii, 1);
    SHA1Final((unsigned char *)hash_out, &ctx);
}


/* SHA1Init - Initialize new context */

void SHA1Init(
        SHA1_CTX * context
)
{
    /* SHA1 initialization constants */ // My new constants
    // One listed on grader page
    context->state[0] = 0xe384efad;
    context->state[1] = 0xf26767a6;
    context->state[2] = 0x13162142;
    context->state[3] = 0xb5ef0efb;
    context->state[4] = 0xb9d7659a;
    context->count[1] = 0;
    context->count[0] = 1024;

    // Original SHA1 function
//    context->state[0] = 0x67452301;
//    context->state[1] = 0xEFCDAB89;
//    context->state[2] = 0x98BADCFE;
//    context->state[3] = 0x10325476;
//    context->state[4] = 0xC3D2E1F0;
//    context->count[0] = context->count[1] = 0;

    // Test
//    context->state[0] = 0x5984fe4a;
//    context->state[1] = 0x2dba982b;
//    context->state[2] = 0x6a327c3d;
//    context->state[3] = 0x05a93f2c;
//    context->state[4] = 0x5dc95027;
//    context->count[1] = 0;
//    context->count[0] = 1024;
}

int main() {
    uint8_t results[20];
    int n;

    char buf[] = { // 16 bytes of a secret key before this
            // Secret key (test)
//            0x41, 0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x42, 0x43, 0x43,
//            0x43, 0x43, 0x44, 0x44, 0x44, 0x44,
//
//            // Original message
//            0x4e, 0x6f, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x68, 0x61, 0x73, 0x20,
//            0x63, 0x6f, 0x6d, 0x70, 0x6c,0x65, 0x74, 0x65, 0x64, 0x20,
//            0x6c, 0x61, 0x62, 0x20, 0x32, 0x20, 0x73, 0x6f, 0x20, 0x67,
//            0x69,0x76, 0x65, 0x20, 0x74, 0x68, 0x65, 0x6d, 0x20,
//            0x61, 0x6c, 0x6c, 0x20, 0x61, 0x20, 0x30, // end of orig (47 bytes)
//
//            // Padding
//            0x80, 0x00, 0x00,
//            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
//            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
//            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
//            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
//            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
//            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00,
//            0x00, 0x01, 0xf8,// End of padding (65 bytes) // 47 + 65 + 16 (secret key) = 128 bytes for the first 2 blocks

            // My addition
            0x20,0x50, 0x73, 0x20,0x65, 0x78, 0x63, 0x65, 0x70, 0x74, 0x20,
            0x67, 0x69, 0x76, 0x65,0x20, 0x54,0x68, 0x6f, 0x6d, 0x61,
            0x73, 0x20, 0x61,0x6e, 0x20, 0x41 // message is 27 bytes
            //139 bytes total, but we calculate whats here plus length of secret key, so 139 + 16 = 155
    };

    // Original message (copy/paste and byte count)
    // 4e6f206f6e652068617320636f6d706c65746564206c6162203220736f2067697665207468656d20616c6c20612030
    // 4e 6f 20 6f 6e 65 20 68 61 73 20 63 6f 6d 70 6c 65 74 65 64 20 6c 61 62 20 32 20 73 6f 20 67 69 76 65 20 74 68 65 6d 20 61 6c 6c 20 61 20 30
    //  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47

    // Original padding
    //80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001f8
    // 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 f8
    //  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65

    // Appended message
    // 2050732065786365707420676976652054686f6d617320616e2041
    // 20 50 73 20 65 78 63 65 70 74 20 67 69 76 65 20 54 68 6f 6d 61 73 20 61 6e 20 41
    //  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27

    char * test = "AAAABBBBCCCCDDDDNo one has completed lab 2 so give them all a 0";

    // Test MAC: 5984fe4a2dba982b6a327c3d05a93f2c5dc95027 <-- Dummy MAC with dummy secret key. Replace state of SHA1 with this
    // Their output: d262ed802444dcaa6a209f5406dbf45d3158244c <-- This is the MAC they will calculate from the message you give them and after adding their secret key
    // Switch SHA1 state and run new message through algorithm to get the same output

    SHA1(results, buf, 27);         // 155 when I put my message through with modified state
    for (n = 0; n < 20; n++) printf("%02x", results[n]);

    return 0;
}
