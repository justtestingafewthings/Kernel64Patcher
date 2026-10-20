#include <stdint.h>

static uint32_t read_le32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint32_t read_be32(const unsigned char *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
}

static uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

static void watch_sha256(const unsigned char *data, size_t len,
                         unsigned char digest[32]) {
    static const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t blocks = len / 64 + (len % 64 < 56 ? 1 : 2);
    uint64_t bits = (uint64_t)len * 8;
    for (size_t block = 0; block < blocks; ++block) {
        unsigned char bytes[64] = {0};
        uint32_t w[64], a=h[0], b=h[1], c=h[2], d=h[3],
                 e=h[4], f=h[5], g=h[6], z=h[7];
        size_t pos = block * 64;
        size_t count = pos < len ? len - pos : 0;
        if (count > 64) count = 64;
        if (count) memcpy(bytes, data + pos, count);
        if (pos <= len && len - pos < 64) bytes[len - pos] = 0x80;
        if (block == blocks - 1)
            for (unsigned j = 0; j < 8; ++j)
                bytes[63-j] = (unsigned char)(bits >> (8*j));
        for (unsigned j = 0; j < 16; ++j)
            w[j] = (uint32_t)bytes[4*j] << 24 | (uint32_t)bytes[4*j+1] << 16 |
                   (uint32_t)bytes[4*j+2] << 8 | bytes[4*j+3];
        for (unsigned j = 16; j < 64; ++j) {
            uint32_t s0 = rotr32(w[j-15],7) ^ rotr32(w[j-15],18) ^ (w[j-15] >> 3);
            uint32_t s1 = rotr32(w[j-2],17) ^ rotr32(w[j-2],19) ^ (w[j-2] >> 10);
            w[j] = w[j-16] + s0 + w[j-7] + s1;
        }
        for (unsigned j = 0; j < 64; ++j) {
            uint32_t s1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
            uint32_t t1 = z + s1 + ((e & f) ^ (~e & g)) + k[j] + w[j];
            uint32_t s0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
            uint32_t t2 = s0 + ((a & b) ^ (a & c) ^ (b & c));
            z=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=z;
    }
    for (unsigned j = 0; j < 32; ++j)
        digest[j] = (unsigned char)(h[j/4] >> (24 - 8*(j%4)));
}

struct watch_patch {
    const char *name;
    size_t offset;
    uint64_t address;
    size_t size;
    unsigned char original[8], replacement[8];
};

struct watch_profile {
    const char *name;
    size_t length;
    uint32_t magic, cpu, subtype;
    unsigned char stock_hash[32];
    size_t count;
    struct watch_patch patches[6];
};

#include "watchos32-profiles.h"

static int patch_watch_kernel(unsigned char *buf, size_t len, int dry_run) {
    const struct watch_profile *profile = NULL;
    if (len < 28) {
        fprintf(stderr, "Truncated Watch kernel.\n");
        return -1;
    }
    for (size_t n = 0; n < sizeof(watch_profiles)/sizeof(*watch_profiles); ++n) {
        const struct watch_profile *candidate = &watch_profiles[n];
        unsigned char digest[32];
        int valid = 1;
        if (len != candidate->length || read_le32(buf) != candidate->magic ||
            read_le32(buf+4) != candidate->cpu || read_le32(buf+8) != candidate->subtype)
            continue;
        unsigned char *normalized = malloc(len);
        if (!normalized) return -1;
        memcpy(normalized, buf, len);
        for (size_t i = 0; i < candidate->count; ++i) {
            const struct watch_patch *p = &candidate->patches[i];
            if (!p->size || p->size > sizeof(p->original) || p->offset > len ||
                len - p->offset < p->size ||
                (memcmp(buf+p->offset, p->original, p->size) &&
                 memcmp(buf+p->offset, p->replacement, p->size))) {
                valid = 0;
                break;
            }
            memcpy(normalized+p->offset, p->original, p->size);
        }
        /* Normalize known patch sites before checking the stock hash. */
        if (valid) watch_sha256(normalized, len, digest);
        free(normalized);
        if (valid && !memcmp(digest, candidate->stock_hash, 32)) {
            profile = candidate;
            break;
        }
    }
    if (!profile) {
        fprintf(stderr, "Unrecognized Watch kernel or unexpected patch-site bytes.\n");
        fprintf(stderr, "No output written.\n");
        return -1;
    }
    printf("Verified %s kernel SHA-256.\n", profile->name);
    for (size_t i = 0; i < profile->count; ++i) {
        const struct watch_patch *p = &profile->patches[i];
        int done = !memcmp(buf+p->offset, p->replacement, p->size);
        printf("%s: VA 0x%llx, file 0x%zx: %s\n", p->name,
               (unsigned long long)p->address,
               p->offset, done ? "already patched" : dry_run ? "would patch" : "patching");
        if (!dry_run) memcpy(buf+p->offset, p->replacement, p->size);
    }
    return 0;
}
