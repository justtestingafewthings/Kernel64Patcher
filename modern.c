/* Match ARM64 kernels by UUID and SHA-256 after normalizing known patch sites. */
struct modern_patch {
    const char *name;
    int flag;
    size_t offset, size;
    unsigned char original[8], replacement[8];
};

struct modern_profile {
    const char *name;
    size_t length;
    unsigned char uuid[16], stock_hash[32];
    int supported_flags, not_applicable;
    size_t count;
    struct modern_patch patches[8];
};

#include "modern-profiles.h"

/* main has already validated all load-command extents. Older kernels return
 * 1 for legacy finders; 0 means handled, and -1 means refusal. */
static int patch_modern_kernel(unsigned char *buf, size_t len,
                               int flags, int dry_run) {
    const struct modern_profile *profile = NULL;
    const unsigned char *uuid = NULL;
    size_t pos = 32;
    int modern_platform = 0;
    for (uint32_t i = 0; i < read_le32(buf+16); ++i) {
        uint32_t command = read_le32(buf+pos), size = read_le32(buf+pos+4);
        if (command == 0x1b && size == 24) {
            if (uuid) {
                fprintf(stderr, "Duplicate kernel UUID command.\n");
                return -1;
            }
            uuid = buf+pos+8;
        }
        if (command == 0x32 && size >= 24) {
            uint32_t platform = read_le32(buf+pos+8);
            if ((platform == 2 || platform == 3) &&
                (read_le32(buf+pos+12) >> 16) >= 16) modern_platform = 1;
        }
        pos += size;
    }
    int known_uuid = 0;
    unsigned char *normalized = NULL;
    for (size_t n = 0; uuid && n < sizeof(modern_profiles)/sizeof(*modern_profiles); ++n) {
        const struct modern_profile *candidate = &modern_profiles[n];
        unsigned char digest[32];
        if (memcmp(uuid, candidate->uuid, 16)) continue;
        known_uuid = 1;
        if (len != candidate->length) continue;
        if (!normalized) normalized = malloc(len);
        if (!normalized) { fprintf(stderr, "Out of memory.\n"); return -1; }
        memcpy(normalized, buf, len);
        int valid = 1;
        for (size_t i = 0; i < candidate->count; ++i) {
            const struct modern_patch *p = &candidate->patches[i];
            if (!p->size || p->size > sizeof(p->original) || p->offset > len ||
                p->size > len - p->offset ||
                (memcmp(buf+p->offset, p->original, p->size) &&
                 memcmp(buf+p->offset, p->replacement, p->size))) {
                valid = 0;
                break;
            }
            memcpy(normalized+p->offset, p->original, p->size);
        }
        if (!valid) continue;
        watch_sha256(normalized, len, digest);
        if (!memcmp(digest, candidate->stock_hash, sizeof(digest))) {
            profile = candidate;
            break;
        }
    }
    free(normalized);
    if (!profile && known_uuid) {
        fprintf(stderr, "Kernel length, patch bytes or SHA-256 do not match a verified profile.\n");
        return -1;
    }
    if (!profile) {
        const unsigned char *xnu = memmem(buf, len, "root:xnu-", 9);
        if (xnu) {
            size_t p = (size_t)(xnu - buf) + 9;
            unsigned major = 0;
            while (p < len && buf[p] >= '0' && buf[p] <= '9') {
                if (major < 8792) major = major * 10 + buf[p] - '0';
                ++p;
            }
            if (major >= 8792 && p < len && buf[p] == '.') modern_platform = 1;
        }
        if (modern_platform) {
            fprintf(stderr, "Unsupported ARM64 kernel build. No output written.\n");
            return -1;
        }
        return 1;
    }
    if (flags & ~(profile->supported_flags | profile->not_applicable)) {
        fprintf(stderr, "Requested flags have not been verified for %s. "
                "Supported flags:", profile->name);
        const char letters[] = "afsrop";
        for (size_t i = 0; i < sizeof(letters)-1; ++i)
            if (profile->supported_flags & (1 << i))
                fprintf(stderr, " -%c", letters[i]);
        fprintf(stderr, ". No output written.\n");
        return -1;
    }
    printf("Verified %s kernel SHA-256.\n", profile->name);
    report_not_applicable(flags & profile->not_applicable);
    for (size_t i = 0; i < profile->count; ++i) {
        const struct modern_patch *p = &profile->patches[i];
        if (!(flags & p->flag)) continue;
        int done = !memcmp(buf+p->offset, p->replacement, p->size);
        printf("%s: file 0x%zx: %s\n", p->name, p->offset,
               done ? "already patched" : dry_run ? "would patch" : "patching");
        if (!dry_run) memcpy(buf+p->offset, p->replacement, p->size);
    }
    return 0;
}
