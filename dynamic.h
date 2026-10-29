#ifndef K64_DYNAMIC_H
#define K64_DYNAMIC_H
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#define KD_NONE SIZE_MAX
struct kd_region { size_t off, size; uint64_t address; int executable; char name[17]; };
struct kd_ctx {
    unsigned char *buf;
    size_t len;
    unsigned xnu, platform, minos;
    uint32_t symoff, nsyms, stroff, strsize;
    struct kd_region regions[1024];
    size_t region_count;
    size_t *functions, function_count;
};
static uint32_t kd_word(const struct kd_ctx *, size_t);
static uint64_t kd_va(const struct kd_ctx *, size_t);
static size_t kd_offset(const struct kd_ctx *, uint64_t);
static int kd_executable(const struct kd_ctx *, size_t);
static int kd_exec_bounds(const struct kd_ctx *, size_t, size_t *, size_t *);
static int kd_address(const struct kd_ctx *, size_t, unsigned *, size_t *);
static size_t kd_branch(const struct kd_ctx *, size_t);
static size_t kd_function(const struct kd_ctx *, size_t);
static size_t kd_string(const struct kd_ctx *, const char *);
static size_t kd_xref(const struct kd_ctx *, size_t, size_t, size_t);
static int kd_add(struct kd_ctx *, size_t, const void *, size_t, const char *);
static int kd_add_word(struct kd_ctx *, size_t, uint32_t, const char *);
static int kd_amfi_patch(struct kd_ctx *, enum kp_id);
static int kd_aux(struct kd_ctx *, int);
#endif
