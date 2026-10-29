/* Shared patch selection, transaction and machine-readable diagnostics. */
#ifndef KERNEL_PATCHES_H
#define KERNEL_PATCHES_H
#include <inttypes.h>
#include "atomic_file.h"

enum kp_id {
    KP_AMFI_TRUST, KP_AMFI_SHA1, KP_LAUNCH_CONSTRAINTS, KP_DEVELOPER_MODE,
    KP_FIRMWARE, KP_SPU, KP_ROOTVP, KP_ROOT_HASH, KP_LOCAL_SIGNING,
    KP_UNENCRYPTED, KP_CS_ENFORCEMENT, KP_LIBRARY_VALIDATION,
    KP_APFS_MOUNT_AUTH, KP_APFS_REMOUNT, KP_FAIRPLAY_VALIDATION,
    KP_VM_MAP_PROTECTION, KP_AMFI_VNODE_VALIDATION, KP_LEGACY_CS_VALIDATION,
    KP_NAND_PRESERVE, KP_COUNT
};
struct kp_descriptor { const char *id, *description; };
static const struct kp_descriptor kp_catalog[KP_COUNT] = {
    {"amfi-trust", "AMFI trust-cache lookup"},
    {"amfi-sha1", "AMFI SHA-1 policy"},
    {"launch-constraints", "AMFI launch constraints"},
    {"developer-mode", "AMFI Developer Mode preservation"},
    {"firmware-validation", "AppleFirmwareUpdate IMG4 validation"},
    {"spu-validation", "SPU firmware-validation failure guard"},
    {"rootvp-auth", "Root vnode authentication panic guard"},
    {"root-hash-auth", "Personalized root-hash authentication"},
    {"local-signing-key", "AMFI local-signing-key panic guard"},
    {"unencrypted-data", "Unencrypted data-volume panic guard"},
    {"cs-enforcement", "ARM32 code-signing enforcement policy"},
    {"library-validation", "ARM32 library-validation policy"},
    {"apfs-mount-auth", "APFS kernel-task mount authorization"},
    {"apfs-remount", "APFS root-volume read/write remount guard"},
    {"fairplay-validation", "legacy FairPlay executable validation"},
    {"vm-map-protection", "legacy vm_map maximum-protection guard"},
    {"amfi-vnode-validation", "legacy AMFI vnode-signature validation"},
    {"legacy-cs-validation", "legacy code-signature result path"},
    {"nand-preserve", "Reject automatic NAND migration and formatting during ramdisk boot"}
};
enum kp_status { KP_PENDING, KP_PLANNED, KP_ALREADY, KP_ABSENT, KP_UNSUPPORTED, KP_FAILED };
struct kp_result { enum kp_status status; const char *reason; size_t matches, changes; };
struct kp_edit {
    enum kp_id patch;
    size_t off, size;
    uint64_t address;
    unsigned char before[32], after[32];
    const char *name;
    int data;
};
static struct {
    unsigned char *image;
    size_t length, image_offset;
    enum kp_id active;
    uint64_t selection;
    struct kp_result results[KP_COUNT];
    struct kp_edit edits[4096];
    size_t count;
    int dry_run, output_written;
} kp;
static int kp_ignore_symbols;
#define KP_BIT(id) (UINT64_C(1) << (id))
#define KP_AMFI_BUNDLE (KP_BIT(KP_AMFI_TRUST) | KP_BIT(KP_AMFI_SHA1) | \
                        KP_BIT(KP_LAUNCH_CONSTRAINTS) | KP_BIT(KP_DEVELOPER_MODE))

static void kp_begin(enum kp_id id) { kp.active=id; }
static void kp_absent(const char *reason) {
    kp.results[kp.active].status=KP_ABSENT;
    kp.results[kp.active].reason=reason;
}
static int kp_unsupported(const char *reason) {
    kp.results[kp.active].status=KP_UNSUPPORTED;
    kp.results[kp.active].reason=reason;
    return -1;
}
static void kp_fail_pending(void) {
    for(unsigned i=0;i<KP_COUNT;i++) if((kp.selection&KP_BIT(i)) && kp.results[i].status==KP_PENDING) {
        kp.results[i].status=KP_FAILED;
        kp.results[i].reason="Kernel metadata validation failed before patch discovery";
    }
}
static int kp_add(size_t off,uint64_t address,const void *bytes,size_t size,
                  const char *name,int data) {
    if(!size || size>sizeof(kp.edits[0].before) || off>kp.length || size>kp.length-off)
        return -1;
    struct kp_result *r=&kp.results[kp.active];
    for(size_t i=0;i<kp.count;i++) {
        const struct kp_edit *e=&kp.edits[i];
        if(off<e->off+e->size && e->off<off+size) {
            if(off!=e->off || size!=e->size || memcmp(bytes,e->after,size)) {
                fprintf(stderr,"Conflicting patches: %s and %s.\n",e->name,name);
                return -1;
            }
            /* Shared identical edits still count toward each requested patch. */
            r->matches++;
            r->changes+=memcmp(kp.image+off,bytes,size)!=0;
            return 0;
        }
    }
    if(kp.count==sizeof(kp.edits)/sizeof(*kp.edits)) return -1;
    struct kp_edit *e=&kp.edits[kp.count++];
    e->patch=kp.active;e->off=off;e->size=size;e->address=address;e->name=name;e->data=data;
    memcpy(e->before,kp.image+off,size);memcpy(e->after,bytes,size);
    r->matches++;r->changes+=memcmp(e->before,e->after,size)!=0;
    return 0;
}
static int kp_finish(int result) {
    struct kp_result *r=&kp.results[kp.active];
    if(result) {
        if(r->status!=KP_UNSUPPORTED) r->status=KP_FAILED;
        if(!r->reason) r->reason="Patch discovery or validation failed";
        return -1;
    }
    if(r->matches) r->status=r->changes?KP_PLANNED:KP_ALREADY;
    else if(r->status!=KP_ABSENT && r->status!=KP_ALREADY) {
        r->status=KP_FAILED;r->reason="Finder produced no validated result";return -1;
    }
    return 0;
}
static const char *kp_status_name(enum kp_status s) {
    static const char *names[]={"pending","planned","already_patched","not_applicable","unsupported","failed"};
    return names[s];
}
static void kp_list(FILE *stream) {
    for(unsigned i=0;i<KP_COUNT;i++)
        fprintf(stream,"  --%-22s %s\n",kp_catalog[i].id,kp_catalog[i].description);
}
static void kp_print(void) {
    for(unsigned i=0;i<KP_COUNT;i++) if(kp.selection&KP_BIT(i)) {
        const struct kp_result *r=&kp.results[i];
        printf("%s: %s%s%s\n",kp_catalog[i].id,kp_status_name(r->status),
               r->reason?"; ":"",r->reason?r->reason:"");
    }
    for(size_t i=0;i<kp.count;i++) {
        const struct kp_edit *e=&kp.edits[i];
        printf("%s: VA 0x%" PRIx64 ", file 0x%zx: %s\n",e->name,e->address,
               kp.image_offset+e->off,!memcmp(e->before,e->after,e->size)?"already patched":
               kp.dry_run?"would patch":"planned");
    }
}
static void kp_json_string(FILE *f,const char *s) {
    fputc('"',f);
    for(const unsigned char *p=(const unsigned char *)(s?s:"");*p;p++) {
        if(*p=='"' || *p=='\\') { fputc('\\',f);fputc(*p,f); }
        else if(*p<32) fprintf(f,"\\u%04x",*p);
        else fputc(*p,f);
    }
    fputc('"',f);
}
static void kp_json_bytes(FILE *f,const unsigned char *b,size_t n) {
    fputc('"',f);for(size_t i=0;i<n;i++) fprintf(f,"%02x",b[i]);fputc('"',f);
}
static int kp_report(const char *path,int success) {
    if(!path) return 0;
    struct atomic_file output;
    if(atomic_file_open(&output,path)) { perror(path);return -1; }
    FILE *f=output.stream;
    fprintf(f,"{\"schema_version\":1,\"success\":%s,\"dry_run\":%s,\"output_written\":%s,\"image_offset\":%zu,\"patches\":[",
            success?"true":"false",kp.dry_run?"true":"false",kp.output_written?"true":"false",kp.image_offset);
    int comma=0;
    for(unsigned i=0;i<KP_COUNT;i++) if(kp.selection&KP_BIT(i)) {
        const struct kp_result *r=&kp.results[i];
        if(comma++) fputc(',',f);
        fputs("{\"id\":",f);kp_json_string(f,kp_catalog[i].id);
        fputs(",\"status\":",f);kp_json_string(f,kp_status_name(r->status));
        fputs(",\"reason\":",f);kp_json_string(f,r->reason);
        fprintf(f,",\"matches\":%zu,\"changes\":%zu}",r->matches,r->changes);
    }
    fputs("],\"edits\":[",f);
    for(size_t i=0;i<kp.count;i++) {
        const struct kp_edit *e=&kp.edits[i];
        if(i) fputc(',',f);
        fputs("{\"patch\":",f);kp_json_string(f,kp_catalog[e->patch].id);
        fprintf(f,",\"offset\":%zu,\"image_offset\":%zu,\"address\":\"0x%" PRIx64 "\",\"size\":%zu,\"data\":%s,\"name\":",
                kp.image_offset+e->off,e->off,e->address,e->size,e->data?"true":"false");
        kp_json_string(f,e->name);fputs(",\"original\":",f);kp_json_bytes(f,e->before,e->size);
        fputs(",\"replacement\":",f);kp_json_bytes(f,e->after,e->size);fputc('}',f);
    }
    fputs("]}\n",f);
    return atomic_file_finish(&output,0);
}
#endif
