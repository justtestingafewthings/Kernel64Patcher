/*
* Copyright 2020, @Ralph0045
* gcc Kernel64Patcher.c -o Kernel64Patcher
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "patches.h"
#include "watchos32.c"
#include "dynamic.c"

/* Resolve the containing directory even when the target does not exist yet. */
static char *canonical_target(const char *path) {
    char *copy=strdup(path);
    if(!copy) return NULL;
    char *slash=strrchr(copy,'/');
    const char *base=slash?slash+1:copy;
    char *directory;
    if(slash) { *slash=0;directory=realpath(*copy?copy:"/",NULL); }
    else directory=realpath(".",NULL);
    if(!directory) { free(copy);return NULL; }
    char *answer=malloc(strlen(directory)+strlen(base)+2);
    if(answer) sprintf(answer,"%s/%s",directory,base);
    free(directory);free(copy);return answer;
}
static int same_target(const char *a,const char *b) {
    struct stat sa,sb;
    if(!stat(a,&sa) && !stat(b,&sb) && sa.st_dev==sb.st_dev && sa.st_ino==sb.st_ino) return 1;
    char *ca=canonical_target(a),*cb=canonical_target(b);
    int same=ca && cb && !strcmp(ca,cb);
    free(ca);free(cb);return same;
}

static void usage(const char *program) {
    fprintf(stderr, "Usage: %s <kernel_in> <kernel_out> <args>\n", program);
    fprintf(stderr, "\t-a\t\tPatch AMFI\n");
    fprintf(stderr, "\t-f\t\tPatch AppleFirmwareUpdate img4 signature check\n");
    fprintf(stderr, "\t-s\t\tPatch SPU firmware-validation failure (iOS 15+)\n");
    fprintf(stderr, "\t-r\t\tPatch rootvp authentication panic (iOS 15+)\n");
    fprintf(stderr, "\t-o\t\tPatch personalized root-hash authentication (iOS 15+)\n");
    fprintf(stderr, "\t-p\t\tPatch AMFI local-signing-key panic (iOS 15+)\n");
    fprintf(stderr, "\t-u\t\tPatch unencrypted data-volume panic guard\n");
    fprintf(stderr, "  --dry-run  Validate and report without writing output\n");
    fprintf(stderr, "  --report <path>  Write a JSON patch report\n");
    fprintf(stderr, "  --no-symbols  Discover patches without symbol-table assistance\n");
    fprintf(stderr, "  --list-patches  List independent patch options\n");
    kp_list(stderr);
}

int main(int argc, char **argv) {
    unsigned char *kernel_buf = NULL;
    FILE *fp = NULL;
    size_t kernel_len;
    long length;
    int dry_run = 0, result = 1, report_allowed = 0, legacy_amfi = 0;
    const char *report = NULL;
    uint64_t selection = 0, explicit_selection = 0;
    struct stat in_stat, out_stat;
    if (argc == 2 && !strcmp(argv[1], "--help")) { usage(argv[0]); return 0; }
    if (argc == 2 && !strcmp(argv[1], "--list-patches")) { kp_list(stdout); return 0; }
    if (argc < 4) { usage(argv[0]); return 1; }
    for (int i = 3; i < argc; ++i) {
        if (!strcmp(argv[i], "--dry-run")) dry_run = 1;
        else if (!strcmp(argv[i], "--report")) {
            if(report || i+1==argc) { fprintf(stderr,"Expected one report path.\n");return 1; }
            report=argv[++i];
        }
        else if (!strcmp(argv[i], "--no-symbols")) kp_ignore_symbols=1;
        else if (!strcmp(argv[i], "-a")) { selection |= KP_AMFI_BUNDLE;legacy_amfi=1; }
        else if (!strcmp(argv[i], "-f")) selection |= KP_BIT(KP_FIRMWARE);
        else if (!strcmp(argv[i], "-s")) selection |= KP_BIT(KP_SPU);
        else if (!strcmp(argv[i], "-r")) selection |= KP_BIT(KP_ROOTVP);
        else if (!strcmp(argv[i], "-o")) selection |= KP_BIT(KP_ROOT_HASH);
        else if (!strcmp(argv[i], "-p")) selection |= KP_BIT(KP_LOCAL_SIGNING);
        else if (!strcmp(argv[i], "-u")) selection |= KP_BIT(KP_UNENCRYPTED);
        else {
            unsigned id;
            for(id=0;id<KP_COUNT;id++)
                if(!strncmp(argv[i],"--",2) && !strcmp(argv[i]+2,kp_catalog[id].id)) break;
            if(id==KP_COUNT) { fprintf(stderr, "Unknown flag: %s\n", argv[i]); return 1; }
            selection|=KP_BIT(id);
            explicit_selection|=KP_BIT(id);
        }
    }
    if (!selection) { usage(argv[0]); return 1; }
    kp.selection=selection;kp.dry_run=dry_run;
    printf("%s: Starting...\n", __func__);
    fp = fopen(argv[1], "rb");
    if (!fp) { perror(argv[1]); return 1; }
    if (fstat(fileno(fp), &in_stat) ||
        fseek(fp, 0, SEEK_END) || (length = ftell(fp)) < 32 ||
        fseek(fp, 0, SEEK_SET)) {
        fprintf(stderr, "Cannot read a complete Mach-O header from input.\n");
        goto cleanup;
    }
    kernel_len = (size_t)length;
    if (!stat(argv[2], &out_stat) && in_stat.st_dev == out_stat.st_dev &&
        in_stat.st_ino == out_stat.st_ino) {
        fprintf(stderr, "Input and output must be different files.\n");
        goto cleanup;
    }
    if(report) {
        if(same_target(report,argv[1]) || same_target(report,argv[2])) {
            fprintf(stderr,"Report path must differ from input and output.\n");goto cleanup;
        }
        report_allowed=1;
    }
    kernel_buf = malloc(kernel_len);
    if (!kernel_buf) { fprintf(stderr, "Out of memory.\n"); goto cleanup; }
    if (fread(kernel_buf, 1, kernel_len, fp) != kernel_len) {
        fprintf(stderr, "Short read of input kernel.\n"); goto cleanup;
    }
    fclose(fp); fp = NULL;
    unsigned char *image = kernel_buf;
    size_t image_len = kernel_len;
    if (read_be32(kernel_buf) == 0xcafebabe) {
        /* Preserve the FAT wrapper and patch only its single slice. */
        uint32_t count = read_be32(kernel_buf+4);
        uint32_t offset = read_be32(kernel_buf+16), size = read_be32(kernel_buf+20);
        uint32_t alignment = read_be32(kernel_buf+24);
        if (count != 1 || offset < 28 || offset > kernel_len || size < 32 ||
            size > kernel_len - offset || alignment > 31 ||
            (offset & ((UINT32_C(1) << alignment) - 1))) {
            fprintf(stderr, "Invalid or unsupported FAT wrapper; expected one bounded slice.\n");
            goto cleanup;
        }
        image = kernel_buf + offset;
        image_len = size;
        if (read_le32(image+4) != read_be32(kernel_buf+8) ||
            read_le32(image+8) != read_be32(kernel_buf+12)) {
            fprintf(stderr, "FAT slice architecture does not match its header.\n");
            goto cleanup;
        }
        printf("Single-slice FAT input: file 0x%x, size 0x%x; wrapper preserved.\n", offset, size);
    }
    uint32_t magic = read_le32(image), cpu = read_le32(image+4);
    kp.image=image;kp.length=image_len;kp.image_offset=(size_t)(image-kernel_buf);
    if (magic == 0xfeedface && cpu == 12) {
        if(legacy_amfi) kp.selection=(kp.selection&~KP_AMFI_BUNDLE)|explicit_selection|
            KP_BIT(KP_AMFI_TRUST)|KP_BIT(KP_CS_ENFORCEMENT)|KP_BIT(KP_LIBRARY_VALIDATION);
        if (patch_arm32_kernel(image, image_len, kp.selection)) goto cleanup;
    } else if (magic == 0xfeedfacf && cpu == 0x0100000c) {
        uint32_t ncmds = read_le32(image+16), cmds_size = read_le32(image+20);
        size_t pos = 32, end;
        if (cmds_size > image_len - 32 || !ncmds || ncmds > cmds_size / 8) {
            fprintf(stderr, "Invalid ARM64 load-command table.\n"); goto cleanup;
        }
        end = pos + cmds_size;
        for (uint32_t i = 0; i < ncmds; ++i) {
            if (end - pos < 8) { fprintf(stderr, "Truncated load command.\n"); goto cleanup; }
            uint32_t cmdsize = read_le32(image+pos+4);
            if (cmdsize < 8 || cmdsize > end - pos) {
                fprintf(stderr, "Invalid load-command size.\n"); goto cleanup;
            }
            pos += cmdsize;
        }
        if (pos != end) { fprintf(stderr, "Invalid load-command extent.\n"); goto cleanup; }
        if (patch_dynamic_kernel(image, image_len, kp.selection)) goto cleanup;
    } else {
        fprintf(stderr, "Expected a decompressed ARM or ARM64 Mach-O kernel.\n");
        fprintf(stderr, "Unpack IMG4/IM4P containers first.\n");
        goto cleanup;
    }
    kp_print();
    if (dry_run) {
        puts("Dry run complete. No output written.");
        result = 0;
        goto cleanup;
    }
    for(size_t i=0;i<kp.count;i++) {
        const struct kp_edit *e=&kp.edits[i];
        memcpy(image+e->off,e->after,e->size);
    }
    printf("%s: Writing out patched file to %s...\n", __func__, argv[2]);
    struct atomic_file output;
    if (atomic_file_open(&output, argv[2])) { perror(argv[2]); goto cleanup; }
    int failed = fwrite(kernel_buf, 1, kernel_len, output.stream) != kernel_len;
    if (atomic_file_finish(&output, failed)) { perror(argv[2]); goto cleanup; }
    kp.output_written=1;
    printf("%s: Quitting...\n", __func__);
    result = 0;
cleanup:
    if (fp) fclose(fp);
    if(result) { kp_fail_pending();kp_print(); }
    if(report_allowed && kp_report(report,result==0)) {
        fprintf(stderr,"Cannot write JSON patch report.\n");result=1;
    }
    free(kernel_buf);
    return result;
}
