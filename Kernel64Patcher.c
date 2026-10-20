/*
* Copyright 2020, @Ralph0045
* gcc Kernel64Patcher.c -o Kernel64Patcher
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "patchfinder64.c"
#include "watchos32.c"

#define GET_OFFSET(kernel_len, x) (x - (uintptr_t) kernel_buf)

static uint32_t arm64_branch_instruction(uintptr_t from, uintptr_t to) {
  return from > to ? 0x18000000 - (from - to) / 4 : 0x14000000 + (to - from) / 4;
}

// iOS 15 "%s: firmware validation failed %d\" @%s:%d SPU Firmware Validation Patch
int get_SPUFirmwareValidation_patch(void *kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);

    char rootvpString[43] = "\"%s: firmware validation failed %d\" @%s:%d";
    void* ent_loc = memmem(kernel_buf,kernel_len,rootvpString,42);
    if(!ent_loc) {
        printf("%s: Could not find \"%%s: firmware validation failed %%d\" @%%s:%%d string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"%%s: firmware validation failed %%d\" @%%s:%%d\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"%%s: firmware validation failed %%d\" @%%s:%%d xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"%%s: firmware validation failed %%d\" @%%s:%%d\" ref at %p\n",__FUNCTION__,(void*)xref_stuff);
    addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
    if(!beg_func) {
        printf("%s: Could not find firmware validation function start\n",__FUNCTION__);
        return -1;
    }
    xref_stuff = xref64code(kernel_buf,0,(addr_t)GET_OFFSET(kernel_len, beg_func), beg_func);
    if(!xref_stuff) {
        printf("%s: Could not find previous xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found function xref at %p\n",__FUNCTION__,(void*)xref_stuff);
    addr_t next_bl = step64_back(kernel_buf, xref_stuff, 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find previous bl\n",__FUNCTION__);
        return -1;
    }
    next_bl = step64_back(kernel_buf, (next_bl - 0x4), 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find previous bl\n",__FUNCTION__);
        return -1;
    }
    next_bl = step64_back(kernel_buf, (next_bl - 0x4), 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find previous bl\n",__FUNCTION__);
        return -1;
    }
    beg_func = bof64(kernel_buf,0,next_bl);
    if(!beg_func) {
        printf("%s: Could not find start of firmware validation function\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching SPU Firmware Validation at %p\n\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *) (kernel_buf + beg_func) = 0xD65F03C0;
    return 0;
}

// iOS 15 rootvp not authenticated after mounting Patch
int get_RootVPNotAuthenticatedAfterMounting_patch(void *kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    char rootVPString[40] = "rootvp not authenticated after mounting";
    char md0String[] = "md0";
    void* ent_loc = memmem(kernel_buf,kernel_len,md0String,3);
    if(!ent_loc) {
        printf("%s: Could not find \"md0\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"md0\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"md0\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"md0\" ref at %p\n",__FUNCTION__,(void*)xref_stuff);
    addr_t next_bl = step64(kernel_buf, xref_stuff + 0x8, 100, INSN_CALL);
    if(!next_bl) {
        // Newer devices will fail here, so using another string is required
        printf("%s: Failed to use \"md0\", swapping to \"rootvp not authenticated after mounting\"\n",__FUNCTION__);
        ent_loc = memmem(kernel_buf,kernel_len,rootVPString,39);
        if(!ent_loc) {
            printf("%s: Could not find \"rootvp not authenticated after mounting\" string\n",__FUNCTION__);
            return -1;
        }
        printf("%s: Found \"rootvp not authenticated after mounting\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
        xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
        if(!xref_stuff) {
            printf("%s: Could not find \"rootvp not authenticated after mounting\" xref\n",__FUNCTION__);
            return -1;
        }
        printf("%s: Found \"rootvp not authenticated after mounting\" str xref at %p\n",__FUNCTION__,(void*)xref_stuff);
        addr_t beg_func = bof64(kernel_buf,0,xref_stuff);
        if(!beg_func) {
            printf("%s: Could not find function start\n",__FUNCTION__);
            return -1;
        }
        beg_func = beg_func + 0xA98;
        printf("%s: Found function start at %p\n",__FUNCTION__,(void*)beg_func);
        next_bl = step64(kernel_buf, beg_func, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
    } else {
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
        next_bl = step64(kernel_buf, next_bl + 0x8, 100, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
    }
    printf("%s: Patching ROOTVP at %p\n\n", __FUNCTION__,(void*)(next_bl + 0x4));
    *(uint32_t *) (kernel_buf + next_bl + 0x4) = 0xD503201F;

    return 0;
}

// iOS 15 AMFI Kernel Patch
int get_AMFIInitializeLocalSigningPublicKey_patch(void* kernel_buf,size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);

    char AMFIString[] = "\"AMFI: %s: unable to obtain local signing public key";
    void* ent_loc = memmem(kernel_buf,kernel_len,AMFIString,51);
    if(!ent_loc) {
        printf("%s: Could not find \"AMFI: %%s: unable to obtain local signing public key\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"AMFI: %%s: unable to obtain local signing public key\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!xref_stuff) {
        printf("%s: Could not find \"AMFI: %%s: unable to obtain local signing public key\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"AMFI: %%s: unable to obtain local signing public key ref at %p\n",__FUNCTION__,(void*)xref_stuff);

    printf("%s: Patching \"Local Signing Public Key\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff + 0x4));
    *(uint32_t *) (kernel_buf + xref_stuff + 0x4) = 0xD503201F;
    
    return 0;
}

//iOS 14 AppleFirmwareUpdate img4 signature check
int get_AppleFirmwareUpdate_img4_signature_check(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n",__FUNCTION__);

    char img4_sig_check_string[56] = "%s::%s() Performing img4 validation outside of workloop";
    void* ent_loc = memmem(kernel_buf,kernel_len,img4_sig_check_string,55);
    if(!ent_loc) {
        printf("%s: Could not find \"%%s::%%s() Performing img4 validation outside of workloop\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"%%s::%%s() Performing img4 validation outside of workloop\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));

    if(!ent_ref) {
        printf("%s: Could not find \"%%s::%%s() Performing img4 validation outside of workloop\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"%%s::%%s() Performing img4 validation outside of workloop\" xref at %p\n",__FUNCTION__,(void*)ent_ref);

    printf("%s: Patching \"%%s::%%s() Performing img4 validation outside of workloop\" at %p\n\n", __FUNCTION__,(void*)(ent_ref + 0xc));
    *(uint32_t *) (kernel_buf + ent_ref + 0xc) = 0xD2800000;

    return 0;
}

static addr_t
cbz_ref64_back(const uint8_t *buf, addr_t start, size_t length) {

    //find cbz/cbnz
    uint32_t cbz_mask = 0x7E000000;
    uint32_t instr = 0;
    uint32_t imm = 0;
    addr_t cbz = start;
    while (cbz) {
        instr = *(uint32_t *) (buf + cbz);
        if ((instr & cbz_mask) == 0x34000000) {
            imm = ((instr & 0x00FFFFFF) >> 5) << 2;
            if (cbz + imm == start)
                return cbz;
        }
        cbz -= 4;
    }
    return 0;
}

//iOS 15 "could not authenticate personalized root hash!" patch
int get_could_not_authenticate_personalized_root_hash_patch(void* kernel_buf,size_t kernel_len) {

    printf("%s: Entering ...\n", __FUNCTION__);

    //get target offset for new branch
    char roothash_authenticated_string[sizeof("successfully validated on-disk root hash")] = "successfully validated on-disk root hash";

    unsigned char *roothash_authenticated_loc = memmem(kernel_buf, kernel_len, roothash_authenticated_string, sizeof("successfully validated on-disk root hash") - 1);
    if(!roothash_authenticated_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, roothash_authenticated_string);
        return -1;
    }

    for (; *roothash_authenticated_loc != 0; roothash_authenticated_loc--);
    roothash_authenticated_loc++;
    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, roothash_authenticated_string, GET_OFFSET(kernel_len, roothash_authenticated_loc));

    addr_t roothash_authenticated_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, roothash_authenticated_loc));
    if(!roothash_authenticated_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, roothash_authenticated_string);
        return -1;
    }
    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, roothash_authenticated_string, (void*) roothash_authenticated_ref);

    //get previous cbz
    addr_t branch_target = step64_back(kernel_buf, roothash_authenticated_ref, 20 * 4, 0x34000000, 0x7E000000);
    if(!branch_target) {
        printf("%s: Could not find previous cbz\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found previous cbz at %p\n",__FUNCTION__, (void*) branch_target);
    branch_target++;

    //get patching offset for new branch
    char roothash_failed_string[sizeof("could not authenticate personalized root hash!")] = "could not authenticate personalized root hash!";

    unsigned char *roothash_failed_loc = memmem(kernel_buf, kernel_len, roothash_failed_string, sizeof("could not authenticate personalized root hash!") - 1);
    if(!roothash_failed_loc) {
        printf("%s: Could not find \"%s\" string\n", __FUNCTION__, roothash_failed_string);
        return -1;
    }

    for (; *roothash_failed_loc != 0; roothash_failed_loc--);
    roothash_failed_loc++;
    printf("%s: Found \"%s\" str loc at %p\n", __FUNCTION__, roothash_failed_string, GET_OFFSET(kernel_len, roothash_failed_loc));

    addr_t roothash_failed_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, roothash_failed_loc));
    if(!roothash_failed_ref) {
        printf("%s: Could not find \"%s\" xref\n",__FUNCTION__, roothash_failed_string);
        return -1;
    }
    printf("%s: Found \"%s\" xref at %p\n",__FUNCTION__, roothash_failed_string, (void*) roothash_failed_ref);

    addr_t patch_loc = 0;

    for (int i = 0; i < 16; i++, roothash_failed_ref -= 4) {
        if (cbz_ref64_back(kernel_buf, roothash_failed_ref, roothash_failed_ref)) {
            printf("%s: Found cbz target at %p\n", __FUNCTION__, (void*) roothash_failed_ref);
            patch_loc = roothash_failed_ref;
            break;
        }
    }

    if (!patch_loc) {
        printf("%s: Could not find cbz target\n",__FUNCTION__);
        return -1;
    }

    printf("%s: Patching root hash check at %p\n",__FUNCTION__, (void*) patch_loc);
    *((uint32_t *) (kernel_buf + patch_loc)) = arm64_branch_instruction((uintptr_t) patch_loc, (uintptr_t) branch_target);

    return 0;
}

int get_amfi_out_of_my_way_patch(void* kernel_buf,size_t kernel_len) {
    
    printf("%s: Entering ...\n",__FUNCTION__);
    
    const unsigned char *xnu = memmem(kernel_buf,kernel_len,"root:xnu-",9);
    if (!xnu) {
        fprintf(stderr, "Missing XNU version string.\n");
        return -1;
    }
    const unsigned char *version = xnu + 9;
    const unsigned char *end = (const unsigned char *)kernel_buf + kernel_len;
    int kernel_vers = 0;
    if (version == end || *version < '0' || *version > '9') {
        fprintf(stderr, "Invalid XNU version string.\n");
        return -1;
    }
    while (version < end && *version >= '0' && *version <= '9') {
        int digit = *version++ - '0';
        if (kernel_vers > (INT32_MAX - digit) / 10) {
            fprintf(stderr, "Invalid XNU version string.\n");
            return -1;
        }
        kernel_vers = kernel_vers * 10 + digit;
    }
    if (version == end) {
        fprintf(stderr, "Invalid XNU version string.\n");
        return -1;
    }
    printf("%s: Kernel-%d inputted\n",__FUNCTION__, kernel_vers);
    char amfiString[33] = "entitlements too small";
    int stringLen = 22;
    if (kernel_vers >= 7938) { // Using "entitlements too small" fails on iOS 15 Kernels
        strncpy(amfiString, "Internal Error: No cdhash found.", 33);
        stringLen = 32;
    }
    void* ent_loc = memmem(kernel_buf,kernel_len,amfiString,stringLen);
    if(!ent_loc) {
        printf("%s: Could not find %s string\n",__FUNCTION__, amfiString);
        return -1;
    }
    printf("%s: Found %s str loc at %p\n",__FUNCTION__,amfiString,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!ent_ref) {
        printf("%s: Could not find %s xref\n",__FUNCTION__,amfiString);
        return -1;
    }
    printf("%s: Found %s str ref at %p\n",__FUNCTION__,amfiString,(void*)ent_ref);
    addr_t next_bl = step64(kernel_buf, ent_ref, 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find next bl\n",__FUNCTION__);
        return -1;
    }
    next_bl = step64(kernel_buf, next_bl+0x4, 200, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find next bl\n",__FUNCTION__);
        return -1;
    }
    if(kernel_vers>3789) { 
        next_bl = step64(kernel_buf, next_bl+0x4, 200, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
    }
    addr_t function = follow_call64(kernel_buf, next_bl);
    if(!function) {
        printf("%s: Could not find function bl\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching AMFI at %p\n",__FUNCTION__,(void*)function);
    *(uint32_t *)(kernel_buf + function) = 0x320003E0;
    *(uint32_t *)(kernel_buf + function + 0x4) = 0xD65F03C0;
    return 0;
}

static void usage(const char *program) {
    fprintf(stderr, "Usage: %s <kernel_in> <kernel_out> <args>\n", program);
    fprintf(stderr, "\t-a\t\tPatch AMFI\n");
    fprintf(stderr, "\t-f\t\tPatch AppleFirmwareUpdate img4 signature check\n");
    fprintf(stderr, "\t-s\t\tPatch SPUFirmwareValidation (iOS 15 Only)\n");
    fprintf(stderr, "\t-r\t\tPatch RootVPNotAuthenticatedAfterMounting (iOS 15 Only)\n");
    fprintf(stderr, "\t-o\t\tPatch could_not_authenticate_personalized_root_hash (iOS 15 Only)\n");
    fprintf(stderr, "\t-p\t\tPatch AMFIInitializeLocalSigningPublicKey (iOS 15 Only)\n");
    fprintf(stderr, "  --dry-run  Validate and report without writing output\n");
}

int main(int argc, char **argv) {
    unsigned char *kernel_buf = NULL;
    FILE *fp = NULL;
    size_t kernel_len;
    long length;
    int flags = 0, dry_run = 0, result = 1;
    struct stat in_stat, out_stat;
    if (argc == 2 && !strcmp(argv[1], "--help")) { usage(argv[0]); return 0; }
    if (argc < 4) { usage(argv[0]); return 1; }
    for (int i = 3; i < argc; ++i) {
        if (!strcmp(argv[i], "--dry-run")) dry_run = 1;
        else if (!strcmp(argv[i], "-a")) flags |= 1;
        else if (!strcmp(argv[i], "-f")) flags |= 2;
        else if (!strcmp(argv[i], "-s")) flags |= 4;
        else if (!strcmp(argv[i], "-r")) flags |= 8;
        else if (!strcmp(argv[i], "-o")) flags |= 16;
        else if (!strcmp(argv[i], "-p")) flags |= 32;
        else { fprintf(stderr, "Unknown flag: %s\n", argv[i]); return 1; }
    }
    if (!flags) { usage(argv[0]); return 1; }
    printf("%s: Starting...\n", __FUNCTION__);
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
    kernel_buf = malloc(kernel_len);
    if (!kernel_buf) { fprintf(stderr, "Out of memory.\n"); goto cleanup; }
    if (fread(kernel_buf, 1, kernel_len, fp) != kernel_len) {
        fprintf(stderr, "Short read of input kernel.\n"); goto cleanup;
    }
    fclose(fp); fp = NULL;
    unsigned char *image = kernel_buf;
    size_t image_len = kernel_len;
    if (read_be32(kernel_buf) == 0xcafebabe) {
        /* watchOS 5/6 OTAs can contain one ARMv7k slice in a FAT wrapper.
         * Keep that wrapper intact; validate its extent before taking a view. */
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
    if (magic == 0xfeedface && cpu == 12) {
        if (flags != 1) {
            fprintf(stderr, "ARMv7k supports only -a. ARM64-only flags were refused.\n");
            goto cleanup;
        }
        printf("Kernel: Adding AMFI_get_out_of_my_way patch...\n");
        if (patch_watch_kernel(image, image_len, dry_run)) goto cleanup;
    } else if (magic == 0xfeedfacf && cpu == 0x0100000c) {
        /* The legacy ARM64 finders operate on the raw thin Mach-O image. */
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
        if (flags & 1) {
            printf("Kernel: Adding AMFI_get_out_of_my_way patch...\n");
            if (memmem(image, image_len, "RELEASE_ARM64_T8006", 18)) {
                if (patch_watch_kernel(image, image_len, dry_run)) goto cleanup;
            } else if (get_amfi_out_of_my_way_patch(image, image_len)) goto cleanup;
        }
        if (flags & 2) {
            printf("Kernel: Adding AppleFirmwareUpdate img4 signature check patch...\n");
            if (get_AppleFirmwareUpdate_img4_signature_check(image, image_len)) goto cleanup;
        }
        if (flags & 4) {
            printf("Kernel: Adding SPUFirmwareValidation patch...\n");
            if (get_SPUFirmwareValidation_patch(image, image_len)) goto cleanup;
        }
        if (flags & 32) {
            printf("Kernel: Adding AMFIInitializeLocalSigningPublicKey patch...\n");
            if (get_AMFIInitializeLocalSigningPublicKey_patch(image, image_len)) goto cleanup;
        }
        if (flags & 8) {
            printf("Kernel: Adding RootVPNotAuthenticatedAfterMounting patch...\n");
            if (get_RootVPNotAuthenticatedAfterMounting_patch(image, image_len)) goto cleanup;
        }
        if (flags & 16) {
            printf("Kernel: Adding could_not_authenticate_personalized_root_hash patch...\n");
            if (get_could_not_authenticate_personalized_root_hash_patch(image, image_len)) goto cleanup;
        }
    } else {
        fprintf(stderr, "Expected a decompressed ARM64 or supported ARMv7k Mach-O kernel.\n");
        fprintf(stderr, "Unpack IMG4/IM4P containers first.\n");
        goto cleanup;
    }
    if (dry_run) {
        puts("Dry run complete. No output written.");
        result = 0;
        goto cleanup;
    }
    /* Commit output only after every requested patch succeeds. */
    printf("%s: Writing out patched file to %s...\n", __FUNCTION__, argv[2]);
    char *temporary = malloc(strlen(argv[2]) + sizeof(".tmp.XXXXXX"));
    if (!temporary) goto cleanup;
    sprintf(temporary, "%s.tmp.XXXXXX", argv[2]);
    int fd = mkstemp(temporary);
    if (fd < 0) { perror(temporary); free(temporary); goto cleanup; }
    fp = fdopen(fd, "wb");
    if (!fp) {
        perror("fdopen"); close(fd); unlink(temporary); free(temporary); goto cleanup;
    }
    int failed = fwrite(kernel_buf, 1, kernel_len, fp) != kernel_len;
    if (fclose(fp)) failed = 1;
    fp = NULL;
    if (failed || rename(temporary, argv[2])) {
        fprintf(stderr, "Failed to write output kernel.\n");
        unlink(temporary); free(temporary); goto cleanup;
    }
    free(temporary);
    printf("%s: Quitting...\n", __FUNCTION__);
    result = 0;
cleanup:
    if (fp) fclose(fp);
    free(kernel_buf);
    return result;
}
