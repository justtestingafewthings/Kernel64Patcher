struct ka_scope { size_t code, code_end, text, text_size; };

static uint64_t ka_u64(const unsigned char *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)p[i] << (i * 8);
    return value;
}

static size_t ka_pointer_offset(const struct kd_ctx *ctx, uint64_t pointer) {
    if ((pointer & UINT64_C(0xffff00000000)) == UINT64_C(0xfff000000000))
        pointer |= UINT64_C(0xffff000000000000);
    return kd_offset(ctx, pointer);
}

/* Flattened prelinked kernels leave kmod_info.address zero and retain parallel
 * __kmod_info/__kmod_start arrays identifying each embedded executable. */
static size_t ka_indexed_header(const struct kd_ctx *ctx, size_t name) {
    size_t infos = KD_NONE, starts = KD_NONE, info_size = 0, start_size = 0, p = 32;
    for (uint32_t i = 0; i < kd_word(ctx, 16); ++i) {
        if (p > ctx->len || ctx->len - p < 8) return KD_NONE;
        uint32_t command = kd_word(ctx, p), length = kd_word(ctx, p + 4);
        if (length < 8 || length > ctx->len - p) return KD_NONE;
        if (command == 0x19 && length >= 72) {
            uint32_t count = kd_word(ctx, p + 64);
            if (count > (length - 72) / 80) return KD_NONE;
            for (uint32_t j = 0; j < count; ++j) {
                size_t section = p + 72 + j * 80;
                size_t offset = kd_word(ctx, section + 48);
                uint64_t size = ka_u64(ctx->buf + section + 40);
                if (offset > ctx->len || size > ctx->len - offset || (size & 7)) continue;
                if (!memcmp(ctx->buf + section, "__kmod_info\0", 12)) {
                    infos = offset; info_size = (size_t)size;
                } else if (!memcmp(ctx->buf + section, "__kmod_start\0", 13)) {
                    starts = offset; start_size = (size_t)size;
                }
            }
        }
        p += length;
    }
    if (infos == KD_NONE || starts == KD_NONE || !info_size || info_size > start_size)
        return KD_NONE;
    size_t selected = KD_NONE;
    for (size_t i = 0; i < info_size; i += 8) {
        size_t info = ka_pointer_offset(ctx, ka_u64(ctx->buf + infos + i));
        if (info == KD_NONE || info > name || name - info != 16) continue;
        size_t header = ka_pointer_offset(ctx, ka_u64(ctx->buf + starts + i));
        if (selected != KD_NONE && selected != header) return KD_NONE;
        selected = header;
    }
    return selected;
}

/* Accept packed and naturally aligned kmod_info layouts. */
static int ka_scope(const struct kd_ctx *ctx, struct ka_scope *scope) {
    const char name[] = "com.apple.driver.AppleMobileFileIntegrity";
    size_t selected = KD_NONE, cursor = 0;
    while (cursor < ctx->len) {
        const unsigned char *hit = memmem(ctx->buf + cursor, ctx->len - cursor, name, sizeof(name));
        if (!hit) break;
        size_t at = (size_t)(hit - ctx->buf);
        cursor = at + 1;
        if (at < 16 || ctx->len - at < 184 || read_le32(ctx->buf + at - 8) != 1) continue;
        for (unsigned alignment = 0; alignment < 2; ++alignment) {
            size_t header = ka_pointer_offset(ctx, ka_u64(ctx->buf + at + 140 + alignment * 4));
            if (header == KD_NONE) header = ka_indexed_header(ctx, at);
            if (header == KD_NONE || header > ctx->len || ctx->len - header < 32 ||
                kd_word(ctx, header) != 0xfeedfacf || kd_word(ctx, header + 4) != 0x0100000c ||
                kd_word(ctx, header + 12) != 11) continue;
            uint32_t count = kd_word(ctx, header + 16), size = kd_word(ctx, header + 20);
            if (!count || count > 128 || count > size / 8 || size > ctx->len - header - 32) continue;
            size_t p = header + 32, end = p + size;
            struct ka_scope found = {KD_NONE, KD_NONE, KD_NONE, 0};
            uint32_t parsed = 0;
            for (; parsed < count; ++parsed) {
                if (end - p < 8) break;
                uint32_t command = kd_word(ctx, p), length = kd_word(ctx, p + 4);
                if (length < 8 || length > end - p) break;
                if (command == 0x19 && length >= 72) {
                    uint64_t va = ka_u64(ctx->buf + p + 24), extent = ka_u64(ctx->buf + p + 48);
                    size_t offset = ka_pointer_offset(ctx, va);
                    if (extent && offset != KD_NONE && extent <= ctx->len - offset) {
                        if (!memcmp(ctx->buf + p + 8, "__TEXT_EXEC\0", 12) &&
                            kd_executable(ctx, offset) && kd_executable(ctx, offset + (size_t)extent - 4)) {
                            found.code = offset; found.code_end = offset + (size_t)extent;
                        } else if (!memcmp(ctx->buf + p + 8, "__TEXT\0", 7)) {
                            found.text = offset; found.text_size = (size_t)extent;
                            if ((kd_word(ctx, p + 60) & 4) && kd_executable(ctx, offset)) {
                                found.code = offset; found.code_end = offset + (size_t)extent;
                            }
                            /* Older prelinked containers mark __PRELINK_TEXT
                             * non-executable. Use the child instruction section. */
                            uint32_t sections=kd_word(ctx,p+64);
                            if(sections>(length-72)/80) break;
                            for(uint32_t k=0;k<sections;k++) {
                                size_t s=p+72+(size_t)k*80;
                                if(memcmp(ctx->buf+s,"__text\0",7) ||
                                   !(kd_word(ctx,s+64)&0x80000400u)) continue;
                                uint64_t a=ka_u64(ctx->buf+s+32),n=ka_u64(ctx->buf+s+40);
                                size_t at=ka_pointer_offset(ctx,a);
                                if(n>=4 && at!=KD_NONE && n<=ctx->len-at &&
                                   kd_executable(ctx,at) && kd_executable(ctx,at+(size_t)n-4)) {
                                    found.code=at;found.code_end=at+(size_t)n;
                                }
                            }
                        }
                    }
                }
                p += length;
            }
            if (parsed != count || p != end || found.code == KD_NONE) continue;
            if (found.text == KD_NONE) {
                /* Linker-flattened kexts have one tagged __TEXT_EXEC containing
                 * their code and constants, with no independent __TEXT. */
                found.text = found.code; found.text_size = found.code_end - found.code;
            }
            if (selected != KD_NONE && selected != header) return -1;
            selected = header; *scope = found;
        }
    }
    return selected == KD_NONE ? -1 : 0;
}

static int ka_scope_string(const struct kd_ctx *ctx, const struct ka_scope *scope, const char *s) {
    return memmem(ctx->buf + scope->text, scope->text_size, s, strlen(s)) != NULL;
}

static int ka_import_slot(const struct kd_ctx *ctx, size_t p, unsigned *reg, size_t *slot) {
    uint32_t page = kd_word(ctx, p), load = kd_word(ctx, p + 4);
    if ((page & 0x9f000000) != 0x90000000 || (load & 0xffc00000) != 0xf9400000 ||
        ((load >> 5) & 31) != (page & 31)) return 0;
    uint32_t bits = ((page >> 5) & 0x7ffff) << 2 | ((page >> 29) & 3);
    int64_t pages = (int64_t)(bits & 0x1fffff) - ((bits & 0x100000) ? 0x200000 : 0);
    uint64_t address = (kd_va(ctx, p) & ~UINT64_C(0xfff)) + pages * 4096 +
                       ((load >> 10) & 0xfff) * 8;
    *slot = kd_offset(ctx, address); *reg = load & 31;
    return *slot != KD_NONE && *slot <= ctx->len && ctx->len - *slot >= 8;
}

static int ka_fail(const char *message) {
    fprintf(stderr, "AMFI: %s\n", message);
    return -1;
}

static int ka_match(const struct kd_ctx *ctx, size_t p,
                    const uint32_t *words, const uint32_t *masks, size_t count) {
    if (p > ctx->len || count > (ctx->len - p) / 4) return 0;
    for (size_t i = 0; i < count; ++i)
        if (!kd_executable(ctx, p + i * 4) ||
            (kd_word(ctx, p + i * 4) & masks[i]) != words[i]) return 0;
    return 1;
}

static int ka_unique(size_t *selected, size_t p) {
    if (*selected != KD_NONE && *selected != p) return -1;
    *selected = p;
    return 0;
}

static size_t ka_follow_to(const struct kd_ctx *ctx, size_t p,
                           int (*stop)(const struct kd_ctx *, size_t)) {
    for (unsigned n = 0; n < 8 && p != KD_NONE; ++n) {
        if (!kd_executable(ctx, p)) return KD_NONE;
        if (stop && stop(ctx, p)) return p;
        size_t next;
        unsigned reg; size_t slot;
        if (kd_word(ctx, p) == 0xd503245f) next = p + 4; /* preserve BTI C landing pad */
        else if ((kd_word(ctx, p) & 0xfc000000) == 0x14000000) next = kd_branch(ctx, p);
        else if (ka_import_slot(ctx, p, &reg, &slot) &&
                 kd_word(ctx, p + 8) == (0xd61f0000 | (reg << 5)))
            next = ka_pointer_offset(ctx, ka_u64(ctx->buf + slot));
        else if ((kd_word(ctx, p) & 0x9f00001f) == 0x90000011 &&
                 (kd_word(ctx, p + 4) & 0xffc003ff) == 0x91000231 &&
                 kd_word(ctx, p + 8) == 0xf9400230 &&
                 kd_word(ctx, p + 12) == 0xd71f0a11) {
            /* ADRP/ADD X17; LDR X16,[X17]; BRAA X16,X17. */
            unsigned address_reg;
            if (!kd_address(ctx, p, &address_reg, &slot) || address_reg != 17 ||
                slot > ctx->len || ctx->len - slot < 8) return KD_NONE;
            uint64_t pointer = ka_u64(ctx->buf + slot);
            next = ka_pointer_offset(ctx, pointer);
            if (next == KD_NONE && (kd_word(ctx, 8) & 0xffffff) == 2 &&
                (pointer >> 62) == 2 && kd_va(ctx, 0) != UINT64_MAX) {
                /* Authenticated kernel-cache chained rebases carry a
                 * 32-bit target offset from the collection's mapped base. */
                uint64_t base = kd_va(ctx, 0);
                if ((uint32_t)pointer > UINT64_MAX - base) return KD_NONE;
                next = kd_offset(ctx, base + (uint32_t)pointer);
            }
        }
        else return p;
        if (next == p) return KD_NONE;
        p = next;
    }
    return KD_NONE;
}

static size_t ka_follow(const struct kd_ctx *ctx, size_t p) {
    return ka_follow_to(ctx,p,NULL);
}

/* The optional X2/X3 result carries trust flags, not just the query boolean. */
static int ka_trust_stub(const struct kd_ctx *ctx,size_t start,size_t end,unsigned argument) {
    if(end<start || end-start<16) return 0;
    for(size_t p=start;p+16<=end;p+=4)
        if(kd_word(ctx,p)==0xd2800020 &&
           kd_word(ctx,p+4)==(0xb4000040|argument) &&
           kd_word(ctx,p+8)==(0xf9000000|(argument<<5)) &&
           kd_word(ctx,p+12)==0xd65f03c0) return 1;
    return 0;
}
static size_t ka_ret0_stub(const struct kd_ctx *ctx,size_t start,size_t end) {
    if(end<start || end-start<8) return KD_NONE;
    for(size_t p=start;p+8<=end;p+=4)
        if(kd_word(ctx,p)==0x52800000 && kd_word(ctx,p+4)==0xd65f03c0) return p;
    return KD_NONE;
}
static int ka_prior_trust_stub(const struct kd_ctx *ctx,size_t anchor) {
    size_t start=anchor>512?anchor-512:0;
    return ka_trust_stub(ctx,start,anchor,2) || ka_trust_stub(ctx,start,anchor,3);
}
static int ka_trust(struct kd_ctx *ctx, const struct ka_scope *scope, int *modern, int emit) {
    size_t selected = KD_NONE, old = KD_NONE;
    unsigned selected_argument = 0;
    int old_ambiguous = 0, patched = 0;
    const uint32_t words[] = {0x910003e0, 0xaa0003e1, 0x94000000,
                              0x7100001f, 0x1a9f17e0};
    const uint32_t masks[] = {0xffffffff, 0xffe0ffff, 0xfc000000,
                              0xfffffc1f, 0xffffffff};
    for (size_t n = 0; n < ctx->region_count; ++n) {
        const struct kd_region *r = &ctx->regions[n];
        if (!r->executable) continue;
        size_t start = r->off > scope->code ? r->off : scope->code;
        size_t end = r->off + r->size < scope->code_end ? r->off + r->size : scope->code_end;
        for (size_t p = start; p < end && end - p >= 20; p += 4) {
            if (ka_match(ctx, p, words, masks, 5)) {
                unsigned output = (kd_word(ctx, p + 4) >> 16) & 31;
                unsigned error = (kd_word(ctx, p + 12) >> 5) & 31;
                size_t fn = kd_function(ctx, p);
                if(fn==KD_NONE && output>=19 && output<=28 && error>=19 && error<=28 &&
                   output!=error && ka_prior_trust_stub(ctx,p)) {
                    patched=1;
                    continue;
                }
                if (output < 19 || output > 28 || error < 19 || error > 28 ||
                    output == error || fn == KD_NONE || p < fn || p - fn > 512 ||
                    kd_branch(ctx, p + 8) == KD_NONE || p < 8 ||
                    kd_word(ctx, p - 4) != (0xf900001f | (output << 5)) ||
                    (kd_word(ctx, p - 8) & 0xff00001f) != (0xb4000000 | output) ||
                    kd_branch(ctx, p - 8) != p) continue;
                unsigned output_argument = 0;
                int saved_error = 0;
                for (size_t q = fn; q + 4 <= p; q += 4) {
                    for (unsigned argument = 2; argument <= 3; ++argument) {
                        if (kd_word(ctx, q) != (0xaa0003e0 | (argument << 16) | output))
                            continue;
                        if (output_argument && output_argument != argument)
                            return ka_fail("ambiguous trust-cache output argument");
                        output_argument = argument;
                    }
                    saved_error |= kd_word(ctx, q) == (0xaa0003e0 | error);
                }
                if (!output_argument || !saved_error) continue;
                /* A patched entry has no prologue. Require the stub and ABI
                 * body so a preceding function cannot supply a false match. */
                if(ka_trust_stub(ctx,fn,p,output_argument)) {
                    patched=1;
                    continue;
                }
                if (selected != KD_NONE && selected_argument != output_argument)
                    return ka_fail("ambiguous trust-cache output ABI");
                if (ka_unique(&selected, fn)) return ka_fail("ambiguous trust-cache query");
                selected_argument = output_argument;
            }
            /* Older query ABI returns a packed boolean/flags value. */
            if (kd_word(ctx, p) == 0x52802028 && p >= r->off + 4) {
                size_t call = p - 4;
                uint32_t preceding = kd_word(ctx, call);
                if ((preceding & 0xffff03f0) == 0xaa0003f0 && call >= r->off + 4)
                    call -= 4;
                if ((kd_word(ctx, call) & 0xfc000000) != 0x94000000) continue;
                size_t fn = ka_follow(ctx, kd_branch(ctx, call));
                if (fn == KD_NONE || kd_function(ctx, fn) != fn) continue;
                if (ka_unique(&old, fn)) old_ambiguous = 1;
            }
        }
    }
    if(patched) {
        if(selected!=KD_NONE) return ka_fail("patched and unpatched trust-query candidates disagree");
        *modern=1;
        if(emit) {
            kp.results[kp.active].status=KP_ALREADY;
            kp.results[kp.active].reason="Validated AMFI trust-query replacement already present";
        }
        return 0;
    }
    if (selected != KD_NONE) {
        /* ARM64e can pass the flags pointer in X3 instead of X2. */
        const uint32_t patch[] = {0xd2800020, 0xb4000040 | selected_argument,
                                 0xf9000000 | (selected_argument << 5), 0xd65f03c0};
        *modern = 1;
        return emit?kd_add(ctx, selected, patch, sizeof(patch), "AMFI trust query and output flags"):0;
    }
    if (old_ambiguous) return ka_fail("ambiguous legacy trust-cache query");
    if (old != KD_NONE) {
        const uint32_t patch[] = {0xd2802020, 0xd65f03c0};
        *modern = 0;
        return emit?kd_add(ctx, old, patch, sizeof(patch), "AMFI legacy trust-query flags"):0;
    }
    return ka_fail("unable to validate trust-cache query ABI");
}

static int ka_sha1(struct kd_ctx *ctx, const struct ka_scope *scope, int modern) {
    size_t selected = KD_NONE;
    for (size_t n = 0; n < ctx->region_count; ++n) {
        const struct kd_region *r = &ctx->regions[n];
        if (!r->executable) continue;
        size_t start = r->off > scope->code ? r->off : scope->code;
        size_t end = r->off + r->size < scope->code_end ? r->off + r->size : scope->code_end;
        for (size_t p = start; p < end && end - p >= 16; p += 4) {
            if ((kd_word(ctx, p) & 0xfff8001f) != 0x36d00002) continue;
            size_t stop = p + 64 < r->off + r->size ? p + 64 : r->off + r->size;
            for (size_t q = p + 4; q + 8 <= stop; q += 4) {
                uint32_t comparison=kd_word(ctx,q);
                if ((comparison != 0x7100081f && comparison != 0x6b00001f) ||
                    (kd_word(ctx, q + 4) & 0xff00001f) != 0x54000001 || q < p + 8 ||
                    (kd_word(ctx, q - 4) & 0xfc000000) != 0x94000000 ||
                    (kd_word(ctx, q - 8) & 0xffe0ffff) != 0xaa0003e0 ||
                    kd_branch(ctx, q - 4) == KD_NONE ||
                    kd_function(ctx, p) != kd_function(ctx, q)) continue;
                if (ka_unique(&selected, q)) return ka_fail("ambiguous code-directory hash-type check");
            }
        }
    }
    if (selected == KD_NONE) {
        /* ARM64e uses a dedicated SHA1 diagnostic. Both policy edges must
         * reach the same successor before bypassing the restriction. */
        size_t guard = KD_NONE, successor = KD_NONE;
        for (size_t p = scope->code; p + 36 <= scope->code_end; p += 4) {
            if ((kd_word(ctx, p) & 0xfff8001f) != 0x36d00002 ||
                (kd_word(ctx, p + 4) & 0xffe0ffff) != 0xaa0003e0 ||
                (kd_word(ctx, p + 8) & 0xfc000000) != 0x94000000 ||
                kd_word(ctx, p + 12) != 0x7100041f ||
                (kd_word(ctx, p + 16) & 0xff00001f) != 0x54000001 ||
                (kd_word(ctx, p + 32) & 0xfc000000) != 0x14000000) continue;
            size_t target = kd_branch(ctx, p), text;
            unsigned argument;
            if (target == KD_NONE || target != p + 36 ||
                kd_branch(ctx, p + 16) != target ||
                kd_branch(ctx, p + 8) == KD_NONE ||
                kd_function(ctx, p) != kd_function(ctx, target) ||
                !kd_address(ctx, p + 24, &argument, &text) || argument != 3 ||
                text < scope->text || text - scope->text >= scope->text_size ||
                ctx->len - text < sizeof("%s: Hash type is SHA1") ||
                memcmp(ctx->buf + text, "%s: Hash type is SHA1", sizeof("%s: Hash type is SHA1"))) continue;
            if (ka_unique(&guard, p)) return ka_fail("ambiguous ARM64e SHA1-policy guard");
            successor = target;
        }
        if (guard != KD_NONE) {
            int64_t distance = (int64_t)kd_va(ctx, successor) - (int64_t)kd_va(ctx, guard);
            if ((distance & 3) || distance < -0x8000000 || distance >= 0x8000000)
                return ka_fail("ARM64e SHA1-policy successor is out of range");
            return kd_add_word(ctx, guard, 0x14000000 | ((uint32_t)(distance / 4) & 0x3ffffff),
                               "AMFI ARM64e code-directory SHA1 acceptance");
        }
        if (modern) return ka_fail("missing hash-type check in modern AMFI query implementation");
        kp_absent("Validated legacy trust-query ABI has no modern SHA-1 policy guard");
        return 0;
    }
    return kd_add_word(ctx, selected, 0x6b00001f, "AMFI code-directory SHA1 acceptance");
}

static int ka_constraints(struct kd_ctx *ctx, const struct ka_scope *scope) {
    static const uint32_t words[] = {0x52806088, 0x14000000, 0x52802088,
                                     0x14000000, 0x52804088};
    static const uint32_t masks[] = {0xffffffff, 0xfc000000, 0xffffffff,
                                     0xfc000000, 0xffffffff};
    size_t selected = KD_NONE;
    int patched = 0;
    int present = ka_scope_string(ctx, scope, "LaunchConstraints.cpp") ||
                  ka_scope_string(ctx, scope, "AMFI: Launch Constraint Violation");
    for (size_t n = 0; n < ctx->region_count; ++n) {
        const struct kd_region *r = &ctx->regions[n];
        if (!r->executable) continue;
        size_t start = r->off > scope->code ? r->off : scope->code;
        size_t end = r->off + r->size < scope->code_end ? r->off + r->size : scope->code_end;
        for (size_t p = start; p < end && end - p >= 20; p += 4) {
            if (!ka_match(ctx, p, words, masks, 5)) continue;
            size_t fn = kd_function(ctx, p), a = kd_branch(ctx, p + 4), b = kd_branch(ctx, p + 12);
            if(fn!=KD_NONE && ka_ret0_stub(ctx,fn,p)!=KD_NONE) {
                patched=1;
                continue;
            }
            if (fn == KD_NONE || a == KD_NONE || b == KD_NONE ||
                kd_function(ctx, a) != fn || kd_function(ctx, b) != fn) continue;
            if (ka_unique(&selected, fn)) return ka_fail("ambiguous launch-constraint evaluator");
        }
    }
    /* Newer evaluators use helpers. Identify them by the violation reporter
     * and argument ABI when the adjacent MOV/B table is absent. */
    if (selected == KD_NONE && present) {
        const char marker[] = "AMFI: Launch Constraint Violation";
        const unsigned char *text = memmem(ctx->buf + scope->text, scope->text_size,
                                          marker, sizeof(marker) - 1);
        size_t logger = KD_NONE, evaluator = KD_NONE;
        if (text) {
            size_t string = (size_t)(text - ctx->buf), cursor = scope->code;
            while ((cursor = kd_xref(ctx, cursor, scope->code_end, string)) != KD_NONE) {
                size_t fn = kd_function(ctx, cursor);
                if (fn == KD_NONE || ka_unique(&logger, fn))
                    return ka_fail("ambiguous launch-constraint violation reporter");
                cursor += 4;
            }
        }
        unsigned calls = 0;
        size_t single_call = KD_NONE;
        if (logger != KD_NONE) {
            for (size_t p = scope->code; p + 4 <= scope->code_end; p += 4) {
                if ((kd_word(ctx, p) & 0xfc000000) != 0x94000000 ||
                    ka_follow(ctx, kd_branch(ctx, p)) != logger) continue;
                size_t fn = kd_function(ctx, p);
                if (fn == KD_NONE || fn == logger || fn < scope->code || fn >= scope->code_end)
                    return ka_fail("invalid launch-constraint evaluator entry");
                if(ka_ret0_stub(ctx,fn,fn+512<scope->code_end?fn+512:scope->code_end)!=KD_NONE) {
                    patched=1;
                    continue;
                }
                unsigned arguments = 0;
                for (size_t q = fn; q + 4 <= scope->code_end && q - fn < 128; q += 4) {
                    uint32_t op = kd_word(ctx, q);
                    unsigned to = op & 31, from = (op >> 16) & 31;
                    if ((op & 0xffe0ffe0) == 0xaa0003e0 && to >= 19 && to <= 28 &&
                        from <= 7) arguments |= 1u << from;
                }
                /* The original callback consumes eight arguments; the newer
                 * policy-object evaluator consumes its object and four args. */
                if ((arguments != 0xff && arguments != 0x1f) || ka_unique(&evaluator, fn))
                    return ka_fail("unrecognized launch-constraint evaluator ABI");
                ++calls;
                single_call = p;
            }
        }
        if (calls == 1 && evaluator != KD_NONE) {
            unsigned independent = 0;
            for (size_t p = evaluator; p + 4 <= scope->code_end; p += 4) {
                if (kd_function(ctx, p) != evaluator) break;
                uint32_t op = kd_word(ctx, p);
                if ((op & 0x7e000000) != 0x34000000 &&
                    (op & 0x7e000000) != 0x36000000 &&
                    (op & 0xff000010) != 0x54000000) continue;
                size_t target = kd_branch(ctx, p);
                if (target == KD_NONE || target > single_call || single_call - target > 32) continue;
                int linear = 1;
                for (size_t q = target; q < single_call; q += 4)
                    if (kd_branch(ctx, q) != KD_NONE || kd_word(ctx, q) == 0xd65f03c0 ||
                        kd_word(ctx, q) == 0xd65f0fff) { linear = 0; break; }
                if (linear) ++independent;
            }
            if (independent >= 2) calls = independent;
        }
        if(patched && evaluator == KD_NONE) {
            kp.results[kp.active].status=KP_ALREADY;
            kp.results[kp.active].reason="Validated AMFI launch-constraint replacement already present";
            return 0;
        }
        if (calls < 2 || evaluator == KD_NONE)
            return ka_fail("missing independent launch-constraint rejection paths");
        selected = evaluator;
    }
    if (selected == KD_NONE) {
        if(patched) {
            kp.results[kp.active].status=KP_ALREADY;
            kp.results[kp.active].reason="Validated AMFI launch-constraint replacement already present";
            return 0;
        }
        if (present) return ka_fail("launch-constraint feature exists but evaluator was not validated");
        kp_absent("Launch-constraint interface and evaluator absent in the mapped AMFI module");
        return 0;
    }
    const uint32_t patch[] = {0x52800000, 0xd65f03c0};
    return kd_add(ctx, selected, patch, sizeof(patch), "AMFI launch constraints");
}

static int ka_prefix(const struct kd_ctx *ctx, size_t p, const char *text) {
    size_t length = strlen(text);
    return p < ctx->len && length < ctx->len - p && !memcmp(ctx->buf + p, text, length);
}

static int ka_developer_body(const struct kd_ctx *ctx, size_t p, int enabled, uint32_t first,
                               size_t *slot, unsigned *field) {
    if (!kd_executable(ctx, p) || p > ctx->len || ctx->len - p < 20) return 0;
    /* One ABI passes the state directly to a common setter. */
    if (first == (enabled ? 0x52800020 : 0x52800000) &&
        (kd_word(ctx, p + 4) & 0xfc000000) == 0x14000000) {
        *slot = kd_branch(ctx, p + 4); *field = 0;
        return *slot != KD_NONE && kd_executable(ctx, *slot);
    }
    /* Newer setters share a MAC policy request layout and differ only in
     * the boolean payload at SP. */
    static const uint32_t request[] = {
        0xd503237f, 0xd10203ff, 0xa9077bfd, 0x9101c3fd,
        0x6f00e400, 0xf90033ff, 0xad0203e0, 0xad0103e0,
        0x3d8007e0, 0x528003e8, 0xb90013e8, 0x52800028,
        0x39005be8, 0xb9001fe8
    };
    int request_match = ctx->len - p >= 80;
    for (size_t i = 0; request_match && i < sizeof(request) / sizeof(request[0]); ++i)
        request_match = kd_executable(ctx, p + i * 4) &&
                        (i ? kd_word(ctx, p + i * 4) : first) == request[i];
    if (request_match && kd_word(ctx, p + 56) == (enabled ? 0xf90003e8 : 0xf90003ff) &&
        kd_word(ctx, p + 60) == 0x910043e0 &&
        (kd_word(ctx, p + 64) & 0xfc000000) == 0x94000000 &&
        kd_word(ctx, p + 68) == 0xa9477bfd && kd_word(ctx, p + 72) == 0x910203ff &&
        kd_word(ctx, p + 76) == 0xd65f0fff) {
        *slot = kd_branch(ctx, p + 64); *field = 0;
        return *slot != KD_NONE && kd_executable(ctx, *slot);
    }
    uint32_t page = first, load = kd_word(ctx, p + 4);
    if ((page & 0x9f000000) != 0x90000000 || (load & 0xffc00000) != 0xf9400000 ||
        ((load >> 5) & 31) != (page & 31)) return 0;
    uint32_t bits = ((page >> 5) & 0x7ffff) << 2 | ((page >> 29) & 3);
    int64_t pages = (int64_t)(bits & 0x1fffff) - ((bits & 0x100000) ? 0x200000 : 0);
    uint64_t address = (kd_va(ctx, p) & ~UINT64_C(0xfff)) + pages * 4096 +
                       ((load >> 10) & 0xfff) * 8;
    *slot = kd_offset(ctx, address);
    if (*slot == KD_NONE || kd_executable(ctx, *slot)) return 0;
    size_t store = p + 8;
    unsigned value = 31;
    if (enabled) {
        uint32_t move = kd_word(ctx, store);
        if ((move & 0xffffffe0) != 0x52800020 || (move & 31) == 31) return 0;
        value = move & 31;
        store += 4;
    }
    uint32_t op = kd_word(ctx, store);
    if ((op & 0xffc00000) != 0x39000000 || ((op >> 5) & 31) != (load & 31) ||
        (op & 31) != value || kd_word(ctx, store + 4) != 0xd65f03c0) return 0;
    *field = (op >> 10) & 0xfff;
    return 1;
}

static int ka_developer_setter(const struct kd_ctx *ctx, size_t p, int enabled,
                               size_t *slot, unsigned *field) {
    uint32_t first=kd_word(ctx,p);
    if(ka_developer_body(ctx,p,enabled,first,slot,field)) return 1;
    if(enabled || (first&0xfc000000u)!=0x14000000u || !kd_executable(ctx,p)) return 0;
    size_t target=kd_branch(ctx,p), shared;
    unsigned offset;
    if(target==KD_NONE || target==p ||
       !ka_developer_body(ctx,target,1,kd_word(ctx,target),&shared,&offset)) return 0;
    /* Reconstruct only the overwritten entry word. The retained disable body
     * must still address the enable setter's flag or shared operation. */
    uint32_t original=kd_word(ctx,target);
    if(original==0x52800020u) original=0x52800000u;
    else if((original&0x9f000000u)==0x90000000u) {
        uint32_t load=kd_word(ctx,p+4);
        if((load&0xffc00000u)!=0xf9400000u) return 0;
        uint64_t address=kd_va(ctx,shared), pc=kd_va(ctx,p);
        uint64_t displacement=((load>>10)&4095u)*8u;
        if(address==UINT64_MAX || pc==UINT64_MAX || address<displacement) return 0;
        address-=displacement;
        if(address&4095u) return 0;
        int64_t pages=(int64_t)(address>>12)-(int64_t)(pc>>12);
        if(pages<-(INT64_C(1)<<20) || pages>=(INT64_C(1)<<20)) return 0;
        uint32_t bits=(uint32_t)pages&0x1fffffu;
        original=0x90000000u|((bits&3u)<<29)|((bits>>2)<<5)|((load>>5)&31u);
    } else if(original!=0xd503237fu) return 0;
    if(!ka_developer_body(ctx,p,0,original,slot,field)) return 0;
    return *slot==shared && *field==offset;
}

static int ka_developer_disable(const struct kd_ctx *ctx, size_t p) {
    size_t slot;
    unsigned field;
    return ka_developer_setter(ctx,p,0,&slot,&field);
}

static size_t ka_developer_entry(const struct kd_ctx *ctx, size_t p, int enabled) {
    size_t slot;
    unsigned field;
    /* Stop at the disable entry before following its patched redirect. */
    size_t fn = ka_follow_to(ctx,p,enabled?NULL:ka_developer_disable);
    if (fn == KD_NONE) return KD_NONE;
    if (ka_developer_setter(ctx, fn, enabled, &slot, &field)) return fn;
    /* Some builds wrap the enable operation in initialization work. Accept
     * only a first, unconditional call after a verified save-only prologue. */
    if (kd_function(ctx, fn) != fn) return KD_NONE;
    for (size_t q = fn; q + 4 <= ctx->len && q - fn <= 32; q += 4) {
        if (!kd_executable(ctx, q)) return KD_NONE;
        uint32_t op = kd_word(ctx, q);
        if ((op & 0xfc000000) == 0x94000000) {
            size_t target = ka_follow_to(ctx,kd_branch(ctx,q),enabled?NULL:ka_developer_disable);
            return target != KD_NONE && ka_developer_setter(ctx, target, enabled, &slot, &field)
                ? target : KD_NONE;
        }
        if ((op & 0xffc003ff) == 0xd10003ff || (op & 0xffc003ff) == 0x910003fd ||
            (op & 0xffc003e0) == 0xa90003e0 || (op & 0xffc003e0) == 0xa98003e0 ||
            op == 0xd503237f || op == 0xd503233f || op == 0xd503201f) continue;
        return KD_NONE;
    }
    return KD_NONE;
}

static int ka_developer(struct kd_ctx *ctx, const struct ka_scope *scope) {
    size_t enable = KD_NONE, disable = KD_NONE;
    size_t forced = KD_NONE;
    int present = ka_scope_string(ctx, scope, "developer mode");
    for (size_t n = 0; n < ctx->region_count; ++n) {
        const struct kd_region *r = &ctx->regions[n];
        if (!r->executable) continue;
        size_t start = r->off > scope->code ? r->off : scope->code;
        size_t end = r->off + r->size < scope->code_end ? r->off + r->size : scope->code_end;
        for (size_t p = start; p < end && end - p >= 16; p += 4) {
            unsigned reg;
            size_t string;
            if (!kd_address(ctx, p, &reg, &string) || reg != 0 ||
                (kd_word(ctx, p) & 0x9f000000) != 0x90000000 ||
                (kd_word(ctx, p + 8) & 0xfc000000) != 0x94000000 ||
                (kd_word(ctx, p + 12) & 0xfc000000) != 0x94000000) continue;
            int enabling = ka_prefix(ctx, string, "AMFI: Enabling developer mode since ");
            int disabling = ka_prefix(ctx, string, "AMFI: Disable developer mode since ");
            int forcing = ka_prefix(ctx, string, "AMFI: developer mode is force enabled on this platform");
            if (!enabling && !disabling && !forcing) continue;
            present = 1;
            size_t fn = ka_developer_entry(ctx, kd_branch(ctx, p + 12), enabling || forcing);
            size_t slot; unsigned field;
            if (fn == KD_NONE || !ka_developer_setter(ctx, fn, enabling || forcing, &slot, &field))
                return ka_fail("developer-mode setter could not be validated");
            if (ka_unique(forcing ? &forced : enabling ? &enable : &disable, fn))
                return ka_fail("ambiguous developer-mode setter");
        }
    }
    if (enable == KD_NONE || disable == KD_NONE) {
        if (forced != KD_NONE && disable == KD_NONE) {
            kp.results[kp.active].status=KP_ALREADY;
            kp.results[kp.active].reason="Validated platform path already forces Developer Mode";
            return 0;
        }
        if (present) return ka_fail("developer-mode feature exists without both validated setters");
        kp_absent("Developer Mode interface and setters absent in the mapped AMFI module");
        return 0;
    }
    size_t a, b; unsigned x, y;
    if (!ka_developer_setter(ctx, enable, 1, &a, &x) ||
        !ka_developer_setter(ctx, disable, 0, &b, &y) || a != b || x != y || enable == disable)
        return ka_fail("developer-mode setters do not modify the same flag");
    int64_t distance = (int64_t)kd_va(ctx, enable) - (int64_t)kd_va(ctx, disable);
    if ((distance & 3) || distance < -0x8000000 || distance >= 0x8000000)
        return ka_fail("developer-mode setter branch is out of range");
    return kd_add_word(ctx, disable, 0x14000000 | ((uint32_t)(distance / 4) & 0x3ffffff),
                       "AMFI developer-mode preservation");
}

static int kd_amfi_patch(struct kd_ctx *ctx, enum kp_id id) {
    int modern = 0;
    struct ka_scope scope={0,0,0,0};
    if (ka_scope(ctx, &scope)) return ka_fail("cannot validate the AMFI kext mapping");
    switch(id) {
    case KP_AMFI_TRUST: return ka_trust(ctx,&scope,&modern,1);
    case KP_AMFI_SHA1:
        /* Inspect the query ABI without requesting or recording its edit. */
        if(ka_trust(ctx,&scope,&modern,0)) return -1;
        return ka_sha1(ctx,&scope,modern);
    case KP_LAUNCH_CONSTRAINTS:
        return ka_constraints(ctx,&scope);
    case KP_DEVELOPER_MODE:
        return ka_developer(ctx,&scope);
    default: return -1;
    }
}
