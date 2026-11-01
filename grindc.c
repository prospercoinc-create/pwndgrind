// ed25519 vanity grind, prefix prefilter via 32-byte range compare
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

static unsigned char LOB[33], HIB[33], LOB2[33], HIB2[33];


static void b58enc_c(char *out, const unsigned char *bin, size_t len) {
    static const char *A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    unsigned char buf[128]; int carry, i; size_t j;
    memset(buf, 0, sizeof buf);
    for (i = 0; i < (int)len; i++) {
        carry = bin[i];
        for (j = sizeof buf; j-- > 0; ) { carry += 256 * buf[j]; buf[j] = carry % 58; carry /= 58; }
    }
    for (j = 0; j < sizeof buf && buf[j] == 0; j++) ;
    char *o = out;
    for (; j < sizeof buf; j++) *o++ = A[buf[j]];
    *o = 0;
}

static int b58dec(const char *s, unsigned char out[33]) {
    static const char *A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    unsigned char buf[64]; memset(buf, 0, sizeof buf);
    for (; *s; s++) {
        const char *p = strchr(A, *s); if (!p) return -1;
        int carry = (int)(p - A);
        for (int i = 63; i >= 0; i--) { carry += buf[i] * 58; buf[i] = carry & 0xff; carry >>= 8; }
    }
    memcpy(out, buf + 31, 33);
    return 0;
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) return 1;
    if (argc < 4) { fprintf(stderr, "usage: %s start count [tag] [prefix]\n", argv[0]); return 1; }
    const char *prefix = argc > 4 ? argv[4] : "pwndL";
    const char *scheme = argc > 5 ? argv[5] : "le32";
    int off = 0, be = 0;
    if (!strcmp(scheme, "be32")) { off = 28; be = 1; }
    else if (!strncmp(scheme, "off", 3)) { off = atoi(scheme + 3); }
    else if (!strcmp(scheme, "le64")) { off = 0; be = 2; }
    else if (!strcmp(scheme, "be64")) { off = 24; be = 2; }
    else if (!strcmp(scheme, "le32")) { off = 0; }
    else { fprintf(stderr, "bad scheme\n"); return 1; }
    char lo[64], hi[64];
    int pl = strlen(prefix);
    memcpy(lo, prefix, pl); memset(lo + pl, '1', 43 - pl); lo[43 - pl + pl] = 0;
    memcpy(hi, prefix, pl); memset(hi + pl, 'z', 43 - pl); hi[43 - pl + pl] = 0;
    if (b58dec(lo, LOB) || b58dec(hi, HIB)) { fprintf(stderr, "bad prefix\n"); return 1; }
    char lo2[64], hi2[64];
    memcpy(lo2, prefix, pl); memset(lo2 + pl, '1', 44 - pl); lo2[44] = 0;
    memcpy(hi2, prefix, pl); memset(hi2 + pl, 'z', 44 - pl); hi2[44] = 0;
    if (b58dec(lo2, LOB2) || b58dec(hi2, HIB2)) { fprintf(stderr, "bad prefix\n"); return 1; }

    uint64_t start = strtoull(argv[1], 0, 10), count = strtoull(argv[2], 0, 10);
    const char *tag = argc > 3 ? argv[3] : "c";
    char outpath[128]; snprintf(outpath, sizeof outpath, "hits_%s.txt", tag);
    FILE *out = fopen(outpath, "a");
    time_t t0 = time(NULL);
    unsigned char seed[32] = {0}, pk[32], sk[64];
    uint64_t done = 0, nextprog = 100000;

    for (uint64_t i = start; i < start + count; i++) {
        uint32_t iv = (uint32_t)i;
        memset(seed, 0, 32);
        if (be == 2) {
            if (off) { for (int k = 0; k < 8; k++) seed[off + k] = (i >> (8 * (7 - k))) & 0xff; }
            else { for (int k = 0; k < 8; k++) seed[k] = (i >> (8 * k)) & 0xff; }
        }
        else if (be) { seed[off] = (iv >> 24) & 0xff; seed[off+1] = (iv >> 16) & 0xff; seed[off+2] = (iv >> 8) & 0xff; seed[off+3] = iv & 0xff; }
        else { seed[off] = iv & 0xff; seed[off+1] = (iv >> 8) & 0xff; seed[off+2] = (iv >> 16) & 0xff; seed[off+3] = (iv >> 24) & 0xff; }
        if (argc > 6 && i == start) { fprintf(stderr, "seed:"); for (int k=0;k<32;k++) fprintf(stderr,"%02x",seed[k]); fprintf(stderr,"n"); }
        crypto_sign_seed_keypair(pk, sk, seed);
        unsigned char p33[33]; p33[0] = 0; memcpy(p33 + 1, pk, 32);
        if (argc > 6) { fprintf(stderr, "pk:"); for (int k=0;k<32;k++) fprintf(stderr,"%02x",pk[k]); fprintf(stderr, "|"); }
        if (argc > 6) fprintf(stderr, " cmp %d %d %d %d a%d b%d", memcmp(p33,LOB,33), memcmp(p33,HIB,33), memcmp(p33,LOB2,33), memcmp(p33,HIB2,33), LOB2[4], HIB2[4]);
        if ((memcmp(p33, LOB, 33) >= 0 && memcmp(p33, HIB, 33) <= 0) ||
            (memcmp(p33, LOB2, 33) >= 0 && memcmp(p33, HIB2, 33) <= 0)) {
            char b58[64]; b58enc_c(b58, pk, 32);
            if (strncmp(b58, prefix, pl)) continue;
            fprintf(out, "%s\t%s\t%llu\t", b58, scheme, (unsigned long long)i);
            for (int k = 0; k < 32; k++) fprintf(out, "%02x", seed[k]);
            fprintf(out, "\n"); fflush(out);
        }
        if (++done >= nextprog) {
            double el = difftime(time(NULL), t0);
            printf("PROG %s %llu %.0fs %.0f/s\n", tag, (unsigned long long)(start + done), el, done / (el > 0 ? el : 1));
            fflush(stdout);
            nextprog += 100000;
        }
    }
    printf("DONE %s %llu\n", tag, (unsigned long long)(start + count));
    fclose(out);
    return 0;
}
