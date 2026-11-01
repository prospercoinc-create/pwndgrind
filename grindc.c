// ed25519 vanity grind, prefix prefilter via 32-byte range compare
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

static unsigned char LOB[32], HIB[32];


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

static int b58dec(const char *s, unsigned char out[32]) {
    static const char *A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    unsigned char buf[64]; memset(buf, 0, sizeof buf);
    for (; *s; s++) {
        const char *p = strchr(A, *s); if (!p) return -1;
        int carry = (int)(p - A);
        for (int i = 63; i >= 0; i--) { carry += buf[i] * 58; buf[i] = carry & 0xff; carry >>= 8; }
    }
    memcpy(out, buf + 32, 32);
    return 0;
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) return 1;
    if (argc < 4) { fprintf(stderr, "usage: %s start count [tag] [prefix]\n", argv[0]); return 1; }
    const char *prefix = argc > 4 ? argv[4] : "pwndL";
    char lo[64], hi[64];
    int pl = strlen(prefix);
    memcpy(lo, prefix, pl); memset(lo + pl, '1', 43 - pl); lo[43 - pl + pl] = 0;
    memcpy(hi, prefix, pl); memset(hi + pl, 'z', 43 - pl); hi[43 - pl + pl] = 0;
    if (b58dec(lo, LOB) || b58dec(hi, HIB)) { fprintf(stderr, "bad prefix\n"); return 1; }

    uint64_t start = strtoull(argv[1], 0, 10), count = strtoull(argv[2], 0, 10);
    const char *tag = argc > 3 ? argv[3] : "c";
    char outpath[128]; snprintf(outpath, sizeof outpath, "hits_%s.txt", tag);
    FILE *out = fopen(outpath, "a");
    time_t t0 = time(NULL);
    unsigned char seed[32] = {0}, pk[32], sk[64];
    uint64_t done = 0, nextprog = 100000;

    for (uint64_t i = start; i < start + count; i++) {
        memcpy(seed, &i, 8); memset(seed + 8, 0, 24);
        crypto_sign_seed_keypair(pk, sk, seed);
        if (memcmp(pk, LOB, 32) >= 0 && memcmp(pk, HIB, 32) <= 0) {
            char b58[64]; b58enc_c(b58, pk, 32);
            fprintf(out, "%s\tle32\t%llu\t", b58, (unsigned long long)i);
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
