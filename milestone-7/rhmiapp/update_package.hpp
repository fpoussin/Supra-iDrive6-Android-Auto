// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Required Notice: Copyright (c) 2026 nanaisu - NBT-AAD (https://github.com/Sq00ky/Supra-iDrive6-Android-Auto)
#ifndef NBT_UPDATE_PACKAGE_HPP
#define NBT_UPDATE_PACKAGE_HPP

// OTA packages contain one signed manifest and one daemon binary. Verification
// accepts a public key supplied by the caller; never take this key from a package.
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

namespace nbt { namespace update {
static const unsigned kMaxManifest = 512;
static const unsigned kMaxSignature = 1024;
static const unsigned kMaxBinary = 32u * 1024u * 1024u;

inline uint32_t be32(const unsigned char* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

// The package is NBTOTA1\n, three big-endian u32 lengths, manifest, signature,
// then executable. The RSA/SHA-256 signature covers the exact manifest bytes.
inline bool verify(FILE* f, const char* trustedPem, std::string& version, std::string& error) {
    version.clear(); error.clear();
    unsigned char hdr[20];
    if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr) || memcmp(hdr, "NBTOTA1\n", 8)) {
        error = "invalid package header"; return false;
    }
    const uint32_t ml = be32(hdr + 8), sl = be32(hdr + 12), bl = be32(hdr + 16);
    if (!ml || ml > kMaxManifest || !sl || sl > kMaxSignature || bl < 52 || bl > kMaxBinary) {
        error = "invalid package size"; return false;
    }
    std::vector<unsigned char> manifest(ml), signature(sl);
    if (fread(&manifest[0], 1, ml, f) != ml || fread(&signature[0], 1, sl, f) != sl) {
        error = "truncated package"; return false;
    }
    BIO* bio = BIO_new_mem_buf(const_cast<char*>(trustedPem), -1);
    EVP_PKEY* key = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    bool ok = key &&
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
              EVP_PKEY_base_id(key) == EVP_PKEY_RSA &&
#else
              EVP_PKEY_type(key->type) == EVP_PKEY_RSA &&
#endif
              ctx &&
              EVP_VerifyInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
              EVP_VerifyUpdate(ctx, &manifest[0], ml) == 1 &&
              EVP_VerifyFinal(ctx, &signature[0], sl, key) == 1;
    if (ctx) EVP_MD_CTX_destroy(ctx);
    if (key) EVP_PKEY_free(key);
    if (bio) BIO_free(bio);
    if (!ok) { error = "invalid signature"; return false; }

    // Strict grammar prevents duplicate fields, alternate spellings and paths.
    std::string m((const char*)&manifest[0], ml);
    const std::string prefix = "NBT-AAD-OTA-1\nversion=";
    if (m.compare(0, prefix.size(), prefix)) { error = "invalid manifest"; return false; }
    size_t end = m.find('\n', prefix.size());
    if (end == std::string::npos || end == prefix.size() || end - prefix.size() > 80) {
        error = "invalid version"; return false;
    }
    version = m.substr(prefix.size(), end - prefix.size());
    for (size_t i = 0; i < version.size(); ++i) {
        char c = version[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) {
            error = "invalid version"; return false;
        }
    }
    const std::string tag = "\nsha256=";
    if (m.size() != end + tag.size() + 64 + 1 || m.compare(end, tag.size(), tag) || m[m.size()-1] != '\n') {
        error = "invalid manifest"; return false;
    }
    const std::string expected = m.substr(end + tag.size(), 64);
    for (size_t i = 0; i < expected.size(); ++i)
        if (!((expected[i] >= '0' && expected[i] <= '9') || (expected[i] >= 'a' && expected[i] <= 'f'))) {
            error = "invalid digest"; return false;
        }
    SHA256_CTX hash; SHA256_Init(&hash);
    unsigned char buf[8192], elf[20];
    uint32_t remaining = bl; bool first = true;
    while (remaining) {
        size_t n = remaining < sizeof(buf) ? remaining : sizeof(buf);
        if (fread(buf, 1, n, f) != n) { error = "truncated executable"; return false; }
        if (first) { memcpy(elf, buf, sizeof(elf)); first = false; }
        SHA256_Update(&hash, buf, n); remaining -= (uint32_t)n;
    }
    if (fgetc(f) != EOF || ferror(f)) { error = "trailing data or read error"; return false; }
    if (memcmp(elf, "\177ELF", 4) || elf[4] != 1 || elf[5] != 1 || elf[16] != 2 || elf[17] != 0 ||
        elf[18] != 40 || elf[19] != 0) { error = "not an ARM little-endian executable"; return false; }
    unsigned char digest[SHA256_DIGEST_LENGTH]; SHA256_Final(digest, &hash);
    static const char hex[] = "0123456789abcdef";
    std::string actual;
    for (unsigned i = 0; i < sizeof(digest); ++i) { actual += hex[digest[i] >> 4]; actual += hex[digest[i] & 15]; }
    if (actual != expected) { error = "executable digest mismatch"; return false; }
    return true;
}
} }
#endif
