#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>

#include <string>
#include <vector>
#include <iostream>
#include "json.hpp"

using json = nlohmann::json;

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

static const char* LICENSE_HMAC_SECRET = "mss_semd_2026_super_secret_fixed_01";

// --- base64url encode ---
static std::string b64url_encode(const std::vector<unsigned char>& data) {
    DWORD outLen = 0;
    CryptBinaryToStringA(data.data(), (DWORD)data.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outLen);

    std::string b64(outLen, '\0');
    CryptBinaryToStringA(data.data(), (DWORD)data.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &b64[0], &outLen);

    while (!b64.empty() && (b64.back() == '\0' || b64.back() == '\n')) b64.pop_back();

    for (char& c : b64) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    while (!b64.empty() && b64.back() == '=') b64.pop_back();

    return b64;
}

// --- HMAC ---
static bool hmac_sha256(const std::string& data, std::vector<unsigned char>& out) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD objLen = 0, hashLen = 0, cbData = 0;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cbData, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cbData, 0);

    std::vector<unsigned char> obj(objLen);
    out.resize(hashLen);

    BCryptCreateHash(hAlg, &hHash, obj.data(), objLen,
        (PUCHAR)LICENSE_HMAC_SECRET, (ULONG)strlen(LICENSE_HMAC_SECRET), 0);

    BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    BCryptFinishHash(hHash, out.data(), hashLen, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
}

// --- MAIN ---
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "usage: keygen <productCode> <expires_utc>\n";
        return 1;
    }

    std::string productCode = argv[1];
    std::string expires = argv[2];

    json j;
    j["product_code"] = productCode;
    j["expires_utc"] = expires;

    std::string payload = j.dump();

    std::vector<unsigned char> payloadBytes(payload.begin(), payload.end());
    std::string part1 = b64url_encode(payloadBytes);

    std::vector<unsigned char> mac;
    hmac_sha256(payload, mac);
    std::string part2 = b64url_encode(mac);

    std::string codeKey = part1 + "." + part2;

    std::cout << codeKey << std::endl;
    return 0;
}