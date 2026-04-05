#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <windows.h>
#include <winhttp.h>
#include <sqlext.h>
#include <sqltypes.h>
#include <sql.h>
#include <objbase.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "json.hpp"
using json = nlohmann::json;

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "odbc32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")

static const wchar_t* SERVICE_NAME_W = L"mss_semd_checking";
static const char* LICENSE_HMAC_SECRET = "mss_semd_2026_super_secret_fixed_01";

struct Config {
    std::string odbc_conn;
    std::string base_url;
    std::string token;
    std::string events_endpoint = "/EventLog/GetEvents";
    std::string system_oid;
    std::string program_name = "mss_semd_checking";
    std::string sql_login_name = "mss_semd_checking";
    int poll_interval_seconds = 300;
    int top_n = 500;
    int http_timeout_ms = 30000;
    std::string log_dir;
    std::string date_begin;
    std::string date_end;
    std::string modified_date_begin;
    std::string modified_date_end;
};

struct EventRow {
    std::string idLpu;
    std::string name;
    std::string systemName;
    std::string systemOid;
    std::string date;
    std::string modifiedDate;
    std::string organization;
    std::string department;
    std::string idCaseMis;
    std::string idDocumentMis;
    std::string emdType;
    int emdTypeId = -1;
    int iemkTypeId = -1;
    int status = -1;
    std::string message;
    std::string remdRegNumber;
    std::string idSource;
    std::string dataSource;
    std::string statusText;
    std::string goalText;
    std::string idFedRequest;
    std::string transferId;
    int goal = -1;
    int idDataSource = -1;
    std::string sourceTypeName;
};

static SERVICE_STATUS_HANDLE g_serviceHandle = nullptr;
static SERVICE_STATUS g_serviceStatus{};
static HANDLE g_stopEvent = nullptr;
static std::atomic<bool> g_consoleMode{false};
static std::string g_iniPath;
static std::string g_logDir;

// ------------------------------------------------------------
// Logger
// ------------------------------------------------------------
class Logger {
public:
    bool init(const std::string& dir) {
        dir_ = dir;
        if (dir_.empty()) return false;
        CreateDirectoryA(dir_.c_str(), nullptr);
        filePath_ = dir_ + "\\mss_semd_checking.log";
        return true;
    }

    void info(const char* fmt, ...) {
        va_list ap; va_start(ap, fmt); write("INFO", fmt, ap); va_end(ap);
    }
    void warn(const char* fmt, ...) {
        va_list ap; va_start(ap, fmt); write("WARN", fmt, ap); va_end(ap);
    }
    void error(const char* fmt, ...) {
        va_list ap; va_start(ap, fmt); write("ERROR", fmt, ap); va_end(ap);
    }

private:
    std::mutex mu_;
    std::string dir_;
    std::string filePath_;

    static std::string nowStr() {
        SYSTEMTIME st; GetLocalTime(&st);
        char buf[64];
        sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        return buf;
    }

    void write(const char* lvl, const char* fmt, va_list ap) {
        char msg[8192];
        vsnprintf(msg, sizeof(msg), fmt, ap);
        std::ostringstream oss;
        oss << nowStr() << " [" << lvl << "] " << msg << "\r\n";
        std::string line = oss.str();

        std::lock_guard<std::mutex> lock(mu_);
        FILE* f = nullptr;
        fopen_s(&f, filePath_.c_str(), "ab");
        if (f) {
            fwrite(line.data(), 1, line.size(), f);
            fclose(f);
        }
        if (g_consoleMode.load()) {
            std::fwrite(line.data(), 1, line.size(), stdout);
            std::fflush(stdout);
        }
    }
};

static Logger g_log;

// ------------------------------------------------------------
// INI helpers
// ------------------------------------------------------------
static std::string trim(std::string s) {
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ' || s.back() == '\t')) s.pop_back();
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    return s.substr(i);
}

static std::string iniGet(const std::string& path, const std::string& section, const std::string& key, const std::string& defv) {
    char buf[4096]{};
    GetPrivateProfileStringA(section.c_str(), key.c_str(), defv.c_str(), buf, (DWORD)sizeof(buf), path.c_str());
    return trim(buf);
}

static bool loadConfig(const std::string& iniPath, Config& cfg, std::string& err) {
    cfg.odbc_conn = iniGet(iniPath, "database", "odbc_conn", "");
    if (cfg.odbc_conn.empty()) { err = "ini: [database].odbc_conn is empty"; return false; }

    cfg.base_url = iniGet(iniPath, "netrika", "base_url", "");
    cfg.token = iniGet(iniPath, "netrika", "token", "");
    cfg.events_endpoint = iniGet(iniPath, "netrika", "events_endpoint", cfg.events_endpoint);
    cfg.system_oid = iniGet(iniPath, "netrika", "system_oid", "");
    if (cfg.base_url.empty()) { err = "ini: [netrika].base_url is empty"; return false; }
    if (cfg.token.empty()) { err = "ini: [netrika].token is empty"; return false; }
    if (cfg.system_oid.empty()) { err = "ini: [netrika].system_oid is empty"; return false; }

    cfg.program_name = iniGet(iniPath, "params", "program_name", cfg.program_name);
    cfg.sql_login_name = iniGet(iniPath, "params", "sql_login_name", cfg.sql_login_name);
    cfg.poll_interval_seconds = std::max(30, atoi(iniGet(iniPath, "params", "poll_interval_seconds", "300").c_str()));
    cfg.top_n = std::max(1, atoi(iniGet(iniPath, "params", "top_n", "500").c_str()));
    cfg.http_timeout_ms = std::max(1000, atoi(iniGet(iniPath, "params", "http_timeout_ms", "30000").c_str()));
    cfg.log_dir = iniGet(iniPath, "logging", "log_dir", g_logDir);
    cfg.date_begin = iniGet(iniPath, "params", "date_begin", "");
    cfg.date_end = iniGet(iniPath, "params", "date_end", "");
    cfg.modified_date_begin = iniGet(iniPath, "params", "modified_date_begin", "");
    cfg.modified_date_end = iniGet(iniPath, "params", "modified_date_end", "");
    return true;
}

// ------------------------------------------------------------
// SQL helpers
// ------------------------------------------------------------
static std::string sqlEscape(std::string s) {
    size_t pos = 0;
    while ((pos = s.find('\'', pos)) != std::string::npos) {
        s.insert(pos, 1, '\'');
        pos += 2;
    }
    return s;
}

class SqlDb {
public:
    SqlDb() = default;
    ~SqlDb() { close(); }

    bool open(const std::string& connStr, std::string& err) {
        close();

        if (SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &henv_) != SQL_SUCCESS) {
            err = "SQLAllocHandle ENV failed";
            return false;
        }
        SQLSetEnvAttr(henv_, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0);
        if (SQLAllocHandle(SQL_HANDLE_DBC, henv_, &hdbc_) != SQL_SUCCESS) {
            err = "SQLAllocHandle DBC failed";
            return false;
        }

        SQLCHAR outConn[4096]; SQLSMALLINT outLen = 0;
        SQLRETURN rc = SQLDriverConnectA(
            hdbc_, nullptr,
            (SQLCHAR*)connStr.c_str(), SQL_NTS,
            outConn, sizeof(outConn), &outLen,
            SQL_DRIVER_NOPROMPT);

        if (!(rc == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO)) {
            err = collectDiag(SQL_HANDLE_DBC, hdbc_);
            return false;
        }
        return true;
    }

    void close() {
        if (hdbc_) {
            SQLDisconnect(hdbc_);
            SQLFreeHandle(SQL_HANDLE_DBC, hdbc_);
            hdbc_ = nullptr;
        }
        if (henv_) {
            SQLFreeHandle(SQL_HANDLE_ENV, henv_);
            henv_ = nullptr;
        }
    }

    bool exec(const std::string& sql, std::string* err = nullptr) {
        SQLHSTMT stmt = nullptr;
        if (SQLAllocHandle(SQL_HANDLE_STMT, hdbc_, &stmt) != SQL_SUCCESS) {
            if (err) *err = "SQLAllocHandle STMT failed";
            return false;
        }
        SQLRETURN rc = SQLExecDirectA(stmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
        bool ok = (rc == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO);
        if (!ok && err) *err = collectDiag(SQL_HANDLE_STMT, stmt);
        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        return ok;
    }

    bool querySingleString(const std::string& sql, std::string& val, std::string& err) {
        SQLHSTMT stmt = nullptr;
        if (SQLAllocHandle(SQL_HANDLE_STMT, hdbc_, &stmt) != SQL_SUCCESS) {
            err = "SQLAllocHandle STMT failed";
            return false;
        }
        SQLRETURN rc = SQLExecDirectA(stmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
        if (!(rc == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO)) {
            err = collectDiag(SQL_HANDLE_STMT, stmt);
            SQLFreeHandle(SQL_HANDLE_STMT, stmt);
            return false;
        }
        rc = SQLFetch(stmt);
        if (!(rc == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO)) {
            err = "No rows";
            SQLFreeHandle(SQL_HANDLE_STMT, stmt);
            return false;
        }
        char buf[8192]{}; SQLLEN ind = 0;
        rc = SQLGetData(stmt, 1, SQL_C_CHAR, buf, sizeof(buf), &ind);
        if (!(rc == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO)) {
            err = collectDiag(SQL_HANDLE_STMT, stmt);
            SQLFreeHandle(SQL_HANDLE_STMT, stmt);
            return false;
        }
        val = (ind == SQL_NULL_DATA) ? "" : std::string(buf);
        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        return true;
    }

private:
    SQLHENV henv_ = nullptr;
    SQLHDBC hdbc_ = nullptr;

    static std::string collectDiag(SQLSMALLINT type, SQLHANDLE handle) {
        std::ostringstream oss;
        SQLCHAR state[16]{};
        SQLINTEGER native = 0;
        SQLCHAR text[1024]{};
        SQLSMALLINT len = 0;
        SQLSMALLINT i = 1;
        while (SQLGetDiagRecA(type, handle, i++, state, &native, text, sizeof(text), &len) == SQL_SUCCESS) {
            oss << "[" << state << "] " << text << " ";
        }
        return oss.str();
    }
};

// ------------------------------------------------------------
// Crypto: license
// ------------------------------------------------------------
static std::string b64url_encode(const std::vector<unsigned char>& data) {
    DWORD outLen = 0;
    if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outLen)) {
        return "";
    }
    std::string b64(outLen, '\0');
    if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &b64[0], &outLen)) {
        return "";
    }
    while (!b64.empty() && (b64.back() == '\0' || b64.back() == '\r' || b64.back() == '\n')) b64.pop_back();
    for (char& c : b64) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    while (!b64.empty() && b64.back() == '=') b64.pop_back();
    return b64;
}

static bool b64url_decode(std::string s, std::vector<unsigned char>& out) {
    for (char& c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (s.size() % 4) s.push_back('=');
    DWORD outLen = 0;
    if (!CryptStringToBinaryA(s.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &outLen, nullptr, nullptr)) return false;
    out.resize(outLen);
    if (!CryptStringToBinaryA(s.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &outLen, nullptr, nullptr)) return false;
    out.resize(outLen);
    return true;
}

static bool hmac_sha256(const std::string& data, std::vector<unsigned char>& out) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD objLen = 0, cbData = 0, hashLen = 0;
    std::vector<unsigned char> obj;
    out.clear();

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) return false;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cbData, 0) != 0) goto fail;
    if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cbData, 0) != 0) goto fail;
    obj.resize(objLen);
    out.resize(hashLen);
    if (BCryptCreateHash(hAlg, &hHash, obj.data(), objLen,
        (PUCHAR)LICENSE_HMAC_SECRET, (ULONG)strlen(LICENSE_HMAC_SECRET), 0) != 0) goto fail;
    if (BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0) != 0) goto fail;
    if (BCryptFinishHash(hHash, out.data(), hashLen, 0) != 0) goto fail;

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
fail:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return false;
}

static bool getProductMaterial(SqlDb& db, const std::string& sqlLoginName, std::string& sidHex, std::string& createDate, std::string& err) {
    std::ostringstream q;
    q << "SELECT master.dbo.fn_varbintohexstr([sid]), CONVERT(varchar(19), [create_date], 120) "
      << "FROM master.sys.sql_logins WHERE name = '" << sqlEscape(sqlLoginName) << "'";

    SQLHENV henv = nullptr; // not used, just to keep signature same? no.
    // simpler: query concatenated value
    std::string combined;
    std::ostringstream q2;
    q2 << "SELECT master.dbo.fn_varbintohexstr([sid]) + '|' + CONVERT(varchar(19), [create_date], 120) "
       << "FROM master.sys.sql_logins WHERE name = '" << sqlEscape(sqlLoginName) << "'";
    if (!db.querySingleString(q2.str(), combined, err)) {
        return false;
    }
    size_t p = combined.find('|');
    if (p == std::string::npos) {
        err = "SQL login material malformed";
        return false;
    }
    sidHex = combined.substr(0, p);
    createDate = combined.substr(p + 1);
    return true;
}

static std::string makeProductCode(const std::string& sidHex, const std::string& createDate) {
    std::string plain = sidHex + "|" + createDate;
    std::vector<unsigned char> v(plain.begin(), plain.end());
    return b64url_encode(v);
}

static bool verifyLicenseKey(const std::string& productCode, const std::string& codeKey, std::string& err) {
    size_t dot = codeKey.find('.');
    if (dot == std::string::npos) {
        err = "CodeKey format invalid";
        return false;
    }
    std::string part1 = codeKey.substr(0, dot);
    std::string part2 = codeKey.substr(dot + 1);

    std::vector<unsigned char> payloadBin;
    if (!b64url_decode(part1, payloadBin)) {
        err = "CodeKey payload base64 invalid";
        return false;
    }
    std::string payload(payloadBin.begin(), payloadBin.end());

    std::vector<unsigned char> mac;
    if (!hmac_sha256(payload, mac)) {
        err = "HMAC failed";
        return false;
    }
    std::string expected = b64url_encode(mac);
    if (expected != part2) {
        err = "CodeKey signature mismatch";
        return false;
    }

    json j;
    try {
        j = json::parse(payload);
    } catch (...) {
        err = "CodeKey JSON invalid";
        return false;
    }

    std::string product = j.value("product_code", "");
    std::string expires = j.value("expires_utc", "");
    if (product != productCode) {
        err = "CodeKey product_code mismatch";
        return false;
    }
    if (expires.empty()) {
        err = "CodeKey expires_utc missing";
        return false;
    }

    SYSTEMTIME st{};
    int Y=0,M=0,D=0,h=0,m=0,s=0;
    if (sscanf_s(expires.c_str(), "%d-%d-%dT%d:%d:%dZ", &Y, &M, &D, &h, &m, &s) != 6) {
        err = "CodeKey expires_utc format invalid";
        return false;
    }
    st.wYear = (WORD)Y; st.wMonth = (WORD)M; st.wDay = (WORD)D;
    st.wHour = (WORD)h; st.wMinute = (WORD)m; st.wSecond = (WORD)s;
    FILETIME ftExp{}, ftNow{}, ftLoc{};
    if (!SystemTimeToFileTime(&st, &ftExp)) {
        err = "SystemTimeToFileTime failed";
        return false;
    }
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &ftNow);
    ULARGE_INTEGER a{}, b{};
    a.LowPart = ftExp.dwLowDateTime; a.HighPart = ftExp.dwHighDateTime;
    b.LowPart = ftNow.dwLowDateTime; b.HighPart = ftNow.dwHighDateTime;
    if (a.QuadPart < b.QuadPart) {
        err = "CodeKey expired";
        return false;
    }
    return true;
}

static bool checkLicense(SqlDb& db, const Config& cfg) {
    std::string sidHex, createDate, err;
    if (!getProductMaterial(db, cfg.sql_login_name, sidHex, createDate, err)) {
        g_log.error("License: SQL login '%s' not found in master.sys.sql_logins. Can't build product code. %s",
            cfg.sql_login_name.c_str(), err.c_str());
        return false;
    }
    std::string productCode = makeProductCode(sidHex, createDate);
    std::string codeKey;
    std::ostringstream q;
    q << "SELECT CodeKey FROM dbo.mss_keys WHERE mss_program='" << sqlEscape(cfg.program_name) << "'";
    if (!db.querySingleString(q.str(), codeKey, err) || codeKey.empty()) {
        g_log.error("License: no CodeKey in dbo.mss_keys for mss_program='%s'. ProductCode=%s",
            cfg.program_name.c_str(), productCode.c_str());
        return false;
    }
    if (!verifyLicenseKey(productCode, codeKey, err)) {
        g_log.error("License: invalid CodeKey for mss_program='%s'. %s", cfg.program_name.c_str(), err.c_str());
        return false;
    }
    g_log.info("License: OK.");
    return true;
}

// ------------------------------------------------------------
// HTTP helpers
// ------------------------------------------------------------
static std::wstring toWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring ws(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &ws[0], n);
    return ws;
}

static bool splitUrl(const std::string& url, std::wstring& host, INTERNET_PORT& port, std::wstring& path, bool& https) {
    URL_COMPONENTS uc{};
    wchar_t hostBuf[512]{};
    wchar_t pathBuf[2048]{};
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = hostBuf;
    uc.dwHostNameLength = _countof(hostBuf);
    uc.lpszUrlPath = pathBuf;
    uc.dwUrlPathLength = _countof(pathBuf);
    std::wstring wurl = toWide(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) return false;
    host.assign(uc.lpszHostName, uc.dwHostNameLength);
    path.assign(uc.lpszUrlPath, uc.dwUrlPathLength);
    port = uc.nPort;
    https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    return true;
}

static bool http_post_json(const std::string& url,
                           const std::string& token,
                           const std::string& body,
                           std::string& rawOut,
                           json& jsonOut,
                           int& statusCode,
                           int timeoutMs) {
    rawOut.clear();
    jsonOut = json();
    statusCode = 0;

    std::wstring host, path;
    INTERNET_PORT port = 0;
    bool https = false;
    if (!splitUrl(url, host, port, path, https)) {
        rawOut = "splitUrl failed";
        return false;
    }

    HINTERNET hSession = WinHttpOpen(L"mss_semd_checking/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { rawOut = "WinHttpOpen failed"; return false; }

    WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) {
        rawOut = "WinHttpConnect failed";
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        rawOut = "WinHttpOpenRequest failed";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::string hdr = "Authorization: " + token + "\r\n"
                      "Accept: application/json\r\n"
                      "Content-Type: application/json\r\n";
    std::wstring whdr = toWide(hdr);
    BOOL ok = WinHttpSendRequest(hRequest,
        whdr.c_str(), (DWORD)-1,
        (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
    if (!ok) {
        rawOut = "WinHttpSendRequest failed";
        goto done;
    }

    ok = WinHttpReceiveResponse(hRequest, nullptr);
    if (!ok) {
        rawOut = "WinHttpReceiveResponse failed";
        goto done;
    }

    DWORD dwSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;
        std::string chunk(avail, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, &chunk[0], avail, &read)) break;
        chunk.resize(read);
        rawOut += chunk;
    }

    try {
        if (!rawOut.empty()) jsonOut = json::parse(rawOut);
    } catch (...) {
        // leave jsonOut empty; rawOut still contains payload
    }

    if (statusCode >= 200 && statusCode < 300) {
        ok = TRUE;
    } else {
        ok = FALSE;
    }

done:
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ok == TRUE;
}

// ------------------------------------------------------------
// EventLog request + DB load
// ------------------------------------------------------------

static std::string todayYmd() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char d[16];
    sprintf_s(d, "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
    return d;
}

static std::string makeEventsRequestBody(const Config& cfg, int startRow, int endRow) {
    std::ostringstream ss;
    ss << "{";

    bool needComma = false;

    auto addStrField = [&](const char* name, const std::string& value) {
        if (value.empty()) return;
        if (needComma) ss << ",";
        ss << "\"" << name << "\":\"" << value << "\"";
        needComma = true;
    };

    addStrField("dateBegin", cfg.date_begin);
    addStrField("dateEnd", cfg.date_end);
    addStrField("modifiedDateBegin", cfg.modified_date_begin);
    addStrField("modifiedDateEnd", cfg.modified_date_end);

    if (needComma) ss << ",";
    ss << "\"systemOid\":[\"" << cfg.system_oid << "\"]";
    ss << ",\"startRow\":" << startRow;
    ss << ",\"endRow\":" << endRow;
    ss << "}";

    return ss.str();
}

static std::string newGuidString() {
    GUID guid;
    CoCreateGuid(&guid);
    char buf[64];
    sprintf_s(buf,
        "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return buf;
}

static std::string jsonGetStr(const json& e, const char* key) {
    return e.contains(key) && !e[key].is_null() ? e[key].get<std::string>() : "";
}

static std::string jsonGetIntSql(const json& e, const char* key) {
    if (!e.contains(key) || e[key].is_null()) return "NULL";
    try { return std::to_string(e[key].get<int>()); }
    catch (...) { return "NULL"; }
}

static std::string normalizeSqlDateTime(std::string s) {
    s = trim(s);
    if (s.empty()) return "";

    if (!s.empty() && s.front() == '"') s.erase(0, 1);
    if (!s.empty() && s.back() == '"') s.pop_back();

    size_t tpos = s.find('T');
    if (tpos != std::string::npos) s[tpos] = ' ';

    if (!s.empty() && (s.back() == 'Z' || s.back() == 'z')) {
        s.pop_back();
    }

    size_t plusPos = s.find('+', 10);
    size_t minusPos = s.find('-', 10);
    size_t tzPos = std::string::npos;

    if (plusPos != std::string::npos) tzPos = plusPos;
    if (minusPos != std::string::npos) {
        if (tzPos == std::string::npos || minusPos < tzPos) tzPos = minusPos;
    }
    if (tzPos != std::string::npos) {
        s = s.substr(0, tzPos);
    }

    size_t dotPos = s.find('.');
    if (dotPos != std::string::npos) {
        size_t fracStart = dotPos + 1;
        size_t fracLen = 0;
        while (fracStart + fracLen < s.size() && isdigit((unsigned char)s[fracStart + fracLen])) {
            ++fracLen;
        }

        if (fracLen == 0) {
            s = s.substr(0, dotPos);
        } else if (fracLen > 3) {
            s = s.substr(0, fracStart + 3);
        }
    }

    return trim(s);
}

static void dbInsertStageEvent(SqlDb& db, const std::string& loadGuid, const json& e) {
    std::ostringstream q;
    std::string rawDate = jsonGetStr(e, "date");
    std::string rawModifiedDate = jsonGetStr(e, "modifiedDate");

    std::string dateVal = normalizeSqlDateTime(rawDate);
    std::string modifiedDateVal = normalizeSqlDateTime(rawModifiedDate);
    q << "INSERT INTO dbo.MSS_NETRIKA_EVENTLOG_STAGE ("
      << "LOAD_GUID,idLpu,name,systemName,systemOid,[date],modifiedDate,organization,department,"
      << "idCaseMis,idDocumentMis,emdType,emdTypeId,iemkTypeId,[status],[message],remdRegNumber,"
      << "idSource,dataSource,statusText,goalText,idFedRequest,transferId,goal,idDataSource,sourceTypeName"
      << ") VALUES ("
      << "'" << sqlEscape(loadGuid) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "idLpu")) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "name")) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "systemName")) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "systemOid")) << "',"
      << (dateVal.empty() ? "NULL" : "CONVERT(datetime, '" + sqlEscape(dateVal) + "', 121)") << ","
      << (modifiedDateVal.empty() ? "NULL" : "CONVERT(datetime, '" + sqlEscape(modifiedDateVal) + "', 121)") << ","      << "'" << sqlEscape(jsonGetStr(e, "organization")) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "department")) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "idCaseMis")) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "idDocumentMis")) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "emdType")) << "',"
      << jsonGetIntSql(e, "emdTypeId") << ","
      << jsonGetIntSql(e, "iemkTypeId") << ","
      << jsonGetIntSql(e, "status") << ","
      << "'" << sqlEscape(jsonGetStr(e, "message")) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "remdRegNumber")) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "idSource")) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "dataSource")) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "statusText")) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "goalText")) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "idFedRequest")) << "',"
      << "'" << sqlEscape(jsonGetStr(e, "transferId")) << "',"
      << jsonGetIntSql(e, "goal") << ","
      << jsonGetIntSql(e, "idDataSource") << ","
      << "'" << sqlEscape(jsonGetStr(e, "sourceTypeName")) << "'"
      << ");";

    std::string err;
    if (!db.exec(q.str(), &err)) {
        g_log.error("Stage INSERT failed: %s", err.c_str());
        g_log.error("Stage INSERT raw date='%s' raw modifiedDate='%s' norm date='%s' norm modifiedDate='%s'",
            rawDate.c_str(),
            rawModifiedDate.c_str(),
            dateVal.c_str(),
            modifiedDateVal.c_str());
        g_log.error("Stage INSERT SQL: %s", q.str().c_str());
    }
}

static void dbApplyStage(SqlDb& db, const std::string& loadGuid) {
    std::ostringstream q;
    q << "EXEC dbo.mss_apply_netrika_statuses @LoadGuid = '" << sqlEscape(loadGuid) << "';";
    std::string err;
    if (!db.exec(q.str(), &err)) {
        g_log.error("Apply stage failed: %s", err.c_str());
    }
}

static void dbApplyNon4Statuses(SqlDb& db, const std::string& loadGuid) {
    std::ostringstream q;
    q
        << ";WITH latest_stage AS ("
        << " SELECT s.*, ROW_NUMBER() OVER ("
        << " PARTITION BY s.MATCHED_MSS_SEMD_DOC_ID"
        << " ORDER BY s.modifiedDate DESC, s.[date] DESC, s.STAGE_ID DESC"
        << " ) AS rn"
        << " FROM dbo.MSS_NETRIKA_EVENTLOG_STAGE s"
        << " WHERE s.LOAD_GUID = '" << sqlEscape(loadGuid) << "'"
        << " AND s.MATCHED_MSS_SEMD_DOC_ID IS NOT NULL"
        << " AND s.[status] IS NOT NULL"
        << " AND s.[status] <> 4"
        << " )"
        << " UPDATE d SET"
        << " d.NETRIKA_STATUS = s.[status],"
        << " d.NETRIKA_STATUS_TEXT = LEFT(ISNULL(s.statusText, ''), 255),"
        << " d.NETRIKA_MESSAGE = LEFT(ISNULL(s.[message], ''), 4000),"
        << " d.NETRIKA_MODIFIED_DATE = s.modifiedDate,"
        << " d.NETRIKA_EVENT_DATE = s.[date],"
        << " d.NETRIKA_IDDOCUMENTMIS = LEFT(ISNULL(s.idDocumentMis, ''), 100),"
        << " d.NETRIKA_IDSOURCE = LEFT(ISNULL(s.idSource, ''), 100),"
        << " d.NETRIKA_IDFEDREQUEST = LEFT(ISNULL(s.idFedRequest, ''), 100),"
        << " d.NETRIKA_REMD_REG_NUMBER = LEFT(ISNULL(s.remdRegNumber, ''), 100),"
        << " d.NETRIKA_GOAL_TEXT = LEFT(ISNULL(s.goalText, ''), 255),"
        << " d.NETRIKA_SOURCE_TYPE_NAME = LEFT(ISNULL(s.sourceTypeName, ''), 100),"
        << " d.NETRIKA_EMD_TYPE_ID = s.emdTypeId,"
        << " d.NETRIKA_IEMK_TYPE_ID = s.iemkTypeId,"
        << " d.NETRIKA_ORGANIZATION = LEFT(ISNULL(s.organization, ''), 255),"
        << " d.NETRIKA_DEPARTMENT = LEFT(ISNULL(s.department, ''), 255),"
        << " d.NETRIKA_CHECK_DATE = GETDATE(),"
        << " d.NETRIKA_MATCH_METHOD = ISNULL(s.MATCH_METHOD, 'MOTCONSU_ID')"
        << " FROM dbo.MSS_SEMD_DOC d"
        << " INNER JOIN latest_stage s"
        << " ON d.MSS_SEMD_DOC_ID = s.MATCHED_MSS_SEMD_DOC_ID"
        << " AND s.rn = 1;";

    std::string err;
    if (!db.exec(q.str(), &err)) {
        g_log.error("Apply non-4 statuses failed: %s", err.c_str());
    } else {
        g_log.info("Applied non-4 statuses for LOAD_GUID=%s", loadGuid.c_str());
    }
}

static void pollOnce(SqlDb& db, const Config& cfg) {
    std::string today = todayYmd();
    std::string dateBegin = cfg.date_begin.empty() ? today : cfg.date_begin;
    std::string dateEnd = cfg.date_end.empty() ? dateBegin : cfg.date_end;
    std::string modifiedDateBegin = cfg.modified_date_begin.empty() ? dateBegin : cfg.modified_date_begin;
    std::string modifiedDateEnd = cfg.modified_date_end.empty() ? dateEnd : cfg.modified_date_end;

    g_log.info(
        "Poll tick: requesting EventLog/GetEvents. dateBegin=%s dateEnd=%s modifiedDateBegin=%s modifiedDateEnd=%s",
        dateBegin.c_str(),
        dateEnd.c_str(),
        modifiedDateBegin.c_str(),
        modifiedDateEnd.c_str()
    );

    const int pageSize = 100;   // EventLog page limit
    int startRow = 0;
    size_t totalRows = 0;
    size_t totalInserted = 0;
    std::string loadGuid = newGuidString();

    for (;;) {
        int endRow = startRow + pageSize;
        std::string body = makeEventsRequestBody(cfg, startRow, endRow);

        std::string raw;
        json parsed;
        int httpStatus = 0;

        bool ok = http_post_json(
            cfg.base_url + cfg.events_endpoint,
            cfg.token,
            body,
            raw,
            parsed,
            httpStatus,
            cfg.http_timeout_ms
        );

        if (!ok) {
            g_log.warn(
                "EventLog request failed on page startRow=%d endRow=%d: HTTP=%d resp=%s",
                startRow, endRow, httpStatus, raw.c_str()
            );
            break;
        }

        if (!parsed.is_array()) {
            g_log.error(
                "EventLog response is not JSON array on page startRow=%d endRow=%d. Raw=%s",
                startRow, endRow, raw.c_str()
            );
            break;
        }

        size_t pageCount = parsed.size();

        g_log.info(
            "EventLog page received: startRow=%d endRow=%d rows=%zu LOAD_GUID=%s",
            startRow, endRow, pageCount, loadGuid.c_str()
        );

        if (pageCount == 0) {
            break;
        }

        size_t pageInserted = 0;

        for (const auto& e : parsed) {
            dbInsertStageEvent(db, loadGuid, e);
            ++totalRows;
            ++pageInserted;
            ++totalInserted;

            if (totalRows <= 5) {
                g_log.info(
                    "Stage sample #%zu: idDocumentMis=%s status=%s statusText=%s",
                    totalRows,
                    jsonGetStr(e, "idDocumentMis").c_str(),
                    jsonGetIntSql(e, "status").c_str(),
                    jsonGetStr(e, "statusText").c_str()
                );
            }
        }

        g_log.info(
            "EventLog page processed: startRow=%d endRow=%d pageRows=%zu totalRows=%zu",
            startRow, endRow, pageInserted, totalRows
        );

        // Если пришло меньше pageSize — это последняя страница
        if (pageCount < (size_t)pageSize) {
            break;
        }

        startRow += pageSize;
    }

    if (totalRows == 0) {
        g_log.info("EventLog returned 0 rows for requested period.");
        return;
    }

    g_log.info("Applying EventLog statuses for LOAD_GUID=%s totalRows=%zu", loadGuid.c_str(), totalRows);
    dbApplyStage(db, loadGuid);
    dbApplyNon4Statuses(db, loadGuid);
    g_log.info("Applied EventLog statuses for LOAD_GUID=%s totalRows=%zu", loadGuid.c_str(), totalRows);
}

// ------------------------------------------------------------
// Service runner
// ------------------------------------------------------------
static void updateServiceState(DWORD state, DWORD win32ExitCode = NO_ERROR, DWORD waitHint = 0) {
    if (!g_serviceHandle) return;
    g_serviceStatus.dwCurrentState = state;
    g_serviceStatus.dwWin32ExitCode = win32ExitCode;
    g_serviceStatus.dwWaitHint = waitHint;
    g_serviceStatus.dwControlsAccepted = (state == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_serviceHandle, &g_serviceStatus);
}

static DWORD WINAPI serviceCtrlHandlerEx(DWORD control, DWORD, LPVOID, LPVOID) {
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_log.info("Service stop requested.");
        updateServiceState(SERVICE_STOP_PENDING, NO_ERROR, 10000);
        if (g_stopEvent) SetEvent(g_stopEvent);
        return NO_ERROR;
    default:
        return NO_ERROR;
    }
}

static int runWorker(const std::string& iniPath, const std::string& logDir) {
    Config cfg;
    std::string err;
    if (!loadConfig(iniPath, cfg, err)) {
        g_log.error("Config load failed: %s", err.c_str());
        return 2;
    }

    if (!cfg.log_dir.empty()) {
        g_log.init(cfg.log_dir);
    }

    g_log.info("Service starting. ini=%s", iniPath.c_str());

    SqlDb db;
    if (!db.open(cfg.odbc_conn, err)) {
        g_log.error("DB connect failed: %s", err.c_str());
        return 3;
    }
    g_log.info("DB connected.");

    if (!checkLicense(db, cfg)) {
        return 4;
    }

    pollOnce(db, cfg);
    g_log.info("Single-run finished.");
    return 0;
    // сверху - через windows taskschedule единичный runner
    // снизу - для background сервиса с таймаутом
    /*
    while (WaitForSingleObject(g_stopEvent, 0) != WAIT_OBJECT_0) {
        pollOnce(db, cfg);

        DWORD step = 1000;
        DWORD total = (DWORD)(cfg.poll_interval_seconds * 1000);
        for (DWORD spent = 0; spent < total; spent += step) {
            if (WaitForSingleObject(g_stopEvent, step) == WAIT_OBJECT_0) break;
        }
    }*/

    g_log.info("Worker exiting.");
    return 0;
}

static void WINAPI serviceMain(DWORD, LPWSTR*) {
    g_serviceHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME_W, serviceCtrlHandlerEx, nullptr);
    if (!g_serviceHandle) return;

    ZeroMemory(&g_serviceStatus, sizeof(g_serviceStatus));
    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwServiceSpecificExitCode = 0;
    updateServiceState(SERVICE_START_PENDING, NO_ERROR, 10000);

    g_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) {
        updateServiceState(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    updateServiceState(SERVICE_RUNNING, NO_ERROR, 0);
    runWorker(g_iniPath, g_logDir);
    updateServiceState(SERVICE_STOPPED, NO_ERROR, 0);
}

// ------------------------------------------------------------
// Main
// ------------------------------------------------------------
int main(int argc, char* argv[]) {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    if (argc >= 4 && std::string(argv[1]) == "--console") {
        g_consoleMode = true;
        g_iniPath = argv[2];
        g_logDir = argv[3];
        g_log.init(g_logDir);
        g_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        int rc = runWorker(g_iniPath, g_logDir);
        CloseHandle(g_stopEvent);
        CoUninitialize();
        return rc;
    }

    if (argc >= 3) {
        g_iniPath = argv[1];
        g_logDir = argv[2];
    } else {
        g_iniPath = "C:\\mss\\mss_semd_checking.ini";
        g_logDir = "C:\\mss\\logs";
    }
    g_log.init(g_logDir);

    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(SERVICE_NAME_W), serviceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(table)) {
        DWORD e = GetLastError();
        g_consoleMode = true;
        g_log.warn("StartServiceCtrlDispatcher failed (%lu). Running as console fallback.", e);
        g_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        int rc = runWorker(g_iniPath, g_logDir);
        CloseHandle(g_stopEvent);
        CoUninitialize();
        return rc;
    }

    CoUninitialize();
    return 0;
}
