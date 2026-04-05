// main.cpp
// Build as service:  cl /std:c++17 main.cpp /DUNICODE /D_UNICODE ...
// Build keygen:      cl /std:c++17 main.cpp /DKEYGEN /DUNICODE /D_UNICODE ...

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winsvc.h>
#include <winhttp.h>
#include <sqlext.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "odbc32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

// =====================
// nlohmann/json single-header
// =====================
// 1) Скачай json.hpp отсюда и положи рядом с main.cpp:
//    https://github.com/nlohmann/json/releases
// 2) Либо через vcpkg (см. инструкцию ниже).
#include "json.hpp"
using json = nlohmann::json;

// ======================================================
// CONFIG (INI)
// ======================================================
struct Config {
    // database
    std::string odbc_conn;     // e.g. "Driver={ODBC Driver 17 for SQL Server};Server=.;Database=Netrika;Uid=...;Pwd=...;TrustServerCertificate=yes;"

    // netrika/eventlog
    std::string base_url;      // e.g. "https://b2b.n3health.ru/n3h-eventlog-api"
    std::string token;         // e.g. "N3 <guid>"
    std::string semd_events_endpoint = "/EventLogSemd/GetEvents";

    // params
    int poll_interval_seconds = 300;
    int lookback_days = 60;
    int top_n = 200;
    int http_timeout_ms = 30000;

    // license/program naming
    std::string program_name = "mss_semd_checking";
    std::string sql_login_name = "mss_semd_checking";
};

static std::string trim(std::string s) {
    auto isws = [](unsigned char c){ return std::isspace(c); };
    while (!s.empty() && isws((unsigned char)s.front())) s.erase(s.begin());
    while (!s.empty() && isws((unsigned char)s.back())) s.pop_back();
    return s;
}

static std::map<std::string, std::map<std::string,std::string>> parse_ini(const std::string& path) {
    std::ifstream f(path);
    std::map<std::string, std::map<std::string,std::string>> out;
    std::string line, section;

    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty()) continue;
        if (line[0] == ';' || line[0] == '#') continue;
        if (line.front() == '[' && line.back() == ']') {
            section = trim(line.substr(1, line.size()-2));
            continue;
        }
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = trim(line.substr(0, eq));
        std::string v = trim(line.substr(eq+1));
        out[section][k] = v;
    }
    return out;
}

static bool load_config(const std::string& ini_path, Config& cfg, std::string& err) {
    auto ini = parse_ini(ini_path);

    auto get = [&](const std::string& sec, const std::string& key, const std::string& def="") -> std::string {
        auto it = ini.find(sec);
        if (it == ini.end()) return def;
        auto it2 = it->second.find(key);
        if (it2 == it->second.end()) return def;
        return it2->second;
    };

    cfg.odbc_conn = get("database","odbc_conn","");
    if (cfg.odbc_conn.empty()) { err = "ini: [database].odbc_conn is empty"; return false; }

    cfg.base_url = get("netrika","base_url","");
    cfg.token = get("netrika","token","");
    cfg.semd_events_endpoint = get("netrika","semd_events_endpoint", cfg.semd_events_endpoint);
    if (cfg.base_url.empty()) { err = "ini: [netrika].base_url is empty"; return false; }
    if (cfg.token.empty()) { err = "ini: [netrika].token is empty"; return false; }

    cfg.program_name = get("params","program_name", cfg.program_name);
    cfg.sql_login_name = get("params","sql_login_name", cfg.sql_login_name);

    cfg.poll_interval_seconds = std::max(30, std::stoi(get("params","poll_interval_seconds", std::to_string(cfg.poll_interval_seconds))));
    cfg.lookback_days = std::max(1, std::stoi(get("params","lookback_days", std::to_string(cfg.lookback_days))));
    cfg.top_n = std::max(1, std::stoi(get("params","top_n", std::to_string(cfg.top_n))));
    cfg.http_timeout_ms = std::max(1000, std::stoi(get("params","http_timeout_ms", std::to_string(cfg.http_timeout_ms))));
    return true;
}

// ======================================================
// LOGGING
// ======================================================
class Logger {
    std::mutex mu_;
    std::string dir_;
    std::string current_date_;
    std::ofstream f_;

    static std::string now_local_iso() {
        SYSTEMTIME st; GetLocalTime(&st);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u.%03u",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        return buf;
    }
    static std::string today_yyyymmdd() {
        SYSTEMTIME st; GetLocalTime(&st);
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%04u%02u%02u", st.wYear, st.wMonth, st.wDay);
        return buf;
    }
    void rotate_if_needed() {
        std::string d = today_yyyymmdd();
        if (d == current_date_ && f_.is_open()) return;

        current_date_ = d;
        if (f_.is_open()) f_.close();

        CreateDirectoryA(dir_.c_str(), nullptr);

        std::string path = dir_ + "\\mss_semd_checking_" + current_date_ + ".log";
        f_.open(path, std::ios::app);
    }

public:
    void init(const std::string& dir) {
        dir_ = dir;
        rotate_if_needed();
    }

    void log(const char* level, const char* fmt, ...) {
        std::lock_guard<std::mutex> lk(mu_);
        rotate_if_needed();

        char msg[4096];
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);

        std::string line = now_local_iso();
        line += " [";
        line += level;
        line += "] ";
        line += msg;
        line += "\r\n";

        // file
        if (f_.is_open()) {
            f_ << line;
            f_.flush();
        }

        // Windows Event Log (опционально) — чтобы было видно в Event Viewer
        // Для простоты пишем только ERROR туда (см. error()).
    }

    void info(const char* fmt, ...) {
        va_list ap; va_start(ap, fmt);
        char msg[4096]; std::vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);
        log("INFO", "%s", msg);
    }
    void warn(const char* fmt, ...) {
        va_list ap; va_start(ap, fmt);
        char msg[4096]; std::vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);
        log("WARN", "%s", msg);
    }
    void error(const char* fmt, ...) {
        va_list ap; va_start(ap, fmt);
        char msg[4096]; std::vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);
        log("ERROR", "%s", msg);

        // EventLog
        HANDLE h = RegisterEventSourceA(nullptr, "mss_semd_checking");
        if (h) {
            LPCSTR strs[1] = { msg };
            ReportEventA(h, EVENTLOG_ERROR_TYPE, 0, 0x1000, nullptr, 1, 0, strs, nullptr);
            DeregisterEventSource(h);
        }
    }
};

static Logger g_log;

// ======================================================
// Helpers: base64 (URL-safe) + HMAC-SHA256 (license)
// ======================================================
static const char* LICENSE_HMAC_SECRET = "CHANGE_ME__KEEP_PRIVATE__MSS_SEMD_CHECKING__HMAC_SECRET";
// ^^^ Поменяй на любой длинный секрет (и держи в исходниках закрыто). Он зашивается в exe.

static std::string b64url_encode(const std::vector<uint8_t>& data) {
    DWORD outLen = 0;
    CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outLen);
    std::string b64(outLen, '\0');
    CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64.data(), &outLen);
    if (!b64.empty() && b64.back() == '\0') b64.pop_back();

    // to url-safe
    for (auto& c : b64) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    while (!b64.empty() && b64.back() == '=') b64.pop_back();
    return b64;
}

static bool b64url_decode(const std::string& in, std::vector<uint8_t>& out) {
    std::string b64 = in;
    for (auto& c : b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (b64.size() % 4 != 0) b64.push_back('=');

    DWORD binLen = 0;
    if (!CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &binLen, nullptr, nullptr)) return false;
    out.resize(binLen);
    if (!CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &binLen, nullptr, nullptr)) return false;
    out.resize(binLen);
    return true;
}

static bool hmac_sha256(const std::string& key, const std::string& msg, std::vector<uint8_t>& out) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st != 0) return false;

    DWORD objLen=0, cbData=0;
    st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cbData, 0);
    if (st != 0) { BCryptCloseAlgorithmProvider(hAlg,0); return false; }

    std::vector<uint8_t> obj(objLen);
    out.resize(32);

    st = BCryptCreateHash(hAlg, &hHash, obj.data(), (ULONG)obj.size(),
        (PUCHAR)key.data(), (ULONG)key.size(), 0);
    if (st != 0) { BCryptCloseAlgorithmProvider(hAlg,0); return false; }

    st = BCryptHashData(hHash, (PUCHAR)msg.data(), (ULONG)msg.size(), 0);
    if (st != 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0); return false; }

    st = BCryptFinishHash(hHash, out.data(), (ULONG)out.size(), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg,0);

    return st == 0;
}

// ======================================================
// DB: ODBC wrapper
// ======================================================
class SqlDb {
    SQLHENV hEnv_ = nullptr;
    SQLHDBC hDbc_ = nullptr;

public:
    bool connect(const std::string& connStr, std::string& err) {
        SQLRETURN rc;

        rc = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &hEnv_);
        if (!SQL_SUCCEEDED(rc)) { err = "SQLAllocHandle ENV failed"; return false; }

        rc = SQLSetEnvAttr(hEnv_, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);
        if (!SQL_SUCCEEDED(rc)) { err = "SQLSetEnvAttr failed"; return false; }

        rc = SQLAllocHandle(SQL_HANDLE_DBC, hEnv_, &hDbc_);
        if (!SQL_SUCCEEDED(rc)) { err = "SQLAllocHandle DBC failed"; return false; }

        SQLCHAR outstr[1024];
        SQLSMALLINT outstrlen = 0;
        rc = SQLDriverConnectA(hDbc_, nullptr,
            (SQLCHAR*)connStr.c_str(), SQL_NTS,
            outstr, sizeof(outstr), &outstrlen,
            SQL_DRIVER_NOPROMPT);

        if (!SQL_SUCCEEDED(rc)) {
            err = "SQLDriverConnect failed";
            return false;
        }
        return true;
    }

    void disconnect() {
        if (hDbc_) { SQLDisconnect(hDbc_); SQLFreeHandle(SQL_HANDLE_DBC, hDbc_); hDbc_ = nullptr; }
        if (hEnv_) { SQLFreeHandle(SQL_HANDLE_ENV, hEnv_); hEnv_ = nullptr; }
    }

    bool exec(const std::string& sql) {
        SQLHSTMT hStmt = nullptr;
        if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_STMT, hDbc_, &hStmt))) return false;

        auto rc = SQLExecDirectA(hStmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
        SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
        return SQL_SUCCEEDED(rc);
    }

    bool scalar_string(const std::string& sql, std::string& out) {
        out.clear();
        SQLHSTMT hStmt = nullptr;
        if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_STMT, hDbc_, &hStmt))) return false;
        auto rc = SQLExecDirectA(hStmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
        if (!SQL_SUCCEEDED(rc)) { SQLFreeHandle(SQL_HANDLE_STMT, hStmt); return false; }

        if (SQLFetch(hStmt) == SQL_SUCCESS) {
            char buf[2048]; memset(buf, 0, sizeof(buf));
            SQLLEN ind = 0;
            SQLGetData(hStmt, 1, SQL_C_CHAR, buf, sizeof(buf), &ind);
            if (ind != SQL_NULL_DATA) out = buf;
        }
        SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
        return true;
    }

    struct SemdDocRow {
        int mss_semd_doc_id = 0;
        int motconsu_id = 0; // idDocumentMis
        int semd_id = 0;
        int status = 0;
        std::string date_entry;
    };

    bool query_semd_docs(const std::string& sql, std::vector<SemdDocRow>& out) {
        out.clear();
        SQLHSTMT hStmt = nullptr;
        if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_STMT, hDbc_, &hStmt))) return false;

        auto rc = SQLExecDirectA(hStmt, (SQLCHAR*)sql.c_str(), SQL_NTS);
        if (!SQL_SUCCEEDED(rc)) { SQLFreeHandle(SQL_HANDLE_STMT, hStmt); return false; }

        while (SQLFetch(hStmt) == SQL_SUCCESS) {
            SemdDocRow r{};
            SQLLEN ind = 0;

            SQLGetData(hStmt, 1, SQL_C_LONG, &r.mss_semd_doc_id, 0, &ind);
            SQLGetData(hStmt, 2, SQL_C_LONG, &r.motconsu_id, 0, &ind);
            SQLGetData(hStmt, 3, SQL_C_LONG, &r.semd_id, 0, &ind);
            SQLGetData(hStmt, 4, SQL_C_LONG, &r.status, 0, &ind);

            char buf[64]; memset(buf, 0, sizeof(buf));
            SQLGetData(hStmt, 5, SQL_C_CHAR, buf, sizeof(buf), &ind);
            if (ind != SQL_NULL_DATA) r.date_entry = buf;

            out.push_back(std::move(r));
        }

        SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
        return true;
    }
};

// ======================================================
// License logic
// ======================================================
static std::string sql_get_product_code(SqlDb& db, const std::string& loginName) {
    // sid + create_date -> single string
    // create_date as ISO 120
    std::ostringstream q;
    q << "select "
      << " convert(varchar(256), sid, 1) + '|' + convert(varchar(19), create_date, 120) "
      << " from master.sys.sql_logins where name = '" << loginName << "';";

    std::string s;
    if (!db.scalar_string(q.str(), s) || s.empty()) return "";
    // "Код продукта" — base64url( raw bytes of utf8 string )
    std::vector<uint8_t> bytes(s.begin(), s.end());
    return b64url_encode(bytes);
}

static bool sql_get_codekey(SqlDb& db, const std::string& programName, std::string& codekey) {
    std::ostringstream q;
    q << "select CodeKey from dbo.mss_keys where mss_program='" << programName << "';";
    return db.scalar_string(q.str(), codekey) && !codekey.empty();
}

// Key format (string): base64url( json_payload ) + "." + base64url( hmac(payload) )
// payload json: { "product_code": "...", "expires_utc": "2026-12-31T23:59:59Z" }
static bool validate_codekey(const std::string& product_code, const std::string& codekey, std::string& why) {
    why.clear();
    auto dot = codekey.find('.');
    if (dot == std::string::npos) { why = "CodeKey invalid format (no dot)"; return false; }

    std::string payload_b64 = codekey.substr(0, dot);
    std::string sig_b64 = codekey.substr(dot + 1);

    std::vector<uint8_t> payload_bytes, sig_bytes;
    if (!b64url_decode(payload_b64, payload_bytes)) { why = "CodeKey payload base64 decode failed"; return false; }
    if (!b64url_decode(sig_b64, sig_bytes)) { why = "CodeKey signature base64 decode failed"; return false; }

    std::string payload(payload_bytes.begin(), payload_bytes.end());

    std::vector<uint8_t> sig_calc;
    if (!hmac_sha256(LICENSE_HMAC_SECRET, payload, sig_calc)) { why = "HMAC calculation failed"; return false; }

    if (sig_bytes != sig_calc) { why = "CodeKey signature mismatch"; return false; }

    json j;
    try { j = json::parse(payload); }
    catch (...) { why = "CodeKey payload json parse failed"; return false; }

    std::string pc = j.value("product_code", "");
    std::string exp = j.value("expires_utc", "");
    if (pc.empty() || exp.empty()) { why = "CodeKey payload missing fields"; return false; }
    if (pc != product_code) { why = "CodeKey product_code mismatch"; return false; }

    // parse expires_utc "YYYY-MM-DDTHH:MM:SSZ"
    SYSTEMTIME stNow; GetSystemTime(&stNow);
    FILETIME ftNow; SystemTimeToFileTime(&stNow, &ftNow);
    ULARGE_INTEGER uiNow; uiNow.LowPart = ftNow.dwLowDateTime; uiNow.HighPart = ftNow.dwHighDateTime;

    SYSTEMTIME stExp{};
    if (exp.size() < 20 || exp.back() != 'Z') { why = "expires_utc invalid format"; return false; }
    // YYYY-MM-DDTHH:MM:SSZ
    stExp.wYear  = (WORD)std::stoi(exp.substr(0,4));
    stExp.wMonth = (WORD)std::stoi(exp.substr(5,2));
    stExp.wDay   = (WORD)std::stoi(exp.substr(8,2));
    stExp.wHour  = (WORD)std::stoi(exp.substr(11,2));
    stExp.wMinute= (WORD)std::stoi(exp.substr(14,2));
    stExp.wSecond= (WORD)std::stoi(exp.substr(17,2));

    FILETIME ftExp;
    if (!SystemTimeToFileTime(&stExp, &ftExp)) { why = "expires_utc conversion failed"; return false; }
    ULARGE_INTEGER uiExp; uiExp.LowPart = ftExp.dwLowDateTime; uiExp.HighPart = ftExp.dwHighDateTime;

    if (uiNow.QuadPart > uiExp.QuadPart) { why = "CodeKey expired"; return false; }
    return true;
}

static std::string make_codekey(const std::string& product_code, const std::string& expires_utc) {
    json j;
    j["product_code"] = product_code;
    j["expires_utc"] = expires_utc;

    std::string payload = j.dump();
    std::vector<uint8_t> sig;
    if (!hmac_sha256(LICENSE_HMAC_SECRET, payload, sig)) return "";

    std::vector<uint8_t> payload_bytes(payload.begin(), payload.end());
    std::string p64 = b64url_encode(payload_bytes);
    std::string s64 = b64url_encode(sig);
    return p64 + "." + s64;
}

// ======================================================
// HTTP client: WinHTTP JSON POST
// ======================================================
static bool parse_url(const std::string& url, bool& https, std::wstring& host, INTERNET_PORT& port, std::wstring& path) {
    https = false; port = 80;

    // crude parse
    std::string u = url;
    if (u.rfind("https://", 0) == 0) { https = true; u = u.substr(8); port = 443; }
    else if (u.rfind("http://", 0) == 0) { https = false; u = u.substr(7); port = 80; }
    else return false;

    auto slash = u.find('/');
    std::string hostport = (slash == std::string::npos) ? u : u.substr(0, slash);
    std::string p = (slash == std::string::npos) ? "/" : u.substr(slash);

    std::string h = hostport;
    auto colon = hostport.find(':');
    if (colon != std::string::npos) {
        h = hostport.substr(0, colon);
        port = (INTERNET_PORT)std::stoi(hostport.substr(colon+1));
    }

    host.assign(h.begin(), h.end());
    path.assign(p.begin(), p.end());
    return true;
}

static bool http_post_json(
    const std::string& base_url,
    const std::string& endpoint,
    const std::string& auth_header_value,
    const std::string& body,
    int timeout_ms,
    int& status_code,
    std::string& response_body)
{
    status_code = 0;
    response_body.clear();

    bool https;
    std::wstring host, basePath;
    INTERNET_PORT port;
    std::wstring baseW;
    if (!parse_url(base_url, https, host, port, basePath)) return false;

    // join basePath + endpoint carefully
    std::wstring ep(endpoint.begin(), endpoint.end());
    std::wstring fullPath = basePath;
    if (!fullPath.empty() && fullPath.back() == L'/' && !ep.empty() && ep.front() == L'/') fullPath.pop_back();
    fullPath += ep;

    HINTERNET hSession = WinHttpOpen(L"mss_semd_checking/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    WinHttpSetTimeouts(hSession, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    DWORD flags = WINHTTP_FLAG_REFRESH;
    if (https) flags |= WINHTTP_FLAG_SECURE;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", fullPath.c_str(),
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    std::wstring headers =
        L"Content-Type: application/json\r\n"
        L"Accept: application/json\r\n";

    // Authorization header
    std::wstring authW(L"Authorization: ");
    authW.append(std::wstring(auth_header_value.begin(), auth_header_value.end()));
    authW.append(L"\r\n");
    headers += authW;

    BOOL bResults = WinHttpSendRequest(
        hRequest,
        headers.c_str(),
        (DWORD)-1L,
        (LPVOID)body.data(),
        (DWORD)body.size(),
        (DWORD)body.size(),
        0);

    if (!bResults) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return false;
    }

    bResults = WinHttpReceiveResponse(hRequest, nullptr);
    if (!bResults) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
    status_code = (int)dwStatusCode;

    // read response
    std::string resp;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;
        std::vector<char> buf(avail + 1);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, buf.data(), avail, &read)) break;
        resp.append(buf.data(), buf.data() + read);
    }
    response_body = std::move(resp);

    WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
    return true;
}

// ======================================================
// Business: poll SEMD
// ======================================================
static std::string sql_escape_single_quotes(std::string s) {
    size_t pos = 0;
    while ((pos = s.find('\'', pos)) != std::string::npos) {
        s.insert(pos, 1, '\'');
        pos += 2;
    }
    return s;
}

static std::vector<SqlDb::SemdDocRow> db_get_docs_to_check(SqlDb& db, const Config& cfg) {
    std::vector<SqlDb::SemdDocRow> rows;
    std::ostringstream q;
    q << "select top (" << cfg.top_n << ") "
      << " MSS_SEMD_DOC_ID, MOTCONSU_ID, isnull(SEMD_ID,0) as SEMD_ID, isnull(Status,-1) as Status, "
      << " convert(varchar(19), DATE_ENTRY, 120) as DATE_ENTRY "
      << " from dbo.MSS_SEMD_DOC with (nolock) "
      << " where MOTCONSU_ID is not null "
      << " and DATE_ENTRY >= dateadd(day, -" << cfg.lookback_days << ", getdate()) "
      << " and isnull(Status,-1) in (2,3) "
      << " order by DATE_ENTRY desc;";

    if (!db.query_semd_docs(q.str(), rows)) {
        g_log.warn("db_get_docs_to_check: query failed");
        rows.clear();
    }
    return rows;
}

static void db_update_doc_status(SqlDb& db, int mss_semd_doc_id, int status, const std::string& statusText) {
    std::ostringstream q;
    q << "update dbo.MSS_SEMD_DOC set "
      << " Status=" << status
      << ", Status_readable='" << sql_escape_single_quotes(statusText) << "'"
      << " where MSS_SEMD_DOC_ID=" << mss_semd_doc_id << ";";

    if (!db.exec(q.str())) {
        g_log.warn("Failed to update MSS_SEMD_DOC_ID=%d status=%d", mss_semd_doc_id, status);
    }
}

static bool get_semd_events(const Config& cfg, int idDocumentMis, std::string& rawResp, json& parsed, int& httpStatus) {
    json filter;
    filter["idDocumentMis"] = std::to_string(idDocumentMis); // swagger показывает string, поэтому safe как string
    filter["startRow"] = 0;
    filter["endRow"] = 100;

    std::string body = filter.dump();
    std::string resp;
    int sc = 0;
    bool ok = http_post_json(cfg.base_url, cfg.semd_events_endpoint, cfg.token, body, cfg.http_timeout_ms, sc, resp);
    httpStatus = sc;
    rawResp = resp;

    if (!ok) return false;
    if (sc < 200 || sc >= 300) return false;

    try { parsed = json::parse(resp); }
    catch (...) { return false; }

    return true;
}

static bool pick_latest_event(const json& arr, int& status, std::string& statusText, std::string& modifiedDate) {
    if (!arr.is_array() || arr.empty()) return false;

    // выбираем по max(modifiedDate) как строка ISO (лексикографически ок для ISO 8601)
    const json* best = nullptr;
    std::string bestDate;

    for (const auto& e : arr) {
        std::string md = e.value("modifiedDate", "");
        if (md.empty()) md = e.value("date", "");
        if (!best || md > bestDate) {
            best = &e;
            bestDate = md;
        }
    }

    if (!best) return false;
    status = best->value("status", -1);
    statusText = best->value("statusText", "");
    if (statusText.empty()) statusText = best->value("message", "");
    modifiedDate = bestDate;
    return true;
}

// ======================================================
// Service core
// ======================================================
static SERVICE_STATUS_HANDLE g_svcStatusHandle = nullptr;
static SERVICE_STATUS g_svcStatus{};
static HANDLE g_stopEvent = nullptr;

static void set_service_status(DWORD state, DWORD win32ExitCode = NO_ERROR) {
    g_svcStatus.dwCurrentState = state;
    g_svcStatus.dwWin32ExitCode = win32ExitCode;
    SetServiceStatus(g_svcStatusHandle, &g_svcStatus);
}

class SemdService {
    Config cfg_;
    std::string ini_path_;
    std::string log_dir_;
    std::atomic<bool> running_{false};

public:
    SemdService(const std::string& ini_path, const std::string& log_dir)
        : ini_path_(ini_path), log_dir_(log_dir) {}

    void run() {
        running_ = true;

        g_log.init(log_dir_);
        g_log.info("Service starting. ini=%s", ini_path_.c_str());

        std::string err;
        if (!load_config(ini_path_, cfg_, err)) {
            g_log.error("Config load failed: %s", err.c_str());
            return;
        }

        // Connect DB
        SqlDb db;
        if (!db.connect(cfg_.odbc_conn, err)) {
            g_log.error("DB connect failed: %s", err.c_str());
            return;
        }
        g_log.info("DB connected.");

        // License check at startup
        if (!check_license_or_stop(db)) {
            db.disconnect();
            return;
        }

        auto next_daily_license_check = std::chrono::system_clock::now() + std::chrono::hours(24);

        while (WaitForSingleObject(g_stopEvent, 0) != WAIT_OBJECT_0) {
            // daily license check
            if (std::chrono::system_clock::now() >= next_daily_license_check) {
                if (!check_license_or_stop(db)) break;
                next_daily_license_check = std::chrono::system_clock::now() + std::chrono::hours(24);
            }

            poll_once(db);

            // sleep
            DWORD waitMs = (DWORD)(cfg_.poll_interval_seconds * 1000);
            DWORD w = WaitForSingleObject(g_stopEvent, waitMs);
            if (w == WAIT_OBJECT_0) break;
        }

        db.disconnect();
        g_log.info("Service stopped.");
        running_ = false;
    }

private:
    bool check_license_or_stop(SqlDb& db) {
        // product code from SQL login
        std::string product_code = sql_get_product_code(db, cfg_.sql_login_name);
        if (product_code.empty()) {
            g_log.error("License: SQL login '%s' not found in master.sys.sql_logins. Can't build product code.",
                cfg_.sql_login_name.c_str());
            return false;
        }

        std::string codekey;
        if (!sql_get_codekey(db, cfg_.program_name, codekey)) {
            g_log.error("License: no CodeKey in dbo.mss_keys for mss_program='%s'. ProductCode=%s",
                cfg_.program_name.c_str(), product_code.c_str());
            // По ТЗ: при отсутствии ключа — выдавать "Код продукта" в лог и останавливаться.
            return false;
        }

        std::string why;
        if (!validate_codekey(product_code, codekey, why)) {
            g_log.error("License: invalid/expired CodeKey for '%s'. Reason=%s ProductCode=%s",
                cfg_.program_name.c_str(), why.c_str(), product_code.c_str());
            return false;
        }

        g_log.info("License: OK.");
        return true;
    }

    void poll_once(SqlDb& db) {
        g_log.info("Poll tick: reading docs...");
        auto rows = db_get_docs_to_check(db, cfg_);
        g_log.info("Poll tick: got %zu docs", rows.size());

        for (const auto& r : rows) {
            if (WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0) break;

            g_log.info("Check MSS_SEMD_DOC_ID=%d MOTCONSU_ID=%d status=%d date_entry=%s",
                r.mss_semd_doc_id, r.motconsu_id, r.status, r.date_entry.c_str());

            std::string raw; json parsed; int httpStatus = 0;
            bool ok = get_semd_events(cfg_, r.motconsu_id, raw, parsed, httpStatus);
            if (!ok) {
                g_log.warn("Eventlog request failed: HTTP=%d MSS_SEMD_DOC_ID=%d MOTCONSU_ID=%d resp=%s",
                    httpStatus, r.mss_semd_doc_id, r.motconsu_id, raw.c_str());
                continue;
            }

            int newStatus = -1; std::string statusText; std::string modDate;
            if (!pick_latest_event(parsed, newStatus, statusText, modDate)) {
                g_log.warn("No events returned for MOTCONSU_ID=%d (HTTP=%d).", r.motconsu_id, httpStatus);
                continue;
            }

            g_log.info("Latest event: status=%d statusText=%s modifiedDate=%s",
                newStatus, statusText.c_str(), modDate.c_str());

            if (newStatus != r.status || statusText != "") {
                db_update_doc_status(db, r.mss_semd_doc_id, newStatus, statusText);
                g_log.info("DB updated: MSS_SEMD_DOC_ID=%d -> Status=%d Status_readable=%s",
                    r.mss_semd_doc_id, newStatus, statusText.c_str());
            }

            if (newStatus == 3) {
                g_log.warn("Status=3 detected (stuck). MSS_SEMD_DOC_ID=%d MOTCONSU_ID=%d", r.mss_semd_doc_id, r.motconsu_id);
                // Здесь можно добавить постановку в очередь на перевыгрузку, если у вас есть endpoint/механизм.
            }
        }
    }
};

// ======================================================
// Windows Service glue
// ======================================================
static const wchar_t* SERVICE_NAME = L"mss_semd_checking";

static void WINAPI svc_ctrl_handler(DWORD ctrl) {
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        set_service_status(SERVICE_STOP_PENDING);
        if (g_stopEvent) SetEvent(g_stopEvent);
        return;
    default:
        return;
    }
}

static void WINAPI svc_main(DWORD argc, LPWSTR* argv) {
    g_svcStatusHandle = RegisterServiceCtrlHandlerW(SERVICE_NAME, svc_ctrl_handler);
    if (!g_svcStatusHandle) return;

    g_svcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_svcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_svcStatus.dwCurrentState = SERVICE_START_PENDING;
    g_svcStatus.dwWin32ExitCode = NO_ERROR;
    g_svcStatus.dwCheckPoint = 0;
    g_svcStatus.dwWaitHint = 0;

    set_service_status(SERVICE_START_PENDING);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) {
        set_service_status(SERVICE_STOPPED, GetLastError());
        return;
    }

    // Paths:
    // argv[0] = exe
    // argv[1] = ini path
    // argv[2] = log dir
    std::string ini = "C:\\mss\\mss_semd_checking.ini";
    std::string logdir = "C:\\mss\\logs";
    if (argc >= 2 && argv[1]) {
        std::wstring w = argv[1];
        ini.assign(w.begin(), w.end());
    }
    if (argc >= 3 && argv[2]) {
        std::wstring w = argv[2];
        logdir.assign(w.begin(), w.end());
    }

    SemdService svc(ini, logdir);

    set_service_status(SERVICE_RUNNING);
    svc.run();

    set_service_status(SERVICE_STOPPED);
    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
}

// ======================================================
// KEYGEN mode (console tool)
// ======================================================
#ifdef KEYGEN
static int keygen_main(int argc, char** argv) {
    // Usage:
    // mss_semd_keygen.exe <product_code> <expires_utc>
    // expires_utc example: 2026-12-31T23:59:59Z
    if (argc < 3) {
        std::printf("Usage: %s <product_code> <expires_utc>\n", argv[0]);
        std::printf("Example: %s ABCDEF... 2026-12-31T23:59:59Z\n", argv[0]);
        return 2;
    }
    std::string product_code = argv[1];
    std::string expires_utc = argv[2];

    std::string codekey = make_codekey(product_code, expires_utc);
    if (codekey.empty()) {
        std::printf("Failed to generate CodeKey\n");
        return 1;
    }
    std::printf("%s\n", codekey.c_str());
    return 0;
}

int main(int argc, char** argv) {
    return keygen_main(argc, argv);
}
#else

// If launched from console for debug: run once and exit
static int console_debug_main(int argc, char** argv) {
    std::string ini = "C:\\mss\\mss_semd_checking.ini";
    std::string logdir = "C:\\mss\\logs";
    if (argc >= 2) ini = argv[1];
    if (argc >= 3) logdir = argv[2];

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SemdService svc(ini, logdir);
    svc.run();
    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    // If started with --console => run as console app
    if (argc >= 2 && std::wstring(argv[1]) == L"--console") {
        std::vector<std::string> a;
        for (int i=0;i<argc;i++){
            std::wstring w(argv[i]);
            a.emplace_back(w.begin(), w.end());
        }
        std::vector<char*> c;
        for (auto& s : a) c.push_back(s.data());
        return console_debug_main((int)c.size(), c.data());
    }

    SERVICE_TABLE_ENTRYW table[] = {
        { (LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONW)svc_main },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(table)) {
        // If not started as service, allow console fallback (helpful on new server)
        std::vector<std::string> a;
        for (int i=0;i<argc;i++){
            std::wstring w(argv[i]);
            a.emplace_back(w.begin(), w.end());
        }
        std::vector<char*> c;
        for (auto& s : a) c.push_back(s.data());
        return console_debug_main((int)c.size(), c.data());
    }
    return 0;
}
#endif