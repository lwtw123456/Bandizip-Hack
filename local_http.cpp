#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include "local_http.h"
extern "C" {
#include "blowfish.h"
}

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

namespace {
constexpr unsigned short kPort = 52007;
constexpr size_t kMaxHeader = 16 * 1024;
constexpr DWORD kIoTimeoutMs = 2000;

static int route(std::string_view path, std::string& plaintext) {
    if (path == "/uni.app/checkProductKey.php") {
        plaintext = R"(<ret result="ok" guid="1234567890abcdef1234567890abcdef" productID="PRO"/>)";
        return 200;
    }
    if (path == "/uni.app/checkValidGUID.php") {
        plaintext = R"(<ret result="ok"/>)";
        return 200;
    }
    plaintext = "not found";
    return 404;
}

static bool send_all(SOCKET socket, std::string_view data) {
    size_t sent = 0;
    while (sent < data.size()) {
        const size_t left = data.size() - sent;
        const int chunk = static_cast<int>(left > 0x7fffffff ? 0x7fffffff : left);
        const int n = send(socket, data.data() + sent, chunk, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static void send_response(SOCKET socket, int status,
                          std::string_view ciphertext) {
    const char* reason = (status == 200) ? "OK" :
                         (status == 400) ? "Bad Request" :
                         (status == 404) ? "Not Found" :
                         (status == 431) ? "Request Header Fields Too Large" :
                         "Internal Server Error";
    std::string headers = "HTTP/1.1 " + std::to_string(status) + " " + reason +
        "\r\nContent-Type: text/html; charset=utf-8"
        "\r\nContent-Length: " + std::to_string(ciphertext.size()) +
        "\r\nConnection: close\r\n\r\n";
    if (send_all(socket, headers)) send_all(socket, ciphertext);
}

static uint32_t read_be32(const uint8_t* x) {
    return (uint32_t(x[0]) << 24) | (uint32_t(x[1]) << 16) |
           (uint32_t(x[2]) << 8) | uint32_t(x[3]);
}

static void write_be32(uint8_t* x, uint32_t v) {
    x[0] = uint8_t(v >> 24);
    x[1] = uint8_t(v >> 16);
    x[2] = uint8_t(v >> 8);
    x[3] = uint8_t(v);
}

static bool encrypt_body(BCRYPT_ALG_HANDLE md5, std::string_view ua,
                         std::string_view plaintext, std::string& out) {
    if (ua.size() > 0xffffffffu) return false;
    unsigned char digest[16];
    const NTSTATUS result = BCryptHash(
        md5, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<char*>(ua.data())),
        static_cast<ULONG>(ua.size()), digest, sizeof(digest));
    if (result < 0) return false;

    const char hex[] = "0123456789abcdef";
    char key[32];
    for (int i = 0; i < 16; ++i) {
        key[i * 2] = hex[digest[i] >> 4];
        key[i * 2 + 1] = hex[digest[i] & 15];
    }
    struct blowfish ctx;
    blowfish_init(&ctx, key, sizeof(key));

    out.clear();
    out.reserve(((plaintext.size() + 7) / 8) * 16);
    for (size_t p = 0; p < plaintext.size(); p += 8) {
        uint8_t block[8] = {};
        const size_t size = std::min<size_t>(8, plaintext.size() - p);
        std::memcpy(block, plaintext.data() + p, size);
        uint32_t left = read_be32(block), right = read_be32(block + 4);
        blowfish_encrypt(&ctx, &left, &right);
        write_be32(block, left);
        write_be32(block + 4, right);
        for (const uint8_t b : block) {
            out.push_back(hex[b >> 4]);
            out.push_back(hex[b & 15]);
        }
    }
    return true;
}

static bool parse_headers(const std::string& request,
                          std::string_view& path,
                          std::string_view& ua) {
    const size_t eol = request.find("\r\n");
    if (eol == std::string::npos) return false;
    const std::string_view line(request.data(), eol);
    const size_t a = line.find(' ');
    if (a == std::string_view::npos) return false;
    const size_t b = line.find(' ', a + 1);
    if (b == std::string_view::npos || b == a + 1) return false;
    path = line.substr(a + 1, b - a - 1);
    if (path.empty()) return false;
    if (path[0] != '/') {
        const size_t scheme = path.find("://");
        if (scheme == std::string_view::npos) return false;
        const size_t slash = path.find('/', scheme + 3);
        path = (slash == std::string_view::npos) ? std::string_view("/", 1)
                                                : path.substr(slash);
    }
    const size_t q = path.find('?');
    if (q != std::string_view::npos) path = path.substr(0, q);

    ua = {};
    size_t p = eol + 2;
    while (p < request.size()) {
        const size_t end = request.find("\r\n", p);
        if (end == std::string::npos || end == p) break;
        const std::string_view h(request.data() + p, end - p);
        if (h.size() >= 11 && _strnicmp(h.data(), "User-Agent:", 11) == 0) {
            size_t start = 11;
            size_t stop = h.size();
            while (start < stop && (h[start] == ' ' || h[start] == '\t'))
                ++start;
            while (stop > start && (h[stop - 1] == ' ' || h[stop - 1] == '\t'))
                --stop;
            ua = h.substr(start, stop - start);
            break;
        }
        p = end + 2;
    }
    return true;
}

static void handle_client(SOCKET client, BCRYPT_ALG_HANDLE md5) {
    const DWORD timeout = kIoTimeoutMs;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    std::string request;
    request.reserve(4096);
    char buf[4096];
    while (request.find("\r\n\r\n") == std::string::npos) {
        const int n = recv(client, buf, sizeof(buf), 0);
        if (n <= 0) return;
        request.append(buf, static_cast<size_t>(n));
        if (request.size() > kMaxHeader) {
            send_response(client, 431, {});
            return;
        }
    }

    std::string_view path, ua;
    if (!parse_headers(request, path, ua)) {
        send_response(client, 400, {});
        return;
    }

    std::string plaintext;
    const int status = route(path, plaintext);
    std::string ciphertext;
    if (!encrypt_body(md5, ua, plaintext, ciphertext)) {
        send_response(client, 500, {});
        return;
    }
    send_response(client, status, ciphertext);
}

SRWLOCK g_lock = SRWLOCK_INIT;
HANDLE g_thread = nullptr;
HANDLE g_ready = nullptr;
volatile LONG g_stop = 0;
volatile LONG g_start_ok = 0;

static DWORD WINAPI server_thread(LPVOID) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        SetEvent(g_ready);
        return 0;
    }

    BCRYPT_ALG_HANDLE md5 = nullptr;
    SOCKET server = INVALID_SOCKET;
    if (BCryptOpenAlgorithmProvider(&md5, BCRYPT_MD5_ALGORITHM, nullptr, 0) < 0)
        goto failed;

    server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == INVALID_SOCKET) goto failed;
    {
        BOOL exclusive = TRUE;
        if (setsockopt(server, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                       reinterpret_cast<const char*>(&exclusive),
                       sizeof(exclusive)) == SOCKET_ERROR) goto failed;
    }
    {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(kPort);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            listen(server, SOMAXCONN) != 0) goto failed;
    }

    InterlockedExchange(&g_start_ok, 1);
    SetEvent(g_ready);

    while (!InterlockedCompareExchange(&g_stop, 0, 0)) {
        fd_set set;
        FD_ZERO(&set);
        FD_SET(server, &set);
        timeval tv{};
        tv.tv_usec = 200000;
        const int ready = select(0, &set, nullptr, nullptr, &tv);
        if (ready == SOCKET_ERROR) break;
        if (ready == 0 || InterlockedCompareExchange(&g_stop, 0, 0)) continue;
        SOCKET client = accept(server, nullptr, nullptr);
        if (client != INVALID_SOCKET) {
            handle_client(client, md5);
            closesocket(client);
        }
    }
    closesocket(server);
    BCryptCloseAlgorithmProvider(md5, 0);
    WSACleanup();
    return 0;

failed:
    if (server != INVALID_SOCKET) closesocket(server);
    if (md5) BCryptCloseAlgorithmProvider(md5, 0);
    WSACleanup();
    SetEvent(g_ready);
    return 0;
}
} // namespace

extern "C" int local_http_start(void) {
    AcquireSRWLockExclusive(&g_lock);
    if (g_thread != nullptr) {
        if (WaitForSingleObject(g_thread, 0) == WAIT_TIMEOUT) {
            ReleaseSRWLockExclusive(&g_lock);
            return 1;
        }
        CloseHandle(g_thread);
        g_thread = nullptr;
    }
    InterlockedExchange(&g_stop, 0);
    InterlockedExchange(&g_start_ok, 0);
    g_ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_ready) {
        ReleaseSRWLockExclusive(&g_lock);
        return 0;
    }
    g_thread = CreateThread(nullptr, 0, server_thread, nullptr, 0, nullptr);
    if (!g_thread) {
        CloseHandle(g_ready);
        g_ready = nullptr;
        ReleaseSRWLockExclusive(&g_lock);
        return 0;
    }
    WaitForSingleObject(g_ready, INFINITE);
    CloseHandle(g_ready);
    g_ready = nullptr;
    const int ok = InterlockedCompareExchange(&g_start_ok, 0, 0) != 0;
    if (!ok) {
        WaitForSingleObject(g_thread, INFINITE);
        CloseHandle(g_thread);
        g_thread = nullptr;
    }
    ReleaseSRWLockExclusive(&g_lock);
    return ok;
}

extern "C" void local_http_stop(void) {
    AcquireSRWLockExclusive(&g_lock);
    if (g_thread) {
        InterlockedExchange(&g_stop, 1);
        WaitForSingleObject(g_thread, INFINITE);
        CloseHandle(g_thread);
        g_thread = nullptr;
    }
    ReleaseSRWLockExclusive(&g_lock);
}