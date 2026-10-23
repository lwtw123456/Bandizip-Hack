#include "WinInetHooks.h"
#include <WinInet.h>
#include <safetyhook.hpp>
#include <mutex>

namespace {

struct WinInetModule {
    HMODULE handle = nullptr;
    ~WinInetModule() { if (handle) ::FreeLibrary(handle); }
} g_wininet;

SafetyHookInline g_connectHook;
SafetyHookInline g_requestHook;
std::mutex g_installMutex;

HINTERNET WINAPI HookInternetConnectA(
    HINTERNET hInternet, LPCSTR server, INTERNET_PORT port,
    LPCSTR user, LPCSTR password, DWORD service,
    DWORD flags, DWORD_PTR context)
{
    if (hInternet && service == INTERNET_SERVICE_HTTP) {
        static char proxy[] = "127.0.0.1:52007";

        struct {
            DWORD dwAccessType;
            LPCSTR lpszProxy;
            LPCSTR lpszProxyBypass;
        } info{};
        info.dwAccessType = INTERNET_OPEN_TYPE_PROXY;
        info.lpszProxy = proxy;

        ::InternetSetOptionA(hInternet, INTERNET_OPTION_PROXY,
                             &info, sizeof(info));
    }

    return g_connectHook.call<HINTERNET>(
        hInternet, server, port, user, password, service, flags, context);
}

HINTERNET WINAPI HookHttpOpenRequestA(
    HINTERNET hConnect, LPCSTR verb, LPCSTR path,
    LPCSTR version, LPCSTR referrer, LPCSTR* acceptTypes,
    DWORD flags, DWORD_PTR context)
{
	flags &= ~INTERNET_FLAG_SECURE;
	
    return g_requestHook.call<HINTERNET>(
        hConnect, verb, path, version, referrer, acceptTypes, flags, context);
}

} // namespace

extern "C" BOOL WINAPI InstallWinInetHooks()
{
    std::lock_guard<std::mutex> lock(g_installMutex);
    if (g_connectHook && g_requestHook)
        return TRUE;

    g_wininet.handle = ::LoadLibraryW(L"wininet.dll");
    if (!g_wininet.handle)
        return FALSE;

    auto connect = ::GetProcAddress(g_wininet.handle, "InternetConnectA");
    auto request = ::GetProcAddress(g_wininet.handle, "HttpOpenRequestA");

    if (connect && request) {
        g_connectHook = safetyhook::create_inline(
            reinterpret_cast<void*>(connect),
            reinterpret_cast<void*>(&HookInternetConnectA));

        if (g_connectHook) {
            g_requestHook = safetyhook::create_inline(
                reinterpret_cast<void*>(request),
                reinterpret_cast<void*>(&HookHttpOpenRequestA));
        }
    }

    if (g_connectHook && g_requestHook)
        return TRUE;

    const DWORD error = (!connect || !request)
        ? ERROR_PROC_NOT_FOUND : ERROR_INVALID_FUNCTION;

    g_requestHook = {};
    g_connectHook = {};
    ::FreeLibrary(g_wininet.handle);
    g_wininet.handle = nullptr;
    ::SetLastError(error);
    return FALSE;
}