#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdint.h>

// Fixed-width wire format shared with controller.py (x64 only).
struct Result { uint64_t hwnd; uint32_t tid, ok, error, observed, query_error, reserved; };
struct Request {
    uint32_t magic, affinity, count, overflow;
    uint64_t only_hwnd;
    Result results[2048];
};
static_assert(sizeof(Result) == 32, "Wire format mismatch");
static_assert(sizeof(Request) == 65560, "Wire format mismatch");

static BOOL CALLBACK ApplyWindow(HWND hwnd, LPARAM param) {
    Request* r = reinterpret_cast<Request*>(param);
    DWORD pid = 0;
    DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetCurrentProcessId()) return TRUE;
    if (r->only_hwnd && r->only_hwnd != reinterpret_cast<uint64_t>(hwnd)) return TRUE;
    if (r->count >= 2048) { r->overflow = 1; return TRUE; }
    Result& out = r->results[r->count++];
    out.hwnd = reinterpret_cast<uint64_t>(hwnd);
    out.tid = tid;
    SetLastError(0);
    out.ok = SetWindowDisplayAffinity(hwnd, r->affinity) ? 1 : 0;
    out.error = out.ok ? 0 : GetLastError();
    DWORD value = 0;
    SetLastError(0);
    if (GetWindowDisplayAffinity(hwnd, &value)) { out.observed = value; out.query_error = 0; }
    else { out.observed = 0xffffffff; out.query_error = GetLastError(); }
    return TRUE;
}

extern "C" __declspec(dllexport) DWORD WINAPI ApplyAffinity(void* param) {
    Request* r = static_cast<Request*>(param);
    if (!r || r->magic != 0x57414631 || (r->affinity != 0 && r->affinity != 0x11))
        return ERROR_INVALID_PARAMETER;
    r->count = 0;
    r->overflow = 0;
    SetLastError(0);
    if (!EnumWindows(ApplyWindow, reinterpret_cast<LPARAM>(r))) {
        DWORD error = GetLastError();
        return error ? error : ERROR_GEN_FAILURE;
    }
    return ERROR_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
