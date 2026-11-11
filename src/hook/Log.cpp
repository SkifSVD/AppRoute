#include "Log.h"

#include "core/Win.h"

#include <cstdarg>
#include <cstdio>
#include <string>

namespace approute::hook {

namespace {

SRWLOCK g_lock = SRWLOCK_INIT;
HANDLE g_file = INVALID_HANDLE_VALUE;

} // namespace

void LogInit()
{
    wchar_t path[MAX_PATH] = {};
    if (GetEnvironmentVariableW(L"APPROUTE_LOG", path, MAX_PATH) == 0) {
        return;
    }
    g_file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

void Log(const wchar_t* format, ...)
{
    wchar_t message[1024];
    va_list args;
    va_start(args, format);
    _vsnwprintf_s(message, _TRUNCATE, format, args);
    va_end(args);

    SYSTEMTIME t{};
    GetLocalTime(&t);
    wchar_t line[1200];
    _snwprintf_s(line, _TRUNCATE, L"%04u-%02u-%02u %02u:%02u:%02u.%03u [AppRoute %lu] %ls\r\n", t.wYear, t.wMonth,
                 t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds, GetCurrentProcessId(), message);

    OutputDebugStringW(line);

    if (g_file == INVALID_HANDLE_VALUE) {
        return;
    }
    char utf8[3600];
    const int len = WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8, sizeof(utf8), nullptr, nullptr);
    if (len <= 1) {
        return;
    }
    AcquireSRWLockExclusive(&g_lock);
    DWORD written = 0;
    WriteFile(g_file, utf8, static_cast<DWORD>(len - 1), &written, nullptr);
    ReleaseSRWLockExclusive(&g_lock);
}

} // namespace approute::hook
