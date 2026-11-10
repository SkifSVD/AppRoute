// approute-run — запуск программы с привязкой её трафика к выбранному интерфейсу.
//
//   approute-run --adapter <интерфейс> [--log <файл>] [--no-wait] -- <программа> [аргументы...]
//
// Программа стартует приостановленной, в неё внедряется approute-hook64.dll, затем она
// продолжает работу. Правило передаётся через переменные окружения (наследуются дочерними
// процессами). Минимальная версия для проверки #5; полноценный launcher — issue #7.

#include "core/NetAdapters.h"
#include "core/Util.h"

#include <format>
#include <optional>
#include <string>
#include <string_view>

using namespace approute;

namespace {

void Out(std::wstring_view text)
{
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    DWORD written = 0;
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        WriteConsoleW(h, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
        return;
    }
    const int len = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string utf8(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), utf8.data(), len, nullptr, nullptr);
    WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
}

void Line(std::wstring_view text)
{
    Out(text);
    Out(L"\n");
}

void PrintUsage()
{
    Line(L"approute-run — запуск программы через выбранный сетевой интерфейс");
    Line(L"");
    Line(L"  approute-run --adapter IF [--log FILE] [--no-wait] -- PROGRAM [ARGS...]");
    Line(L"");
    Line(L"  IF         ifIndex, GUID или имя интерфейса (см. approute-routes list)");
    Line(L"  --log      журнал hook-DLL (все процессы пишут в один файл)");
    Line(L"  --no-wait  не ждать завершения программы");
}

struct Options {
    std::wstring adapter;
    std::wstring log;
    bool wait = true;
    std::wstring commandLine;   // всё после " -- ", как есть
};

// Командная строка программы берётся из исходной строки без перекодирования кавычек.
std::optional<std::wstring> TailAfterSeparator()
{
    const std::wstring_view cmd = GetCommandLineW();
    const auto pos = cmd.find(L" -- ");
    if (pos == std::wstring_view::npos) {
        return std::nullopt;
    }
    std::wstring tail(cmd.substr(pos + 4));
    while (!tail.empty() && tail.front() == L' ') {
        tail.erase(tail.begin());
    }
    if (tail.empty()) {
        return std::nullopt;
    }
    return tail;
}

std::optional<Options> ParseArgs(int argc, wchar_t** argv)
{
    Options o;
    int i = 1;
    for (; i < argc; ++i) {
        const std::wstring_view arg = argv[i];
        if (arg == L"--") {
            break;
        }
        if ((arg == L"--adapter" || arg == L"--log") && i + 1 < argc) {
            (arg == L"--adapter" ? o.adapter : o.log) = argv[++i];
        } else if (arg == L"--no-wait") {
            o.wait = false;
        } else {
            Line(std::format(L"Ошибка: неизвестный параметр {}", arg));
            return std::nullopt;
        }
    }
    auto tail = TailAfterSeparator();
    if (i >= argc || !tail || o.adapter.empty()) {
        return std::nullopt;
    }
    o.commandLine = std::move(*tail);
    return o;
}

std::wstring HookDllPath()
{
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring path = self;
    path.resize(path.find_last_of(L"\\/") + 1);
    return path + L"approute-hook64.dll";
}

bool IsWow64(HANDLE process)
{
    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (!IsWow64Process2(process, &processMachine, &nativeMachine)) {
        return false;
    }
    return processMachine != IMAGE_FILE_MACHINE_UNKNOWN;
}

// LoadLibraryW(dllPath) в целевом процессе через удалённый поток.
DWORD InjectDll(HANDLE process, const std::wstring& dllPath)
{
    const SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        return GetLastError();
    }
    DWORD result = NO_ERROR;
    if (!WriteProcessMemory(process, remote, dllPath.c_str(), bytes, nullptr)) {
        result = GetLastError();
    } else {
        auto* loadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
        HANDLE thread = CreateRemoteThread(process, nullptr, 0, loadLibrary, remote, 0, nullptr);
        if (!thread) {
            result = GetLastError();
        } else {
            if (WaitForSingleObject(thread, 15000) != WAIT_OBJECT_0) {
                result = WAIT_TIMEOUT;
            } else {
                DWORD module = 0;   // младшие 32 бита HMODULE: 0 — LoadLibraryW не удался
                GetExitCodeThread(thread, &module);
                if (module == 0) {
                    result = ERROR_MOD_NOT_FOUND;
                }
            }
            CloseHandle(thread);
        }
    }
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return result;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    const auto options = ParseArgs(argc, argv);
    if (!options) {
        PrintUsage();
        return 1;
    }

    const auto adapters = EnumerateAdapters();
    const auto* adapter = FindAdapter(adapters, options->adapter);
    if (!adapter) {
        Line(std::format(L"Ошибка: интерфейс «{}» не найден", options->adapter));
        return 1;
    }

    const auto dll = HookDllPath();
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Line(std::format(L"Ошибка: не найдена {}", dll));
        return 1;
    }

    // Правило — через окружение: его унаследуют и дочерние процессы (issue #8)
    SetEnvironmentVariableW(L"APPROUTE_ADAPTER", GuidToString(adapter->guid).c_str());
    if (!options->log.empty()) {
        SetEnvironmentVariableW(L"APPROUTE_LOG", options->log.c_str());
    }

    std::wstring commandLine = options->commandLine;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi)) {
        Line(std::format(L"Ошибка запуска: {}", Win32ErrorMessage(GetLastError())));
        return 1;
    }

    if (IsWow64(pi.hProcess)) {
        Line(L"Ошибка: 32-битные программы пока не поддерживаются (issue #7)");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    const DWORD rc = InjectDll(pi.hProcess, dll);
    if (rc != NO_ERROR) {
        Line(std::format(L"Ошибка внедрения DLL: {}", Win32ErrorMessage(rc)));
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    DWORD exitCode = 0;
    if (options->wait) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &exitCode);
    }
    CloseHandle(pi.hProcess);
    return static_cast<int>(exitCode);
}
