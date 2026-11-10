// approute-run — запуск программы с привязкой её трафика к выбранному интерфейсу.
//
//   approute-run --adapter <интерфейс> [--log <файл>] [--no-wait] -- <программа> [аргументы...]
//
// Программа стартует приостановленной, в неё внедряется approute-hook64.dll, затем она
// продолжает работу. Правило передаётся через переменные окружения; дочерние процессы
// получают его от hook-DLL (#8). Полноценный launcher (x86) — issue #7.

#include "core/NetAdapters.h"
#include "core/Process.h"
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
    Line(L"  approute-run --adapter IF [--log FILE] [--no-children] [--no-wait] -- PROGRAM [ARGS...]");
    Line(L"");
    Line(L"  IF             ifIndex, GUID или имя интерфейса (см. approute-routes list)");
    Line(L"  --log          журнал hook-DLL (все процессы пишут в один файл)");
    Line(L"  --no-children  не применять правило к дочерним процессам");
    Line(L"  --no-wait      не ждать завершения программы");
}

struct Options {
    std::wstring adapter;
    std::wstring log;
    bool wait = true;
    bool children = true;
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
        } else if (arg == L"--no-children") {
            o.children = false;
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

    if (IsProcessElevated()) {
        Line(L"Внимание: запуск от имени администратора. Браузеры на Chromium в этом случае");
        Line(L"перезапускают себя без прав; AppRoute отслеживает это, но надёжнее обычный терминал.");
    }

    const auto dll = HookDllPath();
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Line(std::format(L"Ошибка: не найдена {}", dll));
        return 1;
    }

    // Правило — через окружение: его унаследуют и дочерние процессы (issue #8)
    SetEnvironmentVariableW(kEnvAdapter, GuidToString(adapter->guid).c_str());
    SetEnvironmentVariableW(kEnvLog, options->log.empty() ? nullptr : options->log.c_str());
    SetEnvironmentVariableW(kEnvChildren, options->children ? nullptr : L"0");

    std::wstring commandLine = options->commandLine;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    // Как при обычном запуске из консоли: программа (в т.ч. GUI) получает наши stdin/stdout/stderr
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr, TRUE,
                        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi)) {
        Line(std::format(L"Ошибка запуска: {}", Win32ErrorMessage(GetLastError())));
        return 1;
    }

    if (IsProcessWow64(pi.hProcess)) {
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
