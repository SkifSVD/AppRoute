#pragma once

// Запуск программы с правилом AppRoute (issue #7): процесс создаётся приостановленным,
// в него внедряется hook-DLL нужной разрядности, правило передаётся через его окружение
// (наследуется дочерними процессами). Общий код для approute-run и будущего GUI: ничего не
// печатает и не меняет окружение текущего процесса.

#include "core/Policy.h"
#include "core/Win.h"

#include <string>

namespace approute {

struct LaunchRequest {
    std::wstring commandLine;          // программа и аргументы, как в CreateProcess
    std::wstring adapterGuid;          // "{GUID}" интерфейса правила
    std::wstring logPath;              // журнал hook-DLL; пусто — без журнала
    bool includeChildren = true;
    bool systemDns = false;            // dns: system
    UnavailablePolicy policy;
    std::wstring binDir;               // папка hook-DLL и помощников; пусто — папка этого модуля
    bool inheritStdHandles = true;     // консольный запуск: отдать программе свои stdin/out/err
};

enum class LaunchStatus {
    Started,
    StartFailed,        // CreateProcess не удался
    Protected,          // защитное или системное ПО — AppRoute в него не вмешивается
    InjectFailed,       // процесс создан, но правило применить не удалось (процесс завершён)
};

struct LaunchResult {
    LaunchStatus status = LaunchStatus::StartFailed;
    DWORD error = NO_ERROR;
    std::wstring message;              // описание ошибки для пользователя
    std::wstring image;                // полный путь запущенного exe
    bool is32Bit = false;
    HANDLE process = nullptr;          // при Started — описатель процесса, закрывает вызывающий
    DWORD pid = 0;

    bool Ok() const { return status == LaunchStatus::Started; }
};

LaunchResult LaunchWithRule(const LaunchRequest& request);

// Полный путь программы из командной строки так, как её найдёт CreateProcess
// (для поиска правила до запуска); если не найдена — первое слово как есть.
std::wstring ResolveProgramPath(const std::wstring& commandLine);

} // namespace approute
