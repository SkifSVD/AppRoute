#pragma once

// Запуск программы с правилом AppRoute (issue #7): процесс создаётся приостановленным,
// в него внедряется hook-DLL нужной разрядности, правило передаётся через его окружение
// (наследуется дочерними процессами). Общий код для approute-run и будущего GUI: ничего не
// печатает и не меняет окружение текущего процесса.

#include "core/Policy.h"
#include "core/Win.h"

#include <string>
#include <vector>

namespace approute {

struct LaunchRequest {
    std::wstring commandLine;          // программа и аргументы, как в CreateProcess
    std::wstring packageApp;           // или приложение из пакета (AUMID, #59) — тогда commandLine не нужна
    std::wstring packageArguments;     // аргументы приложения из пакета
    std::wstring adapterGuid;          // "{GUID}" интерфейса правила
    std::wstring proxy;                // или SOCKS5-прокси "127.0.0.1:10808" (#17)
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
    std::wstring warning;              // при Started — предупреждение для пользователя (может быть пусто)
    std::wstring image;                // полный путь запущенного exe
    bool is32Bit = false;
    HANDLE process = nullptr;          // при Started — описатель процесса, закрывает вызывающий
    DWORD pid = 0;

    bool Ok() const { return status == LaunchStatus::Started; }
};

LaunchResult LaunchWithRule(const LaunchRequest& request);

// Процессы текущего пользователя с этим exe без hook-DLL, кроме exceptPid (#70): запущенная через
// AppRoute копия может передать им окно и завершиться — тогда правило не действует.
// LaunchWithRule проверяет это сам и пишет предупреждение в LaunchResult::warning.
std::vector<DWORD> ImageRunsWithoutRule(const std::wstring& image, DWORD exceptPid);

// Текст предупреждения: программа уже запущена без AppRoute
std::wstring AlreadyRunningWarning(const std::wstring& image, size_t processes);

// Запрос на запуск по правилу конфига; commandLine — программа и аргументы (для приложения из
// пакета программа — его AUMID, аргументы передаются активации). Переопределения (параметры
// командной строки approute-run) вызывающий применяет поверх.
LaunchRequest RequestForRule(const Rule& rule, std::wstring commandLine);

// --- Приложения из пакетов MSIX и Microsoft Store (#59) ----------------------------------------
//
// Процесс приложения из пакета создаёт Windows, а не AppRoute, поэтому hook-DLL внедряется
// через документированный механизм отладки пакетов IPackageDebugSettings (им пользуются
// Visual Studio и PLMDebug): на время запуска для пакета включается «отладчик» — помощник
// approute-inject. Windows создаёт процесс приложения приостановленным и запускает помощника
// с "-p <pid> -tid <tid>"; тот внедряет hook-DLL и возобновляет поток. Правило передаётся в
// окружении процесса (параметр environment того же API). Сразу после запуска режим отладки
// снимается; если AppRoute завершился раньше, RestorePackageDebugging снимает его при
// следующем запуске.

// Снять режим отладки, оставшийся от прерванного запуска AppRoute
void RestorePackageDebugging();

// Режим отладчика помощника approute-inject: Windows запустила процесс pid (поток tid) пакета
// packageFullName. Внедрить hook-DLL из binDir и возобновить поток; при ошибке процесс
// завершается. signal — имя для событий результата (см. LaunchWithRule). Код ошибки Win32.
DWORD AttachPackageProcess(const std::wstring& packageFullName, const std::wstring& signal, DWORD pid,
                           DWORD tid, const std::wstring& binDir);

// Командная строка для запуска программы правила без аргументов: %ПЕРЕМЕННЫЕ% раскрыты,
// путь в кавычках.
std::wstring CommandLineForApp(std::wstring_view app);

// Аргументы после программы: "\"prog\" a b" → "a b"
std::wstring ArgumentsAfterProgram(std::wstring_view commandLine);

// Полный путь программы из командной строки так, как её найдёт CreateProcess
// (для поиска правила до запуска); если не найдена — первое слово как есть.
std::wstring ResolveProgramPath(const std::wstring& commandLine);

} // namespace approute
