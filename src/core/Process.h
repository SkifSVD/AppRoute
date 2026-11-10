#pragma once

#include "core/Win.h"

#include <string>
#include <utility>
#include <vector>

namespace approute {

// Переменные окружения, через которые hook-DLL получает правило.
inline constexpr wchar_t kEnvAdapter[] = L"APPROUTE_ADAPTER";     // GUID интерфейса
inline constexpr wchar_t kEnvLog[] = L"APPROUTE_LOG";             // путь к журналу (необязательно)
inline constexpr wchar_t kEnvChildren[] = L"APPROUTE_CHILDREN";   // "0" — не распространять на дочерние

using EnvVars = std::vector<std::pair<std::wstring, std::wstring>>;

// 32-битный процесс на 64-битной Windows.
bool IsProcessWow64(HANDLE process);

// Полный путь к исполняемому файлу процесса; пусто при ошибке.
std::wstring GetProcessImageName(HANDLE process);

// Процесс, в который AppRoute никогда не внедряется: защитное ПО (антивирусы) и критичные
// системные процессы. Принимает полный путь или имя файла. Список намеренно консервативный
// и расширяемый; главная гарантия — AppRoute вообще трогает только свои процессы.
bool IsProtectedExecutable(std::wstring_view imagePathOrName);

// true, если владелец (SID токена) процесса совпадает с текущим пользователем. AppRoute
// работает только со своими процессами и не внедряется в процессы других пользователей.
// При невозможности проверить (нет доступа к токену) возвращает false — безопасный отказ.
bool ProcessUserMatchesCurrent(HANDLE process);

// LoadLibraryW(dllPath) в другом процессе той же разрядности через удалённый поток.
// NO_ERROR или код ошибки (ERROR_MOD_NOT_FOUND — LoadLibraryW вернул NULL).
DWORD InjectDll(HANDLE process, const std::wstring& dllPath, DWORD timeoutMs = 15000);

// Новый Unicode-блок окружения: все переменные исходного блока, кроме перечисленных в vars
// (без учёта регистра), плюс vars. unicode=false — исходный блок в кодировке ANSI.
std::vector<wchar_t> MergeEnvironment(const void* block, bool unicode, const EnvVars& vars);

} // namespace approute
