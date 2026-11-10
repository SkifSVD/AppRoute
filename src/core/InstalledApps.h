#pragma once

// Программы, установленные в Windows, и разбор ярлыков — для выбора программы в правиле (#37).

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace approute {

struct InstalledApp {
    std::wstring name;   // "Telegram Desktop" — имя ярлыка (или файла для App Paths)
    std::wstring path;   // полный путь к .exe
};

// Программа, на которую указывает ярлык .lnk (в том числе «объявленный» ярлык MSI), или
// nullopt, если цель — не .exe или её нет на диске.
std::optional<std::wstring> ResolveShortcut(const std::wstring& lnkPath);

// Программа из выбранного пользователем файла: .exe — как есть, .lnk — его цель.
// nullopt и описание ошибки, если это не программа.
std::optional<std::wstring> ProgramFromFile(const std::wstring& path, std::wstring* error);

// Ярлыки меню «Пуск» (общие и пользователя) и зарегистрированные пути программ (App Paths):
// без деинсталляторов и дублей, по алфавиту. Приложения Microsoft Store не входят — их
// нельзя запустить через AppRoute.
std::vector<InstalledApp> EnumerateInstalledApps();

// --- чистые функции (тестируются) ---

// Не показывать в списке: служебный ярлык (удаление, справка, сайт) или приложение Microsoft Store.
bool IsUtilityShortcut(std::wstring_view name, std::wstring_view exePath);

// Без служебных и дублей (одна программа — первая запись: ярлыки меню «Пуск» идут раньше
// App Paths и дают более понятное имя), по имени без учёта регистра.
std::vector<InstalledApp> MergeInstalledApps(std::vector<InstalledApp> apps);

// Строка поиска: все слова входят в имя или путь, без учёта регистра. Пустая — подходит всё.
bool MatchesAppFilter(const InstalledApp& app, std::wstring_view query);

} // namespace approute
