#pragma once

// Ярлыки запуска программы через AppRoute (#13). Ярлык вызывает approute-gui --run: окно не
// открывается, программа стартует по правилу из конфига, ошибки — в окне сообщения. Значок
// ярлыка — значок программы.

#include "core/Config.h"

#include <optional>
#include <string>
#include <string_view>

namespace approute {

struct ShortcutSpec {
    std::wstring target;             // approute-gui.exe
    std::wstring arguments;          // [--config "FILE"] --run "C:\...\app.exe"
    std::wstring workingDirectory;   // папка программы
    std::wstring iconPath;           // программа
    int iconIndex = 0;
    std::wstring description;
};

// Аргумент командной строки в кавычках по правилам CommandLineToArgvW, если нужно.
std::wstring QuoteArgument(std::wstring_view arg);

// Ярлык для правила. configPath пустой или путь по умолчанию — без --config. nullopt и ошибка,
// если в правиле только имя файла: для ярлыка нужен полный путь программы. Приложение из
// пакета (#59): --run "Семейство!Id", значок — exe пакета (packageExe; пусто — значок AppRoute).
std::optional<ShortcutSpec> LaunchShortcutFor(const Rule& rule, const std::wstring& launcherExe,
                                              const std::wstring& configPath, std::wstring* error,
                                              const std::wstring& packageExe = {});

// "Telegram (AppRoute).lnk": имя программы без расширения (или displayName, если задано —
// для приложений из пакетов), недопустимые в именах файлов символы заменены.
std::wstring LaunchShortcutFileName(const Rule& rule, std::wstring_view displayName = {});

// Записать ярлык (перезаписывает существующий файл).
bool SaveShortcut(const std::wstring& lnkPath, const ShortcutSpec& spec, std::wstring* error);

// Прочитать ярлык: цель, аргументы, папка, значок. Для проверки и тестов.
std::optional<ShortcutSpec> ReadShortcut(const std::wstring& lnkPath);

} // namespace approute
