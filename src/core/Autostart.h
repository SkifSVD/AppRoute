#pragma once

// Автозапуск выбранных программ через AppRoute при входе в Windows (#60).
//
// У правила — флажок autostart. Если он включён хотя бы у одного правила, AppRoute добавляет
// одну запись автозагрузки для себя: значение "AppRoute" в HKCU\...\CurrentVersion\Run с
// командой approute-gui.exe [--config FILE] --autostart. Она видна в «Параметры → Приложения →
// Автозагрузка» и там же отключается. Флажков нет — записи нет. Чужие записи автозагрузки
// AppRoute не меняет: FindOwnAutostart только находит включённую автозагрузку самой программы,
// чтобы окно подсказало её отключить (иначе программа стартует ещё и мимо AppRoute).

#include "core/Config.h"
#include "core/Win.h"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace approute {

inline constexpr wchar_t kAutostartValueName[] = L"AppRoute";

// Команда записи: "C:\...\approute-gui.exe" [--config "FILE"] --autostart (без --config, если
// конфиг по умолчанию)
std::wstring AutostartCommand(const std::wstring& guiExe, const std::wstring& configPath);

// Есть правила с флажком autostart
bool AutostartWanted(const Config& config);

// Команда записи "AppRoute" в Run текущего пользователя; nullopt — записи нет
std::optional<std::wstring> ReadAutostartEntry();

// Привести запись к конфигу: есть правила с флажком — записать (обновить путь), нет — удалить.
bool SyncAutostart(const Config& config, const std::wstring& guiExe, const std::wstring& configPath,
                   std::wstring* error);

// Программа из команды автозагрузки: "\"C:\\a b\\x.exe\" -y" → "C:\\a b\\x.exe"; %ПЕРЕМЕННЫЕ%
// раскрываются
std::wstring ProgramOfCommand(std::wstring_view command);

// Команда запускает программу правила (полный путь — тот же файл, имя файла — то же имя)
bool CommandMatchesRule(const Rule& rule, std::wstring_view command);

// Включённая автозагрузка самой программы правила (реестр Run текущего пользователя и всех
// пользователей, папки «Автозагрузка»): описания мест для подсказки. Для приложений из пакетов
// не ищется.
std::vector<std::wstring> FindOwnAutostart(const Rule& rule);

// Интерфейс правила поднят и с адресом, или прокси отвечает на порту
bool RuleTargetReady(const Rule& rule);

} // namespace approute
