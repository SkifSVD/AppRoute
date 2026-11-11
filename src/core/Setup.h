#pragma once

// Установка AppRoute для текущего пользователя (#64) — логика approute-setup.exe.
//
// Установка — в %LOCALAPPDATA%\Programs\AppRoute без прав администратора, запись в «Приложениях»
// (HKCU). Обновление — поверх: текущие файлы переносятся в .backup\<время>_<версия> (хранятся две
// последние копии), новые записываются из установщика. Перенос, а не перезапись: файлы,
// занятые запущенными программами (hook-DLL в программах, запущенных через AppRoute), Windows
// переименовать разрешает. Откат возвращает последнюю сохранённую копию, а текущие файлы
// сохраняет вместо неё — повторный откат возвращает обратно. Конфиг (%APPDATA%\AppRoute) и пароли
// прокси (диспетчер учётных данных) не затрагиваются; удаляются только по выбору при удалении.
//
// Папка установки помечается файлом .approute-install (версия): в чужую непустую папку установщик
// не пишет, а удаляет только помеченную.
//
// Служба AppRoute (#16) по-прежнему ставится из окна правил в %ProgramFiles%\AppRoute;
// установщик только обновляет или удаляет её — с запросом UAC (approute-routes install-service /
// uninstall-service).

#include "core/Win.h"

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace approute {

inline constexpr wchar_t kSetupExeName[] = L"approute-setup.exe";
inline constexpr wchar_t kSetupSubdir[] = L"setup";
inline constexpr wchar_t kBackupSubdir[] = L".backup";
inline constexpr wchar_t kInstallMarker[] = L".approute-install";
inline constexpr size_t kBackupsKept = 2;
inline constexpr wchar_t kUninstallKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AppRoute";

// Окно правил approute-gui: заголовок и сообщение «выйти» (установщик закрывает окно перед
// обновлением — как «Выход» в меню значка)
inline constexpr wchar_t kGuiWindowTitle[] = L"AppRoute — правила программ";
inline constexpr wchar_t kGuiExitMessage[] = L"AppRoute.Gui.Exit";

// %LOCALAPPDATA%\Programs\AppRoute
std::wstring DefaultUserInstallDirectory();

// Сравнение версий X.Y.Z: <0, 0, >0. Недостающие и нечисловые части — 0.
int CompareVersions(std::wstring_view a, std::wstring_view b);

enum class InstallDirState {
    Missing,     // папки нет
    Empty,       // пустая
    Installed,   // установка AppRoute (есть .approute-install)
    Foreign,     // непустая чужая — туда не ставим
};
InstallDirState InspectInstallDirectory(const std::wstring& dir);

// Версия установки из .approute-install; nullopt — не установка AppRoute
std::optional<std::wstring> InstalledVersion(const std::wstring& dir);

struct BackupInfo {
    std::wstring path;      // ...\.backup\20261111-153000-123_0.1.0
    std::wstring version;
};
// Сохранённые копии, новые первыми
std::vector<BackupInfo> ListBackups(const std::wstring& dir);

struct PayloadFile {
    std::wstring name;                 // имя файла без папок
    std::span<const std::byte> data;
};

struct SetupReport {
    std::wstring error;                // причина неудачи
    std::vector<std::wstring> notes;   // замечания при успехе (что осталось сделать вручную)
};

// Установка или обновление: текущие файлы — в резервную копию, новые — из files, копия
// установщика (setupImage) — в setup\approute-setup.exe, отметка версии. Ошибка посередине —
// возврат к прежнему состоянию. Лишние резервные копии (больше kBackupsKept) удаляются.
bool InstallFiles(const std::wstring& dir, const std::vector<PayloadFile>& files, std::wstring_view version,
                  std::span<const std::byte> setupImage, SetupReport* report);

// Откат к последней резервной копии; текущие файлы — в новую копию. Версия, к которой
// откатились, или nullopt (нет копий, ошибка — в report).
std::optional<std::wstring> RollbackFiles(const std::wstring& dir, SetupReport* report);

// Удалить папку установки (только помеченную). Занятые файлы остаются — они в report->notes,
// результат false.
bool RemoveInstallFiles(const std::wstring& dir, SetupReport* report);

// --- запись в «Приложениях» -----------------------------------------------------------------

struct RegistryValue {
    std::wstring name;
    std::variant<std::wstring, DWORD> value;
};
// Значения записи удаления: DisplayName, DisplayVersion, InstallLocation, UninstallString и т. д.
std::vector<RegistryValue> UninstallValues(const std::wstring& dir, std::wstring_view version, DWORD sizeKb,
                                           std::wstring_view installDate);
bool WriteUninstallEntry(const std::wstring& dir, std::wstring_view version, std::wstring* error);
void RemoveUninstallEntry();
// Папка из записи удаления; nullopt — AppRoute не установлен установщиком
std::optional<std::wstring> RegisteredInstallDirectory();

// Размер папки установки без резервных копий, КБ
DWORD InstallSizeKb(const std::wstring& dir);

// --- интеграция с оболочкой -----------------------------------------------------------------

// Ярлык «AppRoute» в меню «Пуск» текущего пользователя
std::wstring StartMenuShortcutPath();
bool CreateStartMenuShortcut(const std::wstring& dir, std::wstring* error);

// Удалить ярлыки AppRoute текущего пользователя: «AppRoute» в меню «Пуск», папку ярлыков
// программ AppRoute там же и ярлыки на рабочем столе, запускающие approute-gui.exe из dir.
void RemoveUserShortcuts(const std::wstring& dir);

// Удалить запись автозапуска AppRoute (#60), если она запускает программу из dir
void RemoveAutostartFor(const std::wstring& dir);

// Удалить настройки пользователя: %APPDATA%\AppRoute (правила), %LOCALAPPDATA%\AppRoute
// (журналы), пароли прокси AppRoute в диспетчере учётных данных, HKCU\Software\AppRoute
void RemoveUserSettings(SetupReport* report);

// Закрыть окно правил, запущенное из dir (вежливо — как «Выход» в меню значка), и дождаться
// выхода. true — окна нет или оно закрылось; *wasRunning — было ли оно запущено, *arguments — его
// аргументы (например, --config): с ними окно открывается снова после обновления.
bool CloseRunningGui(const std::wstring& dir, DWORD waitMs, bool* wasRunning, std::wstring* arguments = nullptr);

// --- служба AppRoute ------------------------------------------------------------------------

struct ServiceSetupArgs {
    std::wstring config;
    std::wstring clientSid;
};
// Параметры из командной строки службы: "...approute-routes.exe" service --config "C" --client-sid S
std::optional<ServiceSetupArgs> ParseServiceCommand(std::wstring_view commandLine);
// Командная строка установленной службы; nullopt — службы нет или не прочитать
std::optional<std::wstring> InstalledServiceCommand();
// Параметры approute-routes для переустановки службы с теми же настройками
std::wstring ServiceReinstallParameters(const ServiceSetupArgs& args, bool withDriver);

} // namespace approute
