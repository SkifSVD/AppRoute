#pragma once

// Служба «AppRoute» — менеджер маршрутов, работающий постоянно (#16).
//
// Ставится и удаляется только явным действием пользователя в approute-gui (согласие → UAC).
// Границы SECURITY.md не меняются: служба управляет только маршрутами (политика из конфига),
// не отслеживает запуск процессов и ни во что не внедряется.
//
// Защита службы, работающей от имени SYSTEM:
//   • файлы копируются в %ProgramFiles%\AppRoute — exe службы не лежит в папке, куда может
//     писать обычная программа (иначе её подмена давала бы права SYSTEM);
//   • из привилегий оставлены только нужные (SeChangeNotify, SeCreateGlobal);
//   • запускать и останавливать службу может пользователь, давший согласие, — без UAC;
//   • журнал — в %ProgramData%\AppRoute с проверкой владельца папки и без следования ссылкам.

#include "core/Win.h"

#include <optional>
#include <string>
#include <vector>

namespace approute {

inline constexpr wchar_t kServiceName[] = L"AppRoute";
inline constexpr wchar_t kServiceDisplayName[] = L"AppRoute — менеджер маршрутов";

// %ProgramFiles%\AppRoute
std::wstring InstallDirectory();

// Файлы AppRoute в папке: approute-*.exe и approute-hook*.dll (без *.old-* и прочего).
std::vector<std::wstring> AppRouteBinaries(const std::wstring& dir);

// "\"C:\Program Files\AppRoute\approute-routes.exe\" service --config \"...\" --client-sid S-..."
std::wstring ServiceCommandLine(const std::wstring& exe, const std::wstring& configPath, const std::wstring& clientSid);

// SDDL службы: стандартные права плюс запуск, остановка и опрос для пользователя clientSid.
std::wstring ServiceSecurityDescriptor(const std::wstring& clientSid);

enum class ServiceState { NotInstalled, Stopped, Starting, Running, Stopping, Unknown };

// Состояние службы — без прав администратора.
ServiceState QueryServiceState();

// Запуск и остановка установленной службы (пользователю, давшему согласие, — без UAC).
bool StartAppRouteService(std::wstring* error);
bool StopAppRouteService(std::wstring* error, DWORD waitMs = 15000);

// Установка (нужны права администратора): копирование файлов из sourceDir в
// InstallDirectory(), регистрация или обновление службы, ярлык «AppRoute» в меню «Пуск» для
// всех пользователей, запуск. Работающая служба сначала останавливается (её изменения
// откатываются).
//
// withDriver — заодно установить драйвер approute-wfp.sys из sourceDir (#18): правила тогда
// действуют для программ, запущенных любым способом. Драйвер не установился (нет файла,
// подпись не принята) — служба всё равно ставится, причина — в *driverNote.
bool InstallAppRouteService(const std::wstring& sourceDir, const std::wstring& configPath,
                            const std::wstring& clientSid, std::wstring* error, bool withDriver = false,
                            std::wstring* driverNote = nullptr);

// Удаление (нужны права администратора): остановка (откат изменений), удаление службы, драйвера,
// файлов и ярлыка. Занятые файлы удаляются при перезагрузке.
bool UninstallAppRouteService(std::wstring* error);

// Драйвер approute-wfp.sys (#18): копируется в InstallDirectory() (туда пишут только
// администраторы — иначе подмена файла дала бы код в ядре), служба драйвера с ручным запуском,
// запуск. Нужны права администратора; тестовая подпись загружается только в тестовом режиме.
inline constexpr wchar_t kDriverServiceName[] = L"approute-wfp";
bool InstallWfpDriver(const std::wstring& sysPath, std::wstring* error);
// Остановка и удаление службы драйвера и файла.
bool UninstallWfpDriver(std::wstring* error);

enum class WfpDriverState { NotInstalled, Stopped, Running };
WfpDriverState QueryWfpDriver();
// Запустить установленный драйвер (нужны права администратора). true — работает.
bool StartWfpDriver(std::wstring* error);

// Журнал службы: dir создаётся с доступом SYSTEM/администраторы (пользователи — чтение).
// Существующая папка с другим владельцем (её мог заранее создать кто угодно) отодвигается в
// сторону; файл-ссылка не открывается. nullptr — открыть безопасно не удалось.
HANDLE OpenProtectedLog(const std::wstring& dir, const std::wstring& file);

} // namespace approute
