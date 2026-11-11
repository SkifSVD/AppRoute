#pragma once

// Приложения из пакетов MSIX и Microsoft Store (#45).
//
// Правило для такого приложения хранит не путь к exe (он меняется с каждым обновлением пакета),
// а идентификатор приложения AUMID: "СемействоПакета!IdПриложения", например
// "Claude_pzs8sxrjxfjjc!Claude". Подходят только приложения полного доверия
// (Windows.FullTrustApplication): обычные программы Win32, упакованные в MSIX.
//
// Правило применяется двумя способами:
// - драйвер WFP (#18): программа определяется по образу, запущена она любым способом; путь к
//   exe находится по пакету, установленному у пользователя, при каждом применении правил;
// - hook-DLL при запуске через AppRoute (#59): документированный механизм отладки пакетов
//   Windows (IPackageDebugSettings) — см. LaunchWithRule.

#include "core/Win.h"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace approute {

// Приложение из манифеста пакета (AppxManifest.xml)
struct ManifestApp {
    std::wstring id;            // "Claude"
    std::wstring executable;    // относительно папки пакета: "app\\Claude.exe"
    std::wstring displayName;   // как в манифесте; бывает ссылкой "ms-resource:..."
    bool fullTrust = false;     // EntryPoint="Windows.FullTrustApplication" или RuntimeBehavior Win32
    bool listed = true;         // есть в меню «Пуск» (AppListEntry не "none")
};

// Приложение пакета, установленного у текущего пользователя, — для мастера
struct PackagedApp {
    std::wstring app;          // AUMID "Семейство!Id"
    std::wstring name;         // имя из меню «Пуск»
    std::wstring executable;   // полный путь к exe текущей версии
};

// Исполняемые файлы приложения в установленной версии пакета
struct PackageExecutables {
    std::wstring main;                  // exe самого приложения
    std::vector<std::wstring> helpers;  // exe других приложений полного доверия того же пакета
};

// Значение поля app правила — AUMID пакетного приложения, а не путь и не имя файла
bool IsPackageApp(std::wstring_view app);
std::wstring_view PackageFamilyOf(std::wstring_view app);   // до '!'
std::wstring_view PackageAppIdOf(std::wstring_view app);    // после '!'

// Разбор манифеста (UTF-16). Ошибка разбора — пусто.
std::vector<ManifestApp> ParseAppxManifest(std::wstring_view xml);

// Приложения полного доверия из меню «Пуск» в пакетах текущего пользователя, кроме системных
// компонентов Windows; по имени.
std::vector<PackagedApp> EnumeratePackagedApps();

// Exe приложения в пакете, установленном у пользователя userSid (пусто — у текущего; для
// другого пользователя нужны права администратора). nullopt и описание — пакета нет, приложение
// не полного доверия и т.п.
std::optional<PackageExecutables> FindPackageExecutables(std::wstring_view app, const std::wstring& userSid,
                                                         std::wstring* error);

// Установленная у текущего пользователя версия пакета приложения
struct InstalledPackage {
    std::wstring fullName;        // полное имя пакета (с версией и архитектурой)
    std::wstring installedPath;   // папка пакета
    PackageExecutables executables;
};
std::optional<InstalledPackage> FindInstalledPackage(std::wstring_view app, std::wstring* error);

// Полное имя пакета процесса; пусто — процесс не из пакета
std::wstring ProcessPackageFullName(HANDLE process);

// Имя приложения из меню «Пуск» текущего пользователя; не найдено — сам AUMID
std::wstring PackagedAppName(std::wstring_view app);

// Запуск штатной активацией Windows (как из меню «Пуск»), без внедрения
bool LaunchPackagedApp(std::wstring_view app, const std::wstring& arguments, DWORD* processId,
                       std::wstring* error);

} // namespace approute
