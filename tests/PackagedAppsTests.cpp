// Тесты приложений из пакетов MSIX (issues #45, #59).

#include "core/Launcher.h"
#include "core/PackagedApps.h"
#include "core/Shortcuts.h"
#include "core/WfpPlan.h"

#include "Test.h"

using namespace approute;

namespace {

constexpr wchar_t kVpn[] = L"{33333333-0000-0000-0000-000000000001}";

constexpr wchar_t kManifest[] =
    LR"(<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:uap10="http://schemas.microsoft.com/appx/manifest/uap/windows10/10">
  <Applications>
    <Application Id="Main" Executable="app\Main.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Главное" Square44x44Logo="a.png" />
    </Application>
    <Application Id="Helper" Executable="app/helper.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="ms-resource:Helper" AppListEntry="none" />
    </Application>
    <Application Id="Tool" Executable="tool.exe" uap10:RuntimeBehavior="win32App" uap10:TrustLevel="mediumIL">
      <uap:VisualElements DisplayName="Tool" />
    </Application>
    <Application Id="Store" Executable="Store.exe" EntryPoint="Store.App">
      <uap:VisualElements DisplayName="Store" />
    </Application>
  </Applications>
</Package>)";

} // namespace

TEST(PackageAppIdentity)
{
    CHECK(IsPackageApp(L"Claude_pzs8sxrjxfjjc!Claude"));
    CHECK(IsPackageApp(L"Microsoft.WindowsTerminal_8wekyb3d8bbwe!App"));
    CHECK(PackageFamilyOf(L"Claude_pzs8sxrjxfjjc!Claude") == L"Claude_pzs8sxrjxfjjc");
    CHECK(PackageAppIdOf(L"Claude_pzs8sxrjxfjjc!Claude") == L"Claude");

    CHECK(!IsPackageApp(L"claude.exe"));
    CHECK(!IsPackageApp(L"C:\\Apps\\a_pzs8sxrjxfjjc!b"));
    CHECK(!IsPackageApp(L"Claude_pzs8sxrjxfjjc"));          // без приложения
    CHECK(!IsPackageApp(L"Claude_short!Claude"));           // не Id издателя
    CHECK(!IsPackageApp(L"Claude_pzs8sxrjxfjjc!"));
    CHECK(!IsPackageApp(L"Claude_pzs8sxrjxfjjc!a b"));
    CHECK(!IsPackageApp(L"odd_pzs8sxrjxfjjc!name.exe"));    // имя файла с '!'
}

TEST(PackageManifestParse)
{
    const auto apps = ParseAppxManifest(kManifest);
    CHECK(apps.size() == 4);
    if (apps.size() != 4) {
        return;
    }
    CHECK(apps[0].id == L"Main" && apps[0].executable == L"app\\Main.exe");
    CHECK(apps[0].fullTrust && apps[0].listed && apps[0].displayName == L"Главное");
    CHECK(apps[1].fullTrust && !apps[1].listed);
    CHECK(apps[2].fullTrust);       // uap10:RuntimeBehavior="win32App"
    CHECK(!apps[3].fullTrust);      // UWP

    CHECK(ParseAppxManifest(L"<not xml").empty());
}

TEST(PackageRuleChecks)
{
    Rule r;
    r.app = L"Claude_pzs8sxrjxfjjc!Claude";
    r.adapter = kVpn;
    CHECK(!ValidateRule(r));
    r.adapter.clear();
    r.proxy = L"127.0.0.1:10808";   // прокси — при запуске через AppRoute (#59)
    CHECK(!ValidateRule(r));

    // Ярлык AppRoute для приложения из пакета (#59): --run AUMID, значок — exe пакета
    std::wstring error;
    const auto spec = LaunchShortcutFor(r, L"C:\\AR\\approute-gui.exe", L"", &error, L"C:\\Pkg\\app\\Claude.exe");
    CHECK(spec.has_value());
    if (spec) {
        CHECK(spec->target == L"C:\\AR\\approute-gui.exe");
        CHECK(spec->arguments == L"--run Claude_pzs8sxrjxfjjc!Claude");
        CHECK(spec->iconPath == L"C:\\Pkg\\app\\Claude.exe");
    }
    const auto noIcon = LaunchShortcutFor(r, L"C:\\AR\\approute-gui.exe", L"", &error);
    CHECK(noIcon && noIcon->iconPath == L"C:\\AR\\approute-gui.exe");
    CHECK(LaunchShortcutFileName(r) == L"Claude (AppRoute).lnk");
    CHECK(LaunchShortcutFileName(r, L"Claude: чат") == L"Claude_ чат (AppRoute).lnk");
}

TEST(PackageLaunchRequest)
{
    Rule r;
    r.app = L"Claude_pzs8sxrjxfjjc!Claude";
    r.proxy = L"127.0.0.1:10808";
    const LaunchRequest q = RequestForRule(r, L"\"Claude_pzs8sxrjxfjjc!Claude\" --flag \"a b\"");
    CHECK(q.packageApp == r.app);
    CHECK(q.packageArguments == L"--flag \"a b\"");
    CHECK(q.proxy == r.proxy);
    CHECK(RequestForRule(r, L"Claude_pzs8sxrjxfjjc!Claude").packageArguments.empty());

    r.app = L"C:\\Apps\\app.exe";   // обычная программа — без пакета
    CHECK(RequestForRule(r, L"\"C:\\Apps\\app.exe\"").packageApp.empty());

    CHECK(ArgumentsAfterProgram(L"prog.exe  -x") == L"-x");
    CHECK(ArgumentsAfterProgram(L"\"C:\\a b\\p.exe\"") == L"");
}

TEST(PackageWfpPlan)
{
    Config c;
    Rule r;
    r.app = L"Claude_pzs8sxrjxfjjc!Claude";
    r.adapter = kVpn;
    c.rules = {r};

    PackageExecutables exes;
    exes.main = L"C:\\Program Files\\WindowsApps\\Claude_1.0_x64__pzs8sxrjxfjjc\\app\\Claude.exe";
    exes.helpers = {L"C:\\Program Files\\WindowsApps\\Claude_1.0_x64__pzs8sxrjxfjjc\\app\\helper.exe"};
    const auto found = [&](std::wstring_view, std::wstring*) -> std::optional<PackageExecutables> { return exes; };

    WfpPlan plan = WfpPlanFromConfig(c, {}, L"S-1-5-21-1-2-3-1001", found);
    CHECK(plan.filters.size() == 2 && plan.notes.empty());
    if (plan.filters.size() == 2) {
        CHECK(plan.filters[0].appPath == exes.main && plan.filters[0].app == r.app);
        CHECK(plan.filters[1].appPath == exes.helpers[0]);
    }

    c.rules[0].includeChildren = false;   // только само приложение
    plan = WfpPlanFromConfig(c, {}, L"S-1-5-21-1-2-3-1001", found);
    CHECK(plan.filters.size() == 1);

    // Пакет не установлен / поиск недоступен — заметка вместо фильтра
    const auto missing = [](std::wstring_view, std::wstring* error) -> std::optional<PackageExecutables> {
        *error = L"пакет не установлен у пользователя";
        return std::nullopt;
    };
    plan = WfpPlanFromConfig(c, {}, L"S-1-5-21-1-2-3-1001", missing);
    CHECK(plan.filters.empty() && plan.notes.size() == 1);
    plan = WfpPlanFromConfig(c, {}, L"S-1-5-21-1-2-3-1001");
    CHECK(plan.filters.empty() && plan.notes.size() == 1);
}
