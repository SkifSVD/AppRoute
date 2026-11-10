// Тесты правки правил и запуска по правилу — общая логика GUI и консольных утилит (issue #12).

#include "core/Config.h"
#include "core/Launcher.h"

#include "Test.h"

using namespace approute;

namespace {

constexpr wchar_t kGuid[] = L"{0F5E9A5F-88C5-4844-9F4C-2037D5332075}";

Rule MakeRule(std::wstring app)
{
    Rule r;
    r.app = std::move(app);
    r.adapter = kGuid;
    return r;
}

} // namespace

TEST(RuleValidation)
{
    CHECK(!ValidateRule(MakeRule(L"C:\\Apps\\app.exe")));
    CHECK(!ValidateRule(MakeRule(L"telegram.exe")));
    CHECK(ValidateRule(MakeRule(L"")));
    CHECK(ValidateRule(MakeRule(L"C:\\Apps\\a*.exe")));
    CHECK(ValidateRule(MakeRule(L"\"C:\\Apps\\app.exe\"")));

    Rule noAdapter = MakeRule(L"app.exe");
    noAdapter.adapter = L"";
    CHECK(ValidateRule(noAdapter));
    noAdapter.adapter = L"happ-xray";   // имя, а не GUID
    CHECK(ValidateRule(noAdapter));
}

TEST(RuleDuplicates)
{
    Config c;
    c.rules = {MakeRule(L"C:\\Apps\\App.exe"), MakeRule(L"telegram.exe")};

    CHECK(FindDuplicateRule(c, L"c:\\apps\\app.exe") == 0u);
    CHECK(FindDuplicateRule(c, L"C:\\Apps\\.\\App.exe") == 0u);    // тот же путь после нормализации
    CHECK(FindDuplicateRule(c, L"TELEGRAM.EXE") == 1u);
    CHECK(!FindDuplicateRule(c, L"C:\\Other\\telegram.exe"));       // путь и имя — разные правила
    CHECK(!FindDuplicateRule(c, L"other.exe"));

    // При правке правило не считается дублем самого себя
    CHECK(!FindDuplicateRule(c, L"C:\\Apps\\App.exe", 0u));
    CHECK(FindDuplicateRule(c, L"telegram.exe", 0u) == 1u);
}

TEST(RuleCleanAppPath)
{
    CHECK(CleanAppPath(L"  C:\\Apps\\app.exe  ") == L"C:\\Apps\\app.exe");
    CHECK(CleanAppPath(L"\"C:\\Program Files\\App\\app.exe\"") == L"C:\\Program Files\\App\\app.exe");
    CHECK(CleanAppPath(L" \"x.exe\" ") == L"x.exe");
    CHECK(CleanAppPath(L"\"") == L"\"");
    CHECK(CleanAppPath(L"").empty());
}

TEST(RuleLaunchRequest)
{
    Rule r = MakeRule(L"app.exe");
    r.onUnavailable = OnUnavailable::Default;
    r.dns = DnsMode::System;
    r.ipv6 = Ipv6Mode::Block;
    r.includeChildren = false;

    const LaunchRequest q = RequestForRule(r, L"\"app.exe\" --x");
    CHECK(q.commandLine == L"\"app.exe\" --x");
    CHECK(q.adapterGuid == kGuid);
    CHECK(q.systemDns);
    CHECK(!q.includeChildren);
    CHECK(q.policy.onUnavailable == OnUnavailable::Default);
    CHECK(q.policy.ipv6 == Ipv6Mode::Block);
    CHECK(q.logPath.empty());
}

TEST(RuleCommandLine)
{
    CHECK(CommandLineForApp(L"C:\\Program Files\\App\\app.exe") == L"\"C:\\Program Files\\App\\app.exe\"");
    wchar_t windir[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemRoot", windir, MAX_PATH);
    CHECK(CommandLineForApp(L"%SystemRoot%\\notepad.exe") == L"\"" + std::wstring(windir) + L"\\notepad.exe\"");
}
