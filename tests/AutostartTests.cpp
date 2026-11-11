// Тесты автозапуска программ через AppRoute при входе в Windows (issue #60).

#include "core/Autostart.h"
#include "core/Config.h"

#include "Test.h"

using namespace approute;

namespace {

Rule MakeRule(std::wstring app)
{
    Rule r;
    r.app = std::move(app);
    r.adapter = L"{0F5E9A5F-88C5-4844-9F4C-2037D5332075}";
    return r;
}

} // namespace

TEST(AutostartConfigField)
{
    Config c;
    c.rules = {MakeRule(L"C:\\Apps\\a.exe"), MakeRule(L"C:\\Apps\\b.exe")};
    c.rules[1].autostart = true;
    CHECK(AutostartWanted(c));

    const std::string text = SerializeConfig(c);
    CHECK(text.find("\"autostart\": true") != std::string::npos || text.find("\"autostart\":true") != std::string::npos);
    std::wstring error;
    const auto parsed = ParseConfig(text, &error);
    CHECK(parsed.has_value());
    if (parsed) {
        CHECK(!parsed->rules[0].autostart && parsed->rules[1].autostart);
    }
    c.rules[1].autostart = false;
    CHECK(!AutostartWanted(c));
    CHECK(SerializeConfig(c).find("autostart") == std::string::npos);   // выключенный не пишется

    const auto bad = ParseConfig(
        R"({"version":1,"rules":[{"app":"C:\\a.exe","target":{"type":"adapter","id":"{0F5E9A5F-88C5-4844-9F4C-2037D5332075}"},"autostart":"yes"}]})",
        &error);
    CHECK(!bad.has_value() && error.find(L"autostart") != std::wstring::npos);
}

TEST(AutostartRuleValidation)
{
    Rule r = MakeRule(L"telegram.exe");   // только имя файла — запускать при входе нечего
    r.autostart = true;
    CHECK(ValidateRule(r).has_value());
    r.app = L"C:\\Apps\\Telegram.exe";
    CHECK(!ValidateRule(r));
    r.app = L"Claude_pzs8sxrjxfjjc!Claude";   // приложение из пакета (#59)
    CHECK(!ValidateRule(r));
}

TEST(AutostartCommandLine)
{
    CHECK(AutostartCommand(L"C:\\AR\\approute-gui.exe", L"") == L"\"C:\\AR\\approute-gui.exe\" --autostart");
    CHECK(AutostartCommand(L"C:\\AR\\approute-gui.exe", DefaultConfigPath()) ==
          L"\"C:\\AR\\approute-gui.exe\" --autostart");
    CHECK(AutostartCommand(L"C:\\AR\\approute-gui.exe", L"D:\\my rules.json") ==
          L"\"C:\\AR\\approute-gui.exe\" --config \"D:\\my rules.json\" --autostart");
}

TEST(AutostartOwnEntryMatch)
{
    CHECK(ProgramOfCommand(L"\"C:\\Program Files\\App\\app.exe\" --minimized") == L"C:\\Program Files\\App\\app.exe");
    CHECK(ProgramOfCommand(L"C:\\Program Files\\App\\app.exe -m") == L"C:\\Program Files\\App\\app.exe");
    CHECK(ProgramOfCommand(L"  tool -x") == L"tool");

    const Rule full = MakeRule(L"C:\\Program Files\\App\\App.exe");
    CHECK(CommandMatchesRule(full, L"\"c:\\program files\\app\\app.exe\" --autostart"));
    CHECK(!CommandMatchesRule(full, L"\"C:\\Other\\app.exe\""));

    const Rule byName = MakeRule(L"Telegram.exe");   // имя файла — в любом каталоге
    CHECK(CommandMatchesRule(byName, L"\"D:\\Tg\\telegram.exe\" -startintray"));
    CHECK(!CommandMatchesRule(byName, L"\"D:\\Tg\\Updater.exe\""));

    CHECK(!CommandMatchesRule(MakeRule(L"Claude_pzs8sxrjxfjjc!Claude"), L"\"C:\\x\\claude.exe\""));
}
