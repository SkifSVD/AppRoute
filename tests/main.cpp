// approute-tests — модульные тесты без сторонних фреймворков (запуск: ctest или напрямую).

#include "core/Config.h"
#include "core/Json.h"
#include "core/Policy.h"
#include "core/Util.h"

#include "Test.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace approute;
using approute::test::Failures;
using approute::test::Registry;

namespace {

constexpr char kGuid[] = "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}";

// ---- JSON ------------------------------------------------------------------

TEST(JsonParsesScalars)
{
    CHECK(json::Parse("null")->IsNull());
    CHECK(json::Parse("true")->AsBool());
    CHECK(!json::Parse(" false ")->AsBool());
    CHECK(json::Parse("-12.5e1")->AsNumber() == -125.0);
    CHECK(json::Parse("0")->AsNumber() == 0.0);
    CHECK(json::Parse("\"a\\\"b\\\\c\\n\"")->AsString() == "a\"b\\c\n");
}

TEST(JsonParsesUnicodeEscapes)
{
    CHECK(json::Parse("\"\\u0416\"")->AsString() == "\xD0\x96");                 // Ж
    CHECK(json::Parse("\"\\ud83d\\ude00\"")->AsString() == "\xF0\x9F\x98\x80");  // 😀
    CHECK(json::Parse("\"\xD0\x96\"")->AsString() == "\xD0\x96");                // UTF-8 как есть
    CHECK(!json::Parse("\"\\ud83d\""));                                          // непарный суррогат
}

TEST(JsonParsesNested)
{
    const auto v = json::Parse("\xEF\xBB\xBF{\"a\": [1, {\"b\": null}], \"c\": {}}");
    CHECK(v && v->IsObject());
    CHECK(v->Find("a")->AsArray().size() == 2);
    CHECK(v->Find("a")->AsArray()[1].Find("b")->IsNull());
    CHECK(v->Find("c")->AsObject().empty());
    CHECK(v->Find("missing") == nullptr);
}

TEST(JsonRejectsInvalid)
{
    for (const char* bad : {"", "{", "[1,]", "{\"a\":1,}", "01", "1.", "-", "tru", "\"a", "{\"a\" 1}",
                            "[1] 2", "{\"a\":1,\"a\":2}", "\"\x01\"", "NaN", "1e999", "// x\n1"}) {
        json::ParseError error;
        const bool parsed = json::Parse(bad, &error).has_value();
        CHECK(!parsed);
        CHECK(!error.message.empty());
    }
}

TEST(JsonReportsPosition)
{
    json::ParseError error;
    CHECK(!json::Parse("{\n  \"a\": tru\n}", &error));
    CHECK(error.line == 2);
    CHECK(error.column == 8);
}

TEST(JsonRejectsDeepNesting)
{
    CHECK(!json::Parse(std::string(1000, '[') + std::string(1000, ']')));
    CHECK(json::Parse(std::string(32, '[') + std::string(32, ']')));
}

TEST(JsonRoundTrip)
{
    const char* text = "{\"s\":\"x\\\"\\n\\u0001\xD0\x96\",\"n\":[0,1.5,-3,1e+20],\"b\":true,\"z\":null,\"o\":{}}";
    const auto v = json::Parse(text);
    CHECK(v.has_value());
    const std::string compact = json::Serialize(*v, 0);
    CHECK(compact == text);
    const auto again = json::Parse(json::Serialize(*v, 2));
    CHECK(again && json::Serialize(*again, 0) == compact);
}

// ---- Config ----------------------------------------------------------------

std::string RuleObject(const std::string& fields)
{
    return std::string("{\"app\":\"C:\\\\Apps\\\\a.exe\",\"target\":{\"type\":\"adapter\",\"id\":\"") + kGuid +
           "\"}" + fields + "}";
}

std::string RuleJson(const std::string& fields)
{
    return "{\"version\":1,\"rules\":[" + RuleObject(fields) + "]}";
}

TEST(ConfigParsesDefaults)
{
    std::wstring error;
    const auto config = ParseConfig(RuleJson(""), &error);
    CHECK(config.has_value());
    CHECK(config->primary == L"auto");
    CHECK(config->rules.size() == 1);
    const Rule& r = config->rules[0];
    CHECK(r.app == L"C:\\Apps\\a.exe");
    CHECK(r.adapter == L"{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}");
    CHECK(r.onUnavailable == OnUnavailable::Block);
    CHECK(r.dns == DnsMode::Adapter);
    CHECK(r.ipv6 == Ipv6Mode::Follow);
    CHECK(r.includeChildren);
}

TEST(ConfigParsesOptions)
{
    std::wstring error;
    const auto config = ParseConfig(
        RuleJson(",\"onUnavailable\":\"default\",\"dns\":\"system\",\"ipv6\":\"block\",\"includeChildren\":false,\"future\":1"),
        &error);
    CHECK(config.has_value());
    const Rule& r = config->rules[0];
    CHECK(r.onUnavailable == OnUnavailable::Default);
    CHECK(r.dns == DnsMode::System);
    CHECK(r.ipv6 == Ipv6Mode::Block);
    CHECK(!r.includeChildren);
}

TEST(ConfigNormalizesGuid)
{
    std::wstring error;
    const auto config = ParseConfig(
        "{\"primary\":\"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\"}", &error);
    CHECK(config && config->primary == L"{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}");
    CHECK(!NormalizeGuid(L"{not-a-guid}"));
    CHECK(!NormalizeGuid(L"Wi-Fi"));
}

TEST(ConfigEmptyIsValid)
{
    std::wstring error;
    const auto config = ParseConfig("{}", &error);
    CHECK(config && config->rules.empty() && config->primary == L"auto");
}

TEST(ConfigRejectsInvalid)
{
    const std::vector<std::string> bad = {
        "[]",
        "{\"version\":2}",
        "{\"version\":1.5}",
        "{\"primary\":\"Wi-Fi\"}",
        "{\"rules\":{}}",
        "{\"rules\":[{\"target\":{\"type\":\"adapter\",\"id\":\"" + std::string(kGuid) + "\"}}]}",
        "{\"rules\":[{\"app\":\"a.exe\"}]}",
        "{\"rules\":[{\"app\":\"a.exe\",\"target\":{\"type\":\"proxy\",\"id\":\"x\"}}]}",
        "{\"rules\":[{\"app\":\"a.exe\",\"target\":{\"type\":\"adapter\",\"id\":\"Wi-Fi\"}}]}",
        RuleJson(",\"onUnavailable\":\"maybe\""),
        RuleJson(",\"dns\":true"),
        RuleJson(",\"includeChildren\":\"yes\""),
        "{\"rules\":[" + RuleObject("") + "," + RuleObject("") + "]}",   // повторное правило
    };
    for (const auto& text : bad) {
        std::wstring error;
        const bool parsed = ParseConfig(text, &error).has_value();
        if (parsed) {
            std::printf("  accepted: %s\n", text.c_str());
        }
        CHECK(!parsed);
        CHECK(!error.empty());
    }
}

TEST(ConfigRoundTrip)
{
    Config config;
    config.primary = L"{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}";
    Rule a;
    a.app = L"C:\\Program Files\\Приложение\\app.exe";
    a.adapter = config.primary;
    a.onUnavailable = OnUnavailable::Default;
    a.ipv6 = Ipv6Mode::Default;
    Rule b;
    b.app = L"telegram.exe";
    b.adapter = config.primary;
    b.dns = DnsMode::System;
    b.includeChildren = false;
    config.rules = {a, b};

    std::wstring error;
    const auto parsed = ParseConfig(SerializeConfig(config), &error);
    CHECK(parsed.has_value());
    CHECK(parsed->primary == config.primary);
    CHECK(parsed->rules.size() == 2);
    CHECK(parsed->rules[0].app == a.app);
    CHECK(parsed->rules[0].onUnavailable == OnUnavailable::Default);
    CHECK(parsed->rules[0].ipv6 == Ipv6Mode::Default);
    CHECK(parsed->rules[1].dns == DnsMode::System);
    CHECK(!parsed->rules[1].includeChildren);
}

TEST(ConfigFindRule)
{
    Config config;
    Rule byName;
    byName.app = L"app.exe";
    Rule byPath;
    byPath.app = L"C:\\Apps\\App.EXE";
    Rule other;
    other.app = L"%SystemRoot%\\System32\\curl.exe";
    config.rules = {byName, byPath, other};

    CHECK(FindRule(config, L"c:\\apps\\app.exe") == &config.rules[1]);    // путь важнее имени
    CHECK(FindRule(config, L"D:\\Other\\APP.exe") == &config.rules[0]);   // по имени файла
    CHECK(FindRule(config, L"C:\\Apps\\..\\Apps\\app.exe") == &config.rules[1]);
    CHECK(FindRule(config, L"C:\\Windows\\System32\\curl.exe") == &config.rules[2]);
    CHECK(FindRule(config, L"C:\\Apps\\other.exe") == nullptr);
}

TEST(ConfigLoadSave)
{
    wchar_t temp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp);
    const std::wstring dir = std::wstring(temp) + L"approute-tests-" + std::to_wstring(GetCurrentProcessId());
    const std::wstring path = dir + L"\\sub\\config.json";

    std::wstring error;
    const auto missing = LoadConfig(path, &error);
    CHECK(missing && missing->rules.empty());   // нет файла — пустой конфиг

    Config config;
    Rule r;
    r.app = L"app.exe";
    r.adapter = L"{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}";
    config.rules = {r};
    CHECK(SaveConfig(path, config, &error));
    const auto loaded = LoadConfig(path, &error);
    CHECK(loaded && loaded->rules.size() == 1 && loaded->rules[0].app == L"app.exe");
    CHECK(GetFileAttributesW((path + L".tmp").c_str()) == INVALID_FILE_ATTRIBUTES);

    DeleteFileW(path.c_str());
    RemoveDirectoryW((dir + L"\\sub").c_str());
    RemoveDirectoryW(dir.c_str());
}

// ---- Политика при недоступном интерфейсе (#9) --------------------------------

TEST(PolicyDefaultsToBlock)
{
    const UnavailablePolicy p;
    CHECK(!p.UseDefaultRoute(false));
    CHECK(!p.UseDefaultRoute(true));
    CHECK(!p.UseSystemDns());
}

TEST(PolicyIpv6FollowsOnUnavailable)
{
    UnavailablePolicy p;
    p.onUnavailable = OnUnavailable::Default;
    CHECK(p.UseDefaultRoute(false));
    CHECK(p.UseDefaultRoute(true));
    CHECK(p.UseSystemDns());
    p.ipv6 = Ipv6Mode::Block;
    CHECK(p.UseDefaultRoute(false));
    CHECK(!p.UseDefaultRoute(true));
}

TEST(PolicyIpv6OverridesBlock)
{
    UnavailablePolicy p;
    p.ipv6 = Ipv6Mode::Default;   // IPv4 блокируется, IPv6 без адреса — маршрутом по умолчанию
    CHECK(!p.UseDefaultRoute(false));
    CHECK(p.UseDefaultRoute(true));
    CHECK(!p.UseSystemDns());
}

TEST(PolicyEnvironmentRoundTrip)
{
    for (const auto on : {OnUnavailable::Block, OnUnavailable::Default}) {
        for (const auto v6 : {Ipv6Mode::Follow, Ipv6Mode::Block, Ipv6Mode::Default}) {
            const wchar_t* a = OnUnavailableEnvValue(on);
            const wchar_t* b = Ipv6EnvValue(v6);
            const auto p = ParsePolicy(a ? a : L"", b ? b : L"");
            CHECK(p.onUnavailable == on);
            CHECK(p.ipv6 == v6);
        }
    }
    const auto junk = ParsePolicy(L"maybe", L"sometimes");   // мусор — безопасное значение
    CHECK(junk.onUnavailable == OnUnavailable::Block && junk.ipv6 == Ipv6Mode::Follow);
}

TEST(Utf8Conversions)
{
    CHECK(ToUtf8(L"Ж") == "\xD0\x96");
    CHECK(FromUtf8("\xD0\x96") == std::wstring(L"Ж"));
    CHECK(!FromUtf8("\xFF\xFE"));
    CHECK(FromUtf8("") == std::wstring());
}

} // namespace

int main()
{
    int failedTests = 0;
    for (const auto& test : Registry()) {
        const int before = Failures();
        test.body();
        const bool ok = Failures() == before;
        failedTests += ok ? 0 : 1;
        std::printf("%s %s\n", ok ? "[ OK ]" : "[FAIL]", test.name);
    }
    std::printf("\n%zu tests, %d failed\n", Registry().size(), failedTests);
    return failedTests == 0 ? 0 : 1;
}
