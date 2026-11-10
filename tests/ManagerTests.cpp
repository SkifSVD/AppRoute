// Тесты запуска менеджера маршрутов из GUI (issue #15): политика из конфига, канал GUI ↔ менеджер.

#include "core/ConfigPolicy.h"
#include "core/ManagerPipe.h"
#include "core/Util.h"

#include "Test.h"

#include <objbase.h>

#include <format>

using namespace approute;

namespace {

NET_LUID Luid(ULONG64 v)
{
    NET_LUID l{};
    l.Value = v;
    return l;
}

NetAdapter Adapter(ULONG64 luid, const wchar_t* alias, const wchar_t* guid)
{
    NetAdapter a;
    a.luid = Luid(luid);
    a.alias = alias;
    CLSIDFromString(guid, &a.guid);
    a.operStatus = IfOperStatusUp;
    UnicastAddress u;
    u.address.si_family = AF_INET;
    u.address.Ipv4.sin_addr.s_addr = htonl(0x0A000000u + static_cast<ULONG>(luid));
    a.unicast.push_back(u);
    return a;
}

constexpr wchar_t kWifi[] = L"{22222222-0000-0000-0000-000000000001}";
constexpr wchar_t kHapp[] = L"{22222222-0000-0000-0000-000000000002}";
constexpr wchar_t kCorp[] = L"{22222222-0000-0000-0000-000000000003}";
constexpr wchar_t kGone[] = L"{22222222-0000-0000-0000-000000000009}";

std::vector<NetAdapter> Adapters()
{
    return {Adapter(1, L"wifi", kWifi), Adapter(2, L"happ", kHapp), Adapter(3, L"corp", kCorp)};
}

Rule MakeRule(const wchar_t* app, const wchar_t* adapter)
{
    Rule r;
    r.app = app;
    r.adapter = adapter;
    return r;
}

std::wstring ThisExe()
{
    std::wstring path(32768, L'\0');
    path.resize(GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size())));
    return path;
}

} // namespace

TEST(ConfigRoutesRoundTrip)
{
    std::wstring error;
    const auto parsed = ParseConfig(
        R"({"version":1,"routes":[{"prefix":"160.79.104.0/23","adapter":"{22222222-0000-0000-0000-000000000002}"}]})",
        &error);
    CHECK(parsed && parsed->routes.size() == 1);
    if (parsed) {
        CHECK(parsed->routes[0].prefix == L"160.79.104.0/23");
        const auto again = ParseConfig(SerializeConfig(*parsed), &error);
        CHECK(again && again->routes.size() == 1 && again->routes[0].adapter == kHapp);
    }
    // Ошибки — конфиг не читается (маршруты меняют сеть, молча пропускать нельзя)
    CHECK(!ParseConfig(R"({"routes":[{"prefix":"0.0.0.0/0","adapter":"{22222222-0000-0000-0000-000000000002}"}]})", &error));
    CHECK(!ParseConfig(R"({"routes":[{"prefix":"10.0.0.1/8","adapter":"{22222222-0000-0000-0000-000000000002}"}]})", &error));
    CHECK(!ParseConfig(R"({"routes":[{"prefix":"10.0.0.0/8","adapter":"happ"}]})", &error));
    CHECK(SerializeConfig(Config{}).find("routes") == std::string::npos);
}

TEST(PolicyFromConfigBasics)
{
    Config c;
    c.primary = kHapp;
    c.rules = {MakeRule(L"a.exe", kCorp), MakeRule(L"b.exe", kCorp), MakeRule(L"c.exe", kHapp),
               MakeRule(L"d.exe", kGone)};
    c.routes = {{L"160.79.104.0/23", kHapp}, {L"10.10.0.0/16", kGone}};
    RememberAdapter(c, {kGone, L"old-vpn", L""});

    const auto p = PolicyFromConfig(c, Adapters(), Luid(1), {Luid(1), Luid(2)});
    CHECK(p.policy.has_value());
    if (p.policy) {
        CHECK(p.policy->primary.Value == 2);
        // 0/0 — на интерфейсе правил, кроме основного; без дублей и отсутствующих
        CHECK(p.policy->ensureDefault.size() == 1 && p.policy->ensureDefault[0].Value == 3);
        CHECK(p.policy->pinned.size() == 1 && p.policy->pinned[0].luid.Value == 2);
    }
    // Подсеть за отсутствующим интерфейсом — пояснение с именем из истории
    bool noted = false;
    for (const auto& n : p.notes) {
        noted = noted || n.find(L"old-vpn") != std::wstring::npos;
    }
    CHECK(noted);

    // Тот же конфиг — та же политика; смена основного — другая
    const auto same = PolicyFromConfig(c, Adapters(), Luid(1), {Luid(1), Luid(2)});
    CHECK(same.policy && p.policy && SamePolicy(*same.policy, *p.policy));
    c.primary = L"auto";
    const auto other = PolicyFromConfig(c, Adapters(), Luid(1), {Luid(1), Luid(2)});
    CHECK(other.policy && p.policy && !SamePolicy(*other.policy, *p.policy));
    CHECK(other.policy && other.policy->ensureDefault.size() == 2);   // corp и happ
}

TEST(ManagerPipeRoundTrip)
{
    const std::wstring name = std::format(L"\\\\.\\pipe\\AppRoute.Test.{}", GetCurrentProcessId());
    const std::wstring self = ThisExe();
    ManagerPipeServer server(name, CurrentUserSid(), self, [](std::string_view request) {
        return std::string("{\"echo\":\"") + std::string(request) + "\"}";
    });
    std::wstring error;
    CHECK(server.Start(&error));

    // Тест не повышен: владельца-администратора не требуем, образ сервера — этот же exe
    const auto reply = CallManager(name, "STATUS", self, 3000, false);
    CHECK(reply.ok);
    CHECK(reply.text == "{\"echo\":\"STATUS\"}");
    const auto second = CallManager(name, "STOP", self, 3000, false);
    CHECK(second.ok && second.text == "{\"echo\":\"STOP\"}");

    // Требование владельца-администратора: канал обычного процесса отклоняется (подмена)
    const auto strict = CallManager(name, "STATUS", self, 3000, true);
    CHECK(!strict.ok && !strict.error.empty());

    // Второй сервер с тем же именем не создаётся (FILE_FLAG_FIRST_PIPE_INSTANCE)
    ManagerPipeServer squatter(name, CurrentUserSid(), self, [](std::string_view) { return std::string(); });
    CHECK(!squatter.Start(&error));
    server.Stop();

    CHECK(!CallManager(name, "STATUS", self, 500, false).ok);   // сервера нет
}

TEST(ManagerPipeRejectsOtherClient)
{
    const std::wstring name = std::format(L"\\\\.\\pipe\\AppRoute.Test2.{}", GetCurrentProcessId());
    ManagerPipeServer server(name, CurrentUserSid(), L"C:\\nowhere\\approute-gui.exe",
                             [](std::string_view) { return std::string("{\"ok\":true}"); });
    std::wstring error;
    CHECK(server.Start(&error));
    const auto reply = CallManager(name, "STOP", L"", 3000, false);
    CHECK(!reply.ok && reply.text.find("denied") != std::string::npos);
}
