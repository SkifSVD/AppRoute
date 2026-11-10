// Тесты глобального переключателя основного интерфейса (issue #14).

#include "core/PrimarySwitch.h"
#include "core/Util.h"

#include "Test.h"

#include <objbase.h>

#include <filesystem>
#include <fstream>

using namespace approute;

namespace {

NET_LUID Luid(ULONG64 v)
{
    NET_LUID l{};
    l.Value = v;
    return l;
}

NetAdapter Adapter(ULONG64 luid, const wchar_t* alias, const wchar_t* guid, bool up, const char* ipv4)
{
    NetAdapter a;
    a.luid = Luid(luid);
    a.alias = alias;
    CLSIDFromString(guid, &a.guid);
    a.operStatus = up ? IfOperStatusUp : IfOperStatusDown;
    if (ipv4) {
        UnicastAddress u;
        u.address.si_family = AF_INET;
        inet_pton(AF_INET, ipv4, &u.address.Ipv4.sin_addr);
        a.unicast.push_back(u);
    }
    return a;
}

constexpr wchar_t kWifi[] = L"{11111111-0000-0000-0000-000000000001}";
constexpr wchar_t kVpn[] = L"{11111111-0000-0000-0000-000000000002}";
constexpr wchar_t kApipa[] = L"{11111111-0000-0000-0000-000000000003}";
constexpr wchar_t kOff[] = L"{11111111-0000-0000-0000-000000000004}";

std::vector<NetAdapter> Adapters()
{
    return {
        Adapter(1, L"wifi", kWifi, true, "192.168.1.10"),
        Adapter(2, L"vpn", kVpn, true, "10.8.0.2"),
        Adapter(3, L"apipa", kApipa, true, "169.254.10.20"),
        Adapter(4, L"off", kOff, false, nullptr),
    };
}

} // namespace

TEST(PrimaryAuto)
{
    const auto c = ChoosePrimary(L"auto", Adapters(), Luid(1));
    CHECK(c.luid && c.luid->Value == 1 && !c.fallback && c.note.empty());
    const auto empty = ChoosePrimary(L"", Adapters(), Luid(1));
    CHECK(empty.luid && empty.luid->Value == 1);
    const auto none = ChoosePrimary(L"auto", Adapters(), std::nullopt);
    CHECK(!none.luid && !none.note.empty());
}

TEST(PrimaryChosenAdapter)
{
    const auto c = ChoosePrimary(kVpn, Adapters(), Luid(1));
    CHECK(c.luid && c.luid->Value == 2 && !c.fallback);
}

TEST(PrimaryFallback)
{
    // Отключён, только автоматический 169.254.x.x или нет в системе — автоматический выбор
    for (const wchar_t* guid : {kOff, kApipa, L"{99999999-0000-0000-0000-000000000000}"}) {
        const auto c = ChoosePrimary(guid, Adapters(), Luid(1));
        CHECK(c.luid && c.luid->Value == 1);
        CHECK(c.fallback && !c.note.empty());
    }
}

TEST(PrimaryConfigWatcher)
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / L"approute-tests-watch";
    fs::create_directories(dir);
    const fs::path file = dir / L"config.json";
    { std::ofstream(file) << "{}"; }

    FileChangeWatcher watcher(file.wstring());
    CHECK(watcher.Event() != nullptr);
    CHECK(WaitForSingleObject(watcher.Event(), 0) == WAIT_TIMEOUT);
    { std::ofstream(file) << "{\"primary\":\"auto\"}"; }
    CHECK(WaitForSingleObject(watcher.Event(), 2000) == WAIT_OBJECT_0);

    std::error_code ec;
    fs::remove_all(dir, ec);
}
