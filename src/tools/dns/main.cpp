// approute-dns — проверка разрешения имён через выбранный интерфейс (тот же резолвер, что в hook-DLL).
//
//   approute-dns --adapter <интерфейс> <имя> [<имя>...]

#include "core/DnsResolver.h"
#include "core/NetAdapters.h"
#include "core/Util.h"

#include <format>
#include <string>
#include <string_view>
#include <vector>

using namespace approute;

namespace {

void Line(std::wstring_view text)
{
    std::wstring s(text);
    s += L"\n";
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        WriteConsoleW(h, s.data(), static_cast<DWORD>(s.size()), &written, nullptr);
        return;
    }
    const int len = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    std::string utf8(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), utf8.data(), len, nullptr, nullptr);
    WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc < 4 || std::wstring_view(argv[1]) != L"--adapter") {
        Line(L"approute-dns --adapter IF ИМЯ [ИМЯ...]");
        return 1;
    }
    const auto adapters = EnumerateAdapters();
    const auto* adapter = FindAdapter(adapters, argv[2]);
    if (!adapter) {
        Line(std::format(L"Ошибка: интерфейс «{}» не найден", argv[2]));
        return 1;
    }
    const auto iface = MakeDnsInterface(*adapter);
    Line(std::format(L"[{}] ifIndex {}, DNS-серверов: {}, IPv4: {}, IPv6: {}", adapter->alias, iface.ifIndex,
                     iface.dnsServers.size(), iface.hasIpv4, iface.hasIpv6));
    const auto doh = DefaultDohServers();

    for (int i = 3; i < argc; ++i) {
        const ULONGLONG start = GetTickCount64();
        const auto a = ResolveViaInterface(argv[i], AF_UNSPEC, iface, doh);
        const auto ms = GetTickCount64() - start;
        std::wstring list;
        for (const auto& addr : a.addresses) {
            list += (list.empty() ? L"" : L", ") + FormatAddress(addr);
        }
        const wchar_t* outcome = a.outcome == DnsOutcome::Resolved ? L"ok"
                               : a.outcome == DnsOutcome::NoSuchName ? L"нет такого имени" : L"ошибка";
        Line(std::format(L"{}: {} через {} за {} мс, TTL {} — {}{}", argv[i], outcome, a.via, ms, a.ttl, list,
                         a.lastError ? std::format(L" (последняя ошибка {})", a.lastError) : std::wstring()));
    }
    return 0;
}
