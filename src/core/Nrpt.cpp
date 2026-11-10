#include "core/Nrpt.h"

#include <algorithm>
#include <cwctype>

namespace approute {

namespace {

constexpr DWORD kConfigGenericDnsServers = 0x8;   // ConfigOptions: правило задаёт DNS-серверы

std::wstring Lower(std::wstring_view s)
{
    std::wstring out(s);
    std::transform(out.begin(), out.end(), out.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return out;
}

std::wstring_view Trim(std::wstring_view s)
{
    while (!s.empty() && std::iswspace(s.front())) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::iswspace(s.back())) {
        s.remove_suffix(1);
    }
    return s;
}

bool ParseAddress(std::wstring_view text, SOCKADDR_INET& out)
{
    const std::wstring s(text);
    out = {};
    if (InetPtonW(AF_INET, s.c_str(), &out.Ipv4.sin_addr) == 1) {
        out.Ipv4.sin_family = AF_INET;
        return true;
    }
    if (InetPtonW(AF_INET6, s.c_str(), &out.Ipv6.sin6_addr) == 1) {
        out.Ipv6.sin6_family = AF_INET6;
        return true;
    }
    return false;
}

// Длина совпадения пространства ns с именем name (оба в нижнем регистре, без точки в конце);
// 0 — не совпало. "." совпадает со всем с минимальным приоритетом.
size_t MatchLength(const std::wstring& ns, const std::wstring& name)
{
    if (ns == L".") {
        return 1;
    }
    if (ns.size() > 1 && ns.front() == L'.') {
        const std::wstring_view bare(ns.data() + 1, ns.size() - 1);
        if (name == bare) {
            return ns.size();
        }
        if (name.size() > ns.size() && name.compare(name.size() - ns.size(), ns.size(), ns) == 0) {
            return ns.size();
        }
        return 0;
    }
    return name == ns ? ns.size() + 1 : 0;   // точное имя точнее суффикса той же длины
}

std::wstring ReadString(HKEY key, const wchar_t* value, DWORD type)
{
    DWORD actual = 0;
    DWORD bytes = 0;
    if (RegQueryValueExW(key, value, nullptr, &actual, nullptr, &bytes) != ERROR_SUCCESS || actual != type || bytes == 0) {
        return {};
    }
    std::wstring data(bytes / sizeof(wchar_t) + 1, L'\0');
    if (RegQueryValueExW(key, value, nullptr, nullptr, reinterpret_cast<BYTE*>(data.data()), &bytes) != ERROR_SUCCESS) {
        return {};
    }
    data.resize(bytes / sizeof(wchar_t));
    return data;
}

std::vector<NrptRule> LoadFrom(const wchar_t* path)
{
    std::vector<NrptRule> rules;
    HKEY root = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &root) != ERROR_SUCCESS) {
        return rules;
    }
    for (DWORD i = 0;; ++i) {
        wchar_t sub[256];
        DWORD len = static_cast<DWORD>(std::size(sub));
        if (RegEnumKeyExW(root, i, sub, &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            break;
        }
        HKEY key = nullptr;
        if (RegOpenKeyExW(root, sub, 0, KEY_READ, &key) != ERROR_SUCCESS) {
            continue;
        }
        DWORD options = 0;
        DWORD size = sizeof(options);
        DWORD type = 0;
        const bool hasOptions = RegQueryValueExW(key, L"ConfigOptions", nullptr, &type,
                                                 reinterpret_cast<BYTE*>(&options), &size) == ERROR_SUCCESS &&
                                type == REG_DWORD;
        if (!hasOptions || (options & kConfigGenericDnsServers)) {
            std::vector<std::wstring> names;
            const std::wstring multi = ReadString(key, L"Name", REG_MULTI_SZ);
            for (size_t pos = 0; pos < multi.size();) {
                const size_t end = multi.find(L'\0', pos);
                const size_t stop = end == std::wstring::npos ? multi.size() : end;
                if (stop > pos) {
                    names.emplace_back(multi, pos, stop - pos);
                }
                pos = stop + 1;
            }
            NrptRule rule = MakeNrptRule(names, ReadString(key, L"GenericDNSServers", REG_SZ));
            if (!rule.namespaces.empty() && !rule.servers.empty()) {
                rules.push_back(std::move(rule));
            }
        }
        RegCloseKey(key);
    }
    RegCloseKey(root);
    return rules;
}

} // namespace

NrptRule MakeNrptRule(const std::vector<std::wstring>& names, std::wstring_view servers)
{
    NrptRule rule;
    for (const auto& n : names) {
        std::wstring ns = Lower(Trim(n));
        while (ns.size() > 1 && ns.back() == L'.') {
            ns.pop_back();
        }
        if (!ns.empty()) {
            rule.namespaces.push_back(std::move(ns));
        }
    }
    while (!servers.empty()) {
        const size_t sep = servers.find_first_of(L";, ");
        const std::wstring_view item = Trim(servers.substr(0, sep));
        SOCKADDR_INET a{};
        if (!item.empty() && ParseAddress(item, a)) {
            rule.servers.push_back(a);
        }
        if (sep == std::wstring_view::npos) {
            break;
        }
        servers.remove_prefix(sep + 1);
    }
    return rule;
}

const NrptRule* MatchNrpt(const std::vector<NrptRule>& rules, std::wstring_view name)
{
    std::wstring n = Lower(Trim(name));
    while (!n.empty() && n.back() == L'.') {
        n.pop_back();
    }
    if (n.empty()) {
        return nullptr;
    }
    const NrptRule* best = nullptr;
    size_t bestLen = 0;
    for (const auto& r : rules) {
        for (const auto& ns : r.namespaces) {
            const size_t len = MatchLength(ns, n);
            if (len > bestLen) {
                bestLen = len;
                best = &r;
            }
        }
    }
    return best;
}

std::vector<NrptRule> LoadNrptRules()
{
    // Групповая политика NRPT, если задана, заменяет локальную таблицу
    auto rules = LoadFrom(L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig");
    if (rules.empty()) {
        rules = LoadFrom(L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig");
    }
    return rules;
}

} // namespace approute
