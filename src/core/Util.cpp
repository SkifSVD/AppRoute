#include "core/Util.h"

#include <combaseapi.h>

#include <cstring>
#include <format>

namespace approute {

std::wstring FormatAddress(const SOCKADDR_INET& addr)
{
    wchar_t buf[INET6_ADDRSTRLEN] = {};
    switch (addr.si_family) {
    case AF_INET:
        InetNtopW(AF_INET, &addr.Ipv4.sin_addr, buf, std::size(buf));
        break;
    case AF_INET6:
        InetNtopW(AF_INET6, &addr.Ipv6.sin6_addr, buf, std::size(buf));
        break;
    default:
        return {};
    }
    return buf;
}

std::wstring FormatPrefix(const IP_ADDRESS_PREFIX& prefix)
{
    return std::format(L"{}/{}", FormatAddress(prefix.Prefix), prefix.PrefixLength);
}

std::wstring GuidToString(const GUID& guid)
{
    wchar_t buf[64] = {};
    StringFromGUID2(guid, buf, static_cast<int>(std::size(buf)));
    return buf;
}

std::wstring Win32ErrorMessage(DWORD code)
{
    wchar_t* text = nullptr;
    const DWORD len = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<wchar_t*>(&text), 0, nullptr);
    std::wstring msg = len ? std::wstring(text, len) : std::wstring(L"неизвестная ошибка");
    if (text) {
        LocalFree(text);
    }
    while (!msg.empty() && (msg.back() == L'\r' || msg.back() == L'\n' || msg.back() == L' ')) {
        msg.pop_back();
    }
    return std::format(L"{}: {}", code, msg);
}

std::wstring InterfaceName(NET_LUID luid)
{
    wchar_t alias[NDIS_IF_MAX_STRING_SIZE + 1] = {};
    if (ConvertInterfaceLuidToAlias(&luid, alias, std::size(alias)) == NO_ERROR) {
        return alias;
    }
    return std::format(L"LUID {:#x}", luid.Value);
}

bool IsProcessElevated()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated;
}

bool IsZeroAddress(const SOCKADDR_INET& addr)
{
    switch (addr.si_family) {
    case AF_INET:
        return addr.Ipv4.sin_addr.s_addr == 0;
    case AF_INET6:
        return IN6_IS_ADDR_UNSPECIFIED(&addr.Ipv6.sin6_addr);
    default:
        return true;
    }
}

bool SameAddress(const SOCKADDR_INET& a, const SOCKADDR_INET& b)
{
    if (a.si_family != b.si_family) {
        // Шлюз "on-link" может прийти как с AF_UNSPEC, так и с нулевым адресом
        return IsZeroAddress(a) && IsZeroAddress(b);
    }
    switch (a.si_family) {
    case AF_INET:
        return a.Ipv4.sin_addr.s_addr == b.Ipv4.sin_addr.s_addr;
    case AF_INET6:
        return std::memcmp(&a.Ipv6.sin6_addr, &b.Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0;
    default:
        return true;
    }
}

bool EqualsIgnoreCase(std::wstring_view a, std::wstring_view b)
{
    return CompareStringOrdinal(a.data(), static_cast<int>(a.size()),
                                b.data(), static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}

} // namespace approute
