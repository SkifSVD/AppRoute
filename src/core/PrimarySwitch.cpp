#include "core/PrimarySwitch.h"

#include "core/Routes.h"
#include "core/Util.h"

#include <algorithm>
#include <format>

namespace approute {

namespace {

bool HasAddress(const NetAdapter& a)
{
    for (const auto& u : a.unicast) {
        const auto& addr = u.address;
        if (addr.si_family == AF_INET) {
            // 169.254.x.x — адрес без DHCP, через него в сеть не выйти
            if ((ntohl(addr.Ipv4.sin_addr.s_addr) & 0xFFFF0000u) != 0xA9FE0000u) {
                return true;
            }
        } else if (addr.si_family == AF_INET6 && !IN6_IS_ADDR_LINKLOCAL(&addr.Ipv6.sin6_addr)) {
            return true;
        }
    }
    return false;
}

} // namespace

PrimaryChoice ChoosePrimary(std::wstring_view configured, const std::vector<NetAdapter>& adapters,
                            std::optional<NET_LUID> detected, const std::vector<NET_LUID>& internetRoutes)
{
    PrimaryChoice c;
    c.luid = detected;
    if (configured.empty() || configured == L"auto") {
        if (!detected) {
            c.note = L"основной физический интерфейс не найден";
        }
        return c;
    }
    const NetAdapter* a = FindAdapter(adapters, configured);
    const bool routed = a && std::any_of(internetRoutes.begin(), internetRoutes.end(),
                                         [&](NET_LUID l) { return SameLuid(l, a->luid); });
    if (a && a->IsUp() && HasAddress(*a) && routed) {
        c.luid = a->luid;
        return c;
    }
    c.fallback = true;
    const wchar_t* why = !a                               ? L"нет в системе"
                         : !a->IsUp() || !HasAddress(*a) ? L"не подключён"
                                                         : L"не ведёт в интернет (нет маршрута по умолчанию)";
    c.note = std::format(L"«{}» {} — весь трафик идёт через автоматически выбранный интерфейс",
                         a ? a->alias : std::wstring(configured), why);
    return c;
}

std::vector<NET_LUID> InterfacesWithInternetRoute()
{
    std::vector<NET_LUID> out;
    for (const auto& route : GetRoutes(AF_INET)) {
        if (IsDefaultLikeRoute(route) &&
            std::none_of(out.begin(), out.end(), [&](NET_LUID l) { return SameLuid(l, route.InterfaceLuid); })) {
            out.push_back(route.InterfaceLuid);
        }
    }
    return out;
}

std::optional<NET_LUID> CurrentInternetInterface()
{
    SOCKADDR_INET dest{};
    dest.si_family = AF_INET;
    dest.Ipv4.sin_addr.s_addr = htonl(0x08080808);   // любой публичный адрес: только поиск маршрута
    if (const auto route = BestRouteTo(dest)) {
        return route->InterfaceLuid;
    }
    return std::nullopt;
}

bool IsRouteManagerRunning()
{
    if (HANDLE m = OpenMutexW(SYNCHRONIZE, FALSE, kRouteManagerMutex)) {
        CloseHandle(m);
        return true;
    }
    return GetLastError() == ERROR_ACCESS_DENIED;
}

FileChangeWatcher::FileChangeWatcher(const std::wstring& file)
{
    const auto slash = file.find_last_of(L"\\/");
    const std::wstring dir = slash == std::wstring::npos ? L"." : file.substr(0, slash);
    const HANDLE h = FindFirstChangeNotificationW(dir.c_str(), FALSE,
                                                  FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME);
    handle_ = h == INVALID_HANDLE_VALUE ? nullptr : h;
}

FileChangeWatcher::~FileChangeWatcher()
{
    if (handle_) {
        FindCloseChangeNotification(handle_);
    }
}

void FileChangeWatcher::Rearm()
{
    if (handle_) {
        FindNextChangeNotification(handle_);
    }
}

} // namespace approute
