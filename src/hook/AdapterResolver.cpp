#include "AdapterResolver.h"

#include "core/Util.h"

#include <cstdio>
#include <cstring>

namespace approute::hook {

namespace {

constexpr ULONGLONG kRefreshIntervalMs = 2000;

bool InPrefix(const SOCKADDR_INET& addr, const SOCKADDR_INET& net, UINT8 prefixLength)
{
    if (addr.si_family != net.si_family) {
        return false;
    }
    const unsigned char* a = nullptr;
    const unsigned char* b = nullptr;
    unsigned maxBits = 0;
    if (addr.si_family == AF_INET) {
        a = reinterpret_cast<const unsigned char*>(&addr.Ipv4.sin_addr);
        b = reinterpret_cast<const unsigned char*>(&net.Ipv4.sin_addr);
        maxBits = 32;
    } else {
        a = reinterpret_cast<const unsigned char*>(&addr.Ipv6.sin6_addr);
        b = reinterpret_cast<const unsigned char*>(&net.Ipv6.sin6_addr);
        maxBits = 128;
    }
    if (prefixLength == 0 || prefixLength > maxBits) {
        return false;
    }
    const unsigned fullBytes = prefixLength / 8u;
    if (std::memcmp(a, b, fullBytes) != 0) {
        return false;
    }
    const unsigned restBits = prefixLength % 8u;
    if (restBits == 0) {
        return true;
    }
    const auto mask = static_cast<unsigned char>(0xFFu << (8u - restBits));
    return (a[fullBytes] & mask) == (b[fullBytes] & mask);
}

bool IsSpecialAddress(const SOCKADDR_INET& d)
{
    if (d.si_family == AF_INET) {
        const auto* b = reinterpret_cast<const unsigned char*>(&d.Ipv4.sin_addr);
        return b[0] == 0 || b[0] == 127                       // 0.0.0.0/8, loopback
            || (b[0] == 169 && b[1] == 254)                   // link-local
            || b[0] >= 224;                                   // multicast, broadcast, reserved
    }
    if (d.si_family == AF_INET6) {
        const auto& a = d.Ipv6.sin6_addr;
        return IN6_IS_ADDR_UNSPECIFIED(&a) || IN6_IS_ADDR_LOOPBACK(&a)
            || IN6_IS_ADDR_LINKLOCAL(&a) || IN6_IS_ADDR_MULTICAST(&a);
    }
    return true;
}

} // namespace

bool AdapterResolver::Init(const wchar_t* guidString)
{
    unsigned long d1 = 0;
    unsigned int d2 = 0, d3 = 0;
    unsigned int d4[8] = {};
    const int n = swscanf_s(guidString, L"{%8lx-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x}",
                            &d1, &d2, &d3, &d4[0], &d4[1], &d4[2], &d4[3], &d4[4], &d4[5], &d4[6], &d4[7]);
    if (n != 11) {
        return false;
    }
    guid_.Data1 = d1;
    guid_.Data2 = static_cast<unsigned short>(d2);
    guid_.Data3 = static_cast<unsigned short>(d3);
    for (int i = 0; i < 8; ++i) {
        guid_.Data4[i] = static_cast<unsigned char>(d4[i]);
    }
    return true;
}

void AdapterResolver::RefreshLocked()
{
    refreshedAt_ = GetTickCount64();
    entries_.clear();

    // LUID получаем каждый раз: VPN-клиент может пересоздать адаптер с тем же GUID
    haveLuid_ = ConvertInterfaceGuidToLuid(&guid_, &luid_) == NO_ERROR;

    PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
    if (GetUnicastIpAddressTable(AF_UNSPEC, &table) != NO_ERROR) {
        return;
    }
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& row = table->Table[i];
        if (row.DadState != IpDadStatePreferred) {
            continue;
        }
        entries_.push_back({row.Address, row.OnLinkPrefixLength, row.InterfaceLuid});
    }
    FreeMibTable(table);
}

void AdapterResolver::EnsureFresh()
{
    AcquireSRWLockShared(&lock_);
    const bool stale = GetTickCount64() - refreshedAt_ > kRefreshIntervalMs || refreshedAt_ == 0;
    ReleaseSRWLockShared(&lock_);
    if (!stale) {
        return;
    }
    AcquireSRWLockExclusive(&lock_);
    if (GetTickCount64() - refreshedAt_ > kRefreshIntervalMs || refreshedAt_ == 0) {
        RefreshLocked();
    }
    ReleaseSRWLockExclusive(&lock_);
}

bool AdapterResolver::GetBindAddress(ADDRESS_FAMILY family, SOCKADDR_INET& out)
{
    EnsureFresh();
    AcquireSRWLockShared(&lock_);
    bool found = false;
    if (haveLuid_) {
        for (const auto& e : entries_) {
            if (!SameLuid(e.luid, luid_) || e.address.si_family != family) {
                continue;
            }
            if (family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&e.address.Ipv6.sin6_addr)) {
                continue;   // link-local не годится для выхода в интернет
            }
            out = e.address;
            found = true;
            break;
        }
    }
    ReleaseSRWLockShared(&lock_);

    if (found) {
        if (out.si_family == AF_INET) {
            out.Ipv4.sin_port = 0;
        } else {
            out.Ipv6.sin6_port = 0;
            out.Ipv6.sin6_flowinfo = 0;
            out.Ipv6.sin6_scope_id = 0;
        }
    }
    return found;
}

bool AdapterResolver::IsLocalDestination(const SOCKADDR_INET& destination)
{
    if (IsSpecialAddress(destination)) {
        return true;
    }
    EnsureFresh();
    AcquireSRWLockShared(&lock_);
    bool local = false;
    for (const auto& e : entries_) {
        if (haveLuid_ && SameLuid(e.luid, luid_)) {
            continue;   // подсеть самого выбранного интерфейса — пусть идёт через него
        }
        if (InPrefix(destination, e.address, e.prefixLength)) {
            local = true;
            break;
        }
    }
    ReleaseSRWLockShared(&lock_);
    return local;
}

} // namespace approute::hook
