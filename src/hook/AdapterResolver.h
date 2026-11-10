#pragma once

#include "core/Win.h"

#include <vector>

namespace approute::hook {

// Знает адреса выбранного интерфейса и локальные подсети остальных.
// Таблица адресов перечитывается не чаще раза в 2 секунды: IP интерфейса может смениться
// (DHCP, переподключение VPN), а интерфейс задан GUID, который не меняется.
class AdapterResolver {
public:
    // "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"
    bool Init(const wchar_t* guidString);

    const GUID& Guid() const { return guid_; }

    // Адрес интерфейса для привязки сокета (порт 0). false — у интерфейса нет адреса этого
    // семейства (интерфейс отключён или без IPv6).
    bool GetBindAddress(ADDRESS_FAMILY family, SOCKADDR_INET& out);

    // Назначение, которое не нужно уводить в выбранный интерфейс: loopback, link-local,
    // multicast/broadcast, а также подсети других интерфейсов (локальная сеть, принтеры).
    bool IsLocalDestination(const SOCKADDR_INET& destination);

private:
    struct Entry {
        SOCKADDR_INET address{};
        UINT8 prefixLength = 0;
        NET_LUID luid{};
    };

    void RefreshLocked();
    void EnsureFresh();

    GUID guid_{};
    SRWLOCK lock_ = SRWLOCK_INIT;
    ULONGLONG refreshedAt_ = 0;
    bool haveLuid_ = false;
    NET_LUID luid_{};
    std::vector<Entry> entries_;
};

} // namespace approute::hook
