#pragma once

// Поведение при недоступном интерфейсе правила (issue #9) и его передача в hook-DLL через
// окружение. Только заголовок: hook-DLL не тянет за собой остальной конфиг.

#include "core/Config.h"
#include "core/Process.h"

#include <string_view>

namespace approute {

struct UnavailablePolicy {
    OnUnavailable onUnavailable = OnUnavailable::Block;
    Ipv6Mode ipv6 = Ipv6Mode::Follow;

    // У интерфейса нет адреса нужного семейства (отключён, нет IPv6): пустить соединение
    // маршрутом по умолчанию (true) или заблокировать (false).
    bool UseDefaultRoute(bool ipv6Family) const
    {
        if (ipv6Family && ipv6 != Ipv6Mode::Follow) {
            return ipv6 == Ipv6Mode::Default;
        }
        return onUnavailable == OnUnavailable::Default;
    }

    // DNS при недоступном интерфейсе: системным резолвером (true) или ошибка (false).
    bool UseSystemDns() const { return onUnavailable == OnUnavailable::Default; }
};

// Значения переменных окружения; nullptr — значение по умолчанию (переменная удаляется).
inline const wchar_t* OnUnavailableEnvValue(OnUnavailable v)
{
    return v == OnUnavailable::Default ? L"default" : nullptr;
}

inline const wchar_t* Ipv6EnvValue(Ipv6Mode v)
{
    return v == Ipv6Mode::Block ? L"block" : v == Ipv6Mode::Default ? L"default" : nullptr;
}

inline UnavailablePolicy ParsePolicy(std::wstring_view onUnavailable, std::wstring_view ipv6)
{
    UnavailablePolicy p;
    if (onUnavailable == L"default") {
        p.onUnavailable = OnUnavailable::Default;
    }
    if (ipv6 == L"block") {
        p.ipv6 = Ipv6Mode::Block;
    } else if (ipv6 == L"default") {
        p.ipv6 = Ipv6Mode::Default;
    }
    return p;
}

inline UnavailablePolicy PolicyFromEnvironment()
{
    wchar_t a[16] = {};
    wchar_t b[16] = {};
    const DWORD na = GetEnvironmentVariableW(kEnvOnUnavailable, a, 16);
    const DWORD nb = GetEnvironmentVariableW(kEnvIpv6, b, 16);
    return ParsePolicy(na > 0 && na < 16 ? a : L"", nb > 0 && nb < 16 ? b : L"");
}

} // namespace approute
