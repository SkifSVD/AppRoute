#pragma once

#include "core/Win.h"

#include <string>
#include <string_view>

namespace approute {

// "192.168.0.1", "fe80::1" и т.п.; для AF_UNSPEC — пустая строка.
std::wstring FormatAddress(const SOCKADDR_INET& addr);

// "0.0.0.0/0", "2000::/3".
std::wstring FormatPrefix(const IP_ADDRESS_PREFIX& prefix);

// "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}".
std::wstring GuidToString(const GUID& guid);

// Текст системной ошибки с кодом: "5: Отказано в доступе.".
std::wstring Win32ErrorMessage(DWORD code);

// Псевдоним интерфейса по LUID (или "LUID xxx", если интерфейс исчез).
std::wstring InterfaceName(NET_LUID luid);

bool IsProcessElevated();

inline bool SameLuid(NET_LUID a, NET_LUID b) { return a.Value == b.Value; }

bool IsZeroAddress(const SOCKADDR_INET& addr);
bool SameAddress(const SOCKADDR_INET& a, const SOCKADDR_INET& b);

// Сравнение строк без учёта регистра (ординальное, Unicode).
bool EqualsIgnoreCase(std::wstring_view a, std::wstring_view b);

} // namespace approute
