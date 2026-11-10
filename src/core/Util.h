#pragma once

#include "core/Win.h"

#include <optional>
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

// addr лежит в подсети net/prefixLength (одно семейство; prefixLength 0 — false).
bool InPrefix(const SOCKADDR_INET& addr, const SOCKADDR_INET& net, UINT8 prefixLength);
bool SameAddress(const SOCKADDR_INET& a, const SOCKADDR_INET& b);

// Сравнение строк без учёта регистра (ординальное, Unicode).
bool EqualsIgnoreCase(std::wstring_view a, std::wstring_view b);

// "160.79.104.0/23", "2607:6bc0::/48"; адрес без длины — /32 или /128. Биты адреса за
// пределами префикса должны быть нулевыми (каноническая запись), иначе nullopt.
std::optional<IP_ADDRESS_PREFIX> ParsePrefix(std::wstring_view text);

// UTF-16 ↔ UTF-8. FromUtf8 возвращает nullopt на некорректном UTF-8.
std::string ToUtf8(std::wstring_view text);
std::optional<std::wstring> FromUtf8(std::string_view text);

} // namespace approute
