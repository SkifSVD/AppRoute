#pragma once

// Цель правила «прокси» (#17): соединения программы идут через SOCKS5-прокси, например
// локальный прокси Xray/V2Ray-клиента, работающего без TUN. Здесь — разбор адреса прокси,
// сообщения протокола (RFC 1928, без аутентификации) и пул служебных адресов для имён.
//
// Имена разрешает прокси: программа получает служебный адрес из 198.18.0.0/15 (диапазон для
// тестирования сетей, в интернете не встречается), а при соединении с ним hook-DLL передаёт
// прокси имя. Так DNS-запросы программы не уходят мимо прокси.

#include "core/Win.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace approute {

// "127.0.0.1:10808" или "[::1]:1080" — только IP-адрес (имя прокси пришлось бы разрешать) и
// порт 1–65535. Порт в результате — в сетевом порядке.
std::optional<SOCKADDR_INET> ParseProxyAddress(std::wstring_view text);

// Обратно: "127.0.0.1:10808", "[::1]:1080".
std::wstring FormatProxyAddress(const SOCKADDR_INET& address);

// Принимает ли прокси TCP-соединения (без рукопожатия), ожидание — не дольше timeoutMs.
bool ProxyResponds(const SOCKADDR_INET& address, DWORD timeoutMs);

// --- протокол -------------------------------------------------------------------------------

// Приветствие: версия 5, один метод — «без аутентификации».
std::string Socks5Greeting();

// Ответ на приветствие (2 байта): выбран метод «без аутентификации».
bool Socks5NoAuthAccepted(std::string_view reply);

// CONNECT к адресу (ATYP 1 / 4) или имени (ATYP 3, ASCII, до 255 байт). Порт — сетевой порядок.
std::string Socks5ConnectRequest(const SOCKADDR_INET& target);
std::optional<std::string> Socks5ConnectRequest(std::string_view host, USHORT port);

// Полная длина ответа на CONNECT по его первым 5 байтам (VER REP RSV ATYP + 1); nullopt —
// неверный ответ.
std::optional<size_t> Socks5ReplyLength(std::string_view head);

// Код ответа (REP): 0 — успех. Описание и код ошибки Winsock для программы.
const wchar_t* Socks5ReplyText(uint8_t code);
int Socks5ReplyToWsaError(uint8_t code);

// --- служебные адреса для имён --------------------------------------------------------------

class FakeIpPool {
public:
    // Адрес для имени (одно имя — один адрес, без учёта регистра). Имя — в ASCII (IDN —
    // уже в punycode). Пул на 131 070 адресов; при исчерпании переиспользуются старейшие.
    SOCKADDR_INET Allocate(std::string_view name);

    // Имя по служебному адресу (IPv4 или ::ffff:IPv4) или nullopt.
    std::optional<std::string> Lookup(const SOCKADDR_INET& address) const;

    static bool InRange(const SOCKADDR_INET& address);

private:
    mutable SRWLOCK lock_ = SRWLOCK_INIT;
    std::unordered_map<std::string, uint32_t> byName_;    // имя → номер в пуле
    std::vector<std::string> byIndex_;                    // номер → имя
    uint32_t next_ = 0;
};

// Имя для прокси: UTF-16 → ASCII (IDN → punycode), без завершающей точки; nullopt — не
// получилось.
std::optional<std::string> ProxyHostName(std::wstring_view name);

} // namespace approute
