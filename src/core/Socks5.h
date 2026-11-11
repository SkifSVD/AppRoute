#pragma once

// Цель правила «прокси» (#17): соединения программы идут через SOCKS5-прокси, например
// локальный прокси Xray/V2Ray-клиента, работающего без TUN. Здесь — разбор адреса прокси,
// сообщения протокола (RFC 1928; логин и пароль — RFC 1929, #56) и пул служебных адресов для имён.
//
// Имена разрешает прокси: программа получает служебный адрес из 198.18.0.0/15 (диапазон для
// тестирования сетей, в интернете не встречается), а при соединении с ним hook-DLL передаёт
// прокси имя. Так DNS-запросы программы не уходят мимо прокси.

#include "core/Win.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace approute {

struct ProxyCredential;

// "127.0.0.1:10808" или "[::1]:1080" — только IP-адрес (имя прокси пришлось бы разрешать) и
// порт 1–65535. Порт в результате — в сетевом порядке.
std::optional<SOCKADDR_INET> ParseProxyAddress(std::wstring_view text);

// Обратно: "127.0.0.1:10808", "[::1]:1080".
std::wstring FormatProxyAddress(const SOCKADDR_INET& address);

// Принимает ли прокси TCP-соединения (без рукопожатия), ожидание — не дольше timeoutMs.
bool ProxyResponds(const SOCKADDR_INET& address, DWORD timeoutMs);

// --- протокол -------------------------------------------------------------------------------

// Приветствие: версия 5, метод «без аутентификации», с offerPassword — и «логин и пароль».
std::string Socks5Greeting(bool offerPassword = false);

// Запрос RFC 1929: VER(1) ULEN USER PLEN PASS в UTF-8; nullopt — длина вне 1–255 байт.
std::optional<std::string> Socks5PasswordRequest(const ProxyCredential& credential);

// Согласование метода (и вход по паролю, если прокси его выбрал)
enum class Socks5Auth {
    Ok,
    NoAnswer,        // нет ответа / соединение закрыто
    NeedsPassword,   // прокси требует логин и пароль, а их нет
    WrongPassword,   // прокси отклонил логин и пароль
    Unsupported,     // прокси не принял ни один метод или это не SOCKS5
};
using Socks5Send = std::function<bool(std::string_view)>;
using Socks5Recv = std::function<bool(char*, size_t)>;
Socks5Auth Socks5Negotiate(const Socks5Send& send, const Socks5Recv& recv, const ProxyCredential* credential);
const wchar_t* Socks5AuthText(Socks5Auth result);

// Проверка прокси: соединение и согласование (с паролем, если он задан), не дольше timeoutMs
// на каждый шаг.
Socks5Auth CheckProxy(const SOCKADDR_INET& address, const ProxyCredential* credential, DWORD timeoutMs);

// Ответ на приветствие (2 байта): выбран метод «без аутентификации».
bool Socks5NoAuthAccepted(std::string_view reply);

// CONNECT к адресу (ATYP 1 / 4) или имени (ATYP 3, ASCII, до 255 байт). Порт — сетевой порядок.
std::string Socks5ConnectRequest(const SOCKADDR_INET& target);
std::optional<std::string> Socks5ConnectRequest(std::string_view host, USHORT port);

// Полная длина ответа на CONNECT по его первым 5 байтам (VER REP RSV ATYP + 1); nullopt —
// неверный ответ.
std::optional<size_t> Socks5ReplyLength(std::string_view head);

// UDP ASSOCIATE (#46): адрес клиента 0.0.0.0:0 — датаграммы придут с адреса, известного
// только после привязки сокета.
std::string Socks5UdpAssociateRequest();

// BND.ADDR:BND.PORT из полного ответа (для UDP ASSOCIATE — адрес реле). Только IP-адрес
// (ATYP 1 / 4); порт — сетевой порядок.
std::optional<SOCKADDR_INET> Socks5ReplyAddress(std::string_view reply);

// Заголовок датаграммы UDP через прокси: RSV RSV FRAG(0) ATYP DST.ADDR DST.PORT.
std::string Socks5UdpHeader(const SOCKADDR_INET& target);
std::optional<std::string> Socks5UdpHeader(std::string_view host, USHORT port);

// Длина заголовка датаграммы от реле; nullopt — неверный заголовок или фрагмент (FRAG != 0,
// фрагменты не поддерживаются — такие датаграммы отбрасываются).
std::optional<size_t> Socks5UdpHeaderLength(std::string_view datagram);

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
