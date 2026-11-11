#pragma once

// UDP через SOCKS5-прокси (UDP ASSOCIATE, RFC 1928; #46).
//
// На каждое назначение сокета программы — «ассоциация»: управляющее TCP-соединение с прокси
// (живёт, пока жив сокет программы), сокет к реле прокси и внутренний UDP-сокет на loopback.
// Программа шлёт датаграммы на внутренний сокет (перехватчики подменяют адрес назначения или
// соединяют сокет с ним), поток реле добавляет заголовок SOCKS5 и пересылает на реле; ответы
// реле — без заголовка — обратно программе. Так программа получает чистые данные при любой
// модели ввода-вывода (синхронной, OVERLAPPED, порт завершения). Адрес отправителя в
// recvfrom и т.п. перехватчики возвращают исходный (UdpRelayOriginal).

#include "core/Win.h"

#include <optional>
#include <string>

namespace approute {
struct ProxyCredential;
}

namespace approute::hook {

// Оригиналы Winsock: поток реле и рукопожатие не должны проходить через перехватчики
struct UdpRelayApi {
    decltype(&::connect) connect = nullptr;
    decltype(&::sendto) sendto = nullptr;
    decltype(&::recvfrom) recvfrom = nullptr;
    decltype(&::closesocket) closesocket = nullptr;
    decltype(&::getsockname) getsockname = nullptr;
};

// credential — логин и пароль прокси (#56) или nullptr; должен жить до конца процесса
void UdpRelayInit(const SOCKADDR_INET& proxy, const ProxyCredential* credential, const UdpRelayApi& api);

// Есть ли хоть одна ассоциация (иначе подменять адреса отправителя не нужно)
bool UdpRelayActive();

// Адрес внутреннего сокета для датаграмм сокета s (семейство socketFamily) на original (как его
// задала программа; target — он же без ::ffff:, host — имя для прокси вместо адреса). Указатель
// действителен до закрытия s. nullptr — ошибка (код Winsock выставлен, причина в журнале).
const sockaddr* UdpRelayRoute(SOCKET s, int socketFamily, const sockaddr* original, int originalLen,
                              const SOCKADDR_INET& target, const std::optional<std::string>& host, int& shimLen);

// Адрес отправителя from — внутренний сокет реле: заменить исходным адресом назначения.
// fromLen — размер буфера / длина адреса, как в recvfrom.
void UdpRelayRewriteFrom(sockaddr* from, int* fromLen);

// Сокет программы закрыт — ассоциации снимаются
void UdpRelayClose(SOCKET s);

} // namespace approute::hook
