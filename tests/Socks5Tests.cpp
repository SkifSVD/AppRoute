// Тесты цели правила «прокси» (issue #17): адрес прокси, сообщения SOCKS5, служебные адреса.

#include "core/Config.h"
#include "core/Socks5.h"
#include "core/Util.h"

#include "Test.h"

#include <cstring>

using namespace approute;

TEST(ProxyAddressParse)
{
    const auto v4 = ParseProxyAddress(L"127.0.0.1:10808");
    CHECK(v4 && v4->si_family == AF_INET && ntohs(v4->Ipv4.sin_port) == 10808);
    CHECK(v4 && FormatProxyAddress(*v4) == L"127.0.0.1:10808");

    const auto v6 = ParseProxyAddress(L"[::1]:1080");
    CHECK(v6 && v6->si_family == AF_INET6 && ntohs(v6->Ipv6.sin6_port) == 1080);
    CHECK(v6 && FormatProxyAddress(*v6) == L"[::1]:1080");

    CHECK(!ParseProxyAddress(L"localhost:1080"));     // только IP: имя прокси пришлось бы разрешать
    CHECK(!ParseProxyAddress(L"127.0.0.1"));
    CHECK(!ParseProxyAddress(L"127.0.0.1:0"));
    CHECK(!ParseProxyAddress(L"127.0.0.1:65536"));
    CHECK(!ParseProxyAddress(L"::1:1080"));           // IPv6 — в скобках
    CHECK(!ParseProxyAddress(L"[::1]1080"));
    CHECK(!ParseProxyAddress(L""));
}

TEST(Socks5Messages)
{
    CHECK(Socks5Greeting() == std::string("\x05\x01\x00", 3));
    CHECK(Socks5NoAuthAccepted(std::string("\x05\x00", 2)));
    CHECK(!Socks5NoAuthAccepted(std::string("\x05\xFF", 2)));
    CHECK(!Socks5NoAuthAccepted(std::string("\x05\x02", 2)));   // требует пароль

    SOCKADDR_INET t{};
    t.Ipv4.sin_family = AF_INET;
    t.Ipv4.sin_addr.s_addr = htonl(0x5DB8D822);   // 93.184.216.34
    t.Ipv4.sin_port = htons(443);
    CHECK(Socks5ConnectRequest(t) == std::string("\x05\x01\x00\x01\x5D\xB8\xD8\x22\x01\xBB", 10));

    const auto byName = Socks5ConnectRequest("example.com", htons(80));
    CHECK(byName && *byName == std::string("\x05\x01\x00\x03\x0B" "example.com" "\x00\x50", 18));
    CHECK(!Socks5ConnectRequest(std::string(256, 'a'), htons(80)));
    CHECK(!Socks5ConnectRequest("", htons(80)));

    CHECK(Socks5ReplyLength(std::string("\x05\x00\x00\x01\x00", 5)) == 10u);
    CHECK(Socks5ReplyLength(std::string("\x05\x00\x00\x04\x00", 5)) == 22u);
    CHECK(Socks5ReplyLength(std::string("\x05\x00\x00\x03\x07", 5)) == 14u);
    CHECK(!Socks5ReplyLength(std::string("\x04\x00\x00\x01\x00", 5)));
    CHECK(!Socks5ReplyLength(std::string("\x05\x00\x00\x09\x00", 5)));
    CHECK(Socks5ReplyToWsaError(0x05) == WSAECONNREFUSED);
    CHECK(Socks5ReplyToWsaError(0x04) == WSAEHOSTUNREACH);
}

TEST(Socks5UdpMessages)
{
    CHECK(Socks5UdpAssociateRequest() == std::string("\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00", 10));

    // Ответ на UDP ASSOCIATE: адрес реле 127.0.0.1:10808
    const auto relay = Socks5ReplyAddress(std::string("\x05\x00\x00\x01\x7F\x00\x00\x01\x2A\x38", 10));
    CHECK(relay && relay->si_family == AF_INET && ntohl(relay->Ipv4.sin_addr.s_addr) == 0x7F000001 &&
          ntohs(relay->Ipv4.sin_port) == 10808);
    CHECK(!Socks5ReplyAddress(std::string("\x05\x00\x00\x01\x7F\x00", 6)));        // обрезан
    CHECK(!Socks5ReplyAddress(std::string("\x05\x00\x00\x03\x01" "a\x00\x50", 8)));  // имя — не адрес

    SOCKADDR_INET t{};
    t.Ipv4.sin_family = AF_INET;
    t.Ipv4.sin_addr.s_addr = htonl(0x08080808);
    t.Ipv4.sin_port = htons(53);
    const std::string header = Socks5UdpHeader(t);
    CHECK(header == std::string("\x00\x00\x00\x01\x08\x08\x08\x08\x00\x35", 10));
    const auto byName = Socks5UdpHeader("example.com", htons(443));
    CHECK(byName && *byName == std::string("\x00\x00\x00\x03\x0B" "example.com" "\x01\xBB", 18));

    CHECK(Socks5UdpHeaderLength(header + "data") == 10u);
    CHECK(Socks5UdpHeaderLength(*byName) == 18u);
    CHECK(!Socks5UdpHeaderLength(std::string("\x00\x00\x01\x01\x08\x08\x08\x08\x00\x35", 10)));   // фрагмент
    CHECK(!Socks5UdpHeaderLength(std::string("\x00\x00\x00\x01\x08\x08", 6)));
}

TEST(FakeIpPoolMapsNames)
{
    FakeIpPool pool;
    const SOCKADDR_INET a = pool.Allocate("Example.COM");
    const SOCKADDR_INET b = pool.Allocate("example.com");
    const SOCKADDR_INET c = pool.Allocate("other.org");
    CHECK(a.si_family == AF_INET && a.Ipv4.sin_addr.s_addr == b.Ipv4.sin_addr.s_addr);
    CHECK(a.Ipv4.sin_addr.s_addr != c.Ipv4.sin_addr.s_addr);
    CHECK(FakeIpPool::InRange(a) && FakeIpPool::InRange(c));
    CHECK(pool.Lookup(a) == std::optional<std::string>("example.com"));
    CHECK(pool.Lookup(c) == std::optional<std::string>("other.org"));

    // ::ffff:служебный адрес — тот же
    SOCKADDR_INET mapped{};
    mapped.Ipv6.sin6_family = AF_INET6;
    mapped.Ipv6.sin6_addr.u.Byte[10] = 0xFF;
    mapped.Ipv6.sin6_addr.u.Byte[11] = 0xFF;
    std::memcpy(&mapped.Ipv6.sin6_addr.u.Byte[12], &a.Ipv4.sin_addr, 4);
    CHECK(pool.Lookup(mapped) == std::optional<std::string>("example.com"));

    // Обычный адрес и свободный служебный — не имя
    SOCKADDR_INET real{};
    real.Ipv4.sin_family = AF_INET;
    real.Ipv4.sin_addr.s_addr = htonl(0x08080808);
    CHECK(!FakeIpPool::InRange(real) && !pool.Lookup(real));
    SOCKADDR_INET unused{};
    unused.Ipv4.sin_family = AF_INET;
    unused.Ipv4.sin_addr.s_addr = htonl(0xC613FFF0);   // 198.19.255.240
    CHECK(FakeIpPool::InRange(unused) && !pool.Lookup(unused));
}

TEST(ProxyHostNameAscii)
{
    CHECK(ProxyHostName(L"example.com.") == std::optional<std::string>("example.com"));
    CHECK(ProxyHostName(L"пример.рф") == std::optional<std::string>("xn--e1afmkfd.xn--p1ai"));
    CHECK(!ProxyHostName(L""));
}

TEST(ConfigProxyRule)
{
    std::wstring error;
    const auto parsed = ParseConfig(
        R"({"version":1,"rules":[{"app":"curl.exe","target":{"type":"proxy","socks5":"127.0.0.1:10808"}}]})", &error);
    CHECK(parsed && parsed->rules.size() == 1);
    if (parsed && !parsed->rules.empty()) {
        const Rule& r = parsed->rules[0];
        CHECK(r.proxy == L"127.0.0.1:10808" && r.adapter.empty());
        CHECK(!ValidateRule(r));
        const auto again = ParseConfig(SerializeConfig(*parsed), &error);
        CHECK(again && again->rules.size() == 1 && again->rules[0].proxy == L"127.0.0.1:10808");
    }
    CHECK(!ParseConfig(R"({"rules":[{"app":"a.exe","target":{"type":"proxy","socks5":"proxy.local:1080"}}]})", &error));
    CHECK(!ParseConfig(R"({"rules":[{"app":"a.exe","target":{"type":"proxy"}}]})", &error));
    CHECK(!ParseConfig(R"({"rules":[{"app":"a.exe","target":{"type":"http"}}]})", &error));

    Rule bad;
    bad.app = L"a.exe";
    bad.proxy = L"?";
    CHECK(ValidateRule(bad).has_value());
}
