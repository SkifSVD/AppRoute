// Тесты сопоставления имён с таблицей NRPT (корпоративный DNS через VPN, issue #10).

#include "core/Nrpt.h"

#include "Test.h"

using namespace approute;

namespace {

std::vector<NrptRule> Rules()
{
    return {
        MakeNrptRule({L".corp.example"}, L"192.0.2.53"),
        MakeNrptRule({L".lab.corp.example"}, L"192.0.2.54; 2001:db8::53"),
        MakeNrptRule({L"host.example."}, L"198.51.100.1"),
    };
}

} // namespace

TEST(NrptParsesServers)
{
    const auto r = MakeNrptRule({L" .Corp.Example. ", L""}, L"192.0.2.1;2001:db8::1, bad;; 198.51.100.7");
    CHECK(r.namespaces.size() == 1);
    CHECK(r.namespaces[0] == L".corp.example");
    CHECK(r.servers.size() == 3);
    CHECK(r.servers[0].si_family == AF_INET);
    CHECK(r.servers[1].si_family == AF_INET6);
    CHECK(r.servers[0].Ipv4.sin_port == 0);
}

TEST(NrptSuffixMatch)
{
    const auto rules = Rules();
    CHECK(MatchNrpt(rules, L"mail.corp.example") == &rules[0]);
    CHECK(MatchNrpt(rules, L"corp.example") == &rules[0]);
    CHECK(MatchNrpt(rules, L"MAIL.CORP.EXAMPLE.") == &rules[0]);
    CHECK(MatchNrpt(rules, L"notcorp.example") == nullptr);
    CHECK(MatchNrpt(rules, L"example") == nullptr);
}

TEST(NrptMostSpecificWins)
{
    const auto rules = Rules();
    CHECK(MatchNrpt(rules, L"a.lab.corp.example") == &rules[1]);
    CHECK(rules[1].servers.size() == 2);
}

TEST(NrptExactName)
{
    const auto rules = Rules();
    CHECK(MatchNrpt(rules, L"host.example") == &rules[2]);
    CHECK(MatchNrpt(rules, L"a.host.example") == nullptr);
}

TEST(NrptCatchAllIsLowestPriority)
{
    std::vector<NrptRule> rules = {MakeNrptRule({L"."}, L"192.0.2.1"), MakeNrptRule({L".corp.example"}, L"192.0.2.2")};
    CHECK(MatchNrpt(rules, L"www.example.org") == &rules[0]);
    CHECK(MatchNrpt(rules, L"x.corp.example") == &rules[1]);
    CHECK(MatchNrpt(rules, L"") == nullptr);
}
