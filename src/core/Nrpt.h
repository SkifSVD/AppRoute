#pragma once

#include "core/Win.h"

#include <string>
#include <string_view>
#include <vector>

namespace approute {

// Таблица политик разрешения имён (NRPT): «имена из этого пространства спрашивать у этих
// DNS-серверов». Так корпоративные VPN (OpenVPN и др.) задают DNS для внутренних доменов —
// без него внутренние имена через интерфейс VPN не разрешаются.

struct NrptRule {
    std::vector<std::wstring> namespaces;   // ".corp.example" (суффикс), "host.example" (имя), "." (все)
    std::vector<SOCKADDR_INET> servers;     // порт 0
};

// Правило из значений реестра: Name (REG_MULTI_SZ) и GenericDNSServers ("a;b").
// Пространства имён приводятся к нижнему регистру, неразобранные адреса пропускаются.
NrptRule MakeNrptRule(const std::vector<std::wstring>& names, std::wstring_view servers);

// Самое точное правило для имени (как в Windows: длиннейшее совпавшее пространство), или nullptr.
// ".corp.example" совпадает с "corp.example" и "a.corp.example"; "host.example" — только с ним.
const NrptRule* MatchNrpt(const std::vector<NrptRule>& rules, std::wstring_view name);

// Действующие правила с DNS-серверами: из групповой политики, если она задаёт NRPT,
// иначе локальные (их пишут VPN-клиенты). Только чтение реестра; при ошибке — пустой список.
std::vector<NrptRule> LoadNrptRules();

} // namespace approute
