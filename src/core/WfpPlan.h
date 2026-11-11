#pragma once

// Что служба AppRoute создаёт в WFP для драйвера approute-wfp.sys (#18): по фильтру на правило
// (программа по пути, только пользователь, давший согласие) с целью — адресами интерфейса
// правила, и исключения (loopback, локальные подсети), которые идут напрямую.
//
// Чистая функция: состояние сети передаётся параметрами, применение — отдельно (служба).

#include "core/Config.h"
#include "core/NetAdapters.h"
#include "core/PackagedApps.h"

#include "driver/AppRouteWfpShared.h"

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace approute {

struct WfpAppFilter {
    std::wstring app;            // как в правиле
    std::wstring appPath;        // полный путь с раскрытыми %ПЕРЕМЕННЫМИ% — для ALE_APP_ID
    std::wstring adapter;        // GUID интерфейса правила
    APPROUTE_TARGET target{};    // контекст провайдера для драйвера
};

struct WfpExemption {
    SOCKADDR_INET prefix{};      // порт 0
    UINT8 length = 0;
};

struct WfpPlan {
    std::wstring userSid;                    // ALE_USER_ID: только процессы этого пользователя
    std::vector<WfpAppFilter> filters;
    std::vector<WfpExemption> exemptions;    // напрямую, без подмены адреса
    std::vector<std::wstring> notes;         // правила, которые драйвер применить не может
};

// Exe приложения из пакета у пользователя плана (#45); nullopt — причина в error.
using WfpPackageResolver =
    std::function<std::optional<PackageExecutables>(std::wstring_view app, std::wstring* error)>;

// Правило для приложения из пакета даёт фильтр на его exe, а с includeChildren — и на exe других
// приложений полного доверия того же пакета. Без resolvePackage такие правила идут в заметки.
WfpPlan WfpPlanFromConfig(const Config& config, const std::vector<NetAdapter>& adapters, const std::wstring& userSid,
                          const WfpPackageResolver& resolvePackage = {});

// Цель для интерфейса a (nullptr — его сейчас нет) по политике правила.
APPROUTE_TARGET MakeWfpTarget(const NetAdapter* a, const Rule& rule);

bool SameWfpTarget(const APPROUTE_TARGET& a, const APPROUTE_TARGET& b);

// Планы дают одинаковые объекты WFP (заметки не сравниваются): повторно применять не нужно.
bool SameWfpPlan(const WfpPlan& a, const WfpPlan& b);

} // namespace approute
