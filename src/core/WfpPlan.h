#pragma once

// Что служба AppRoute создаёт в WFP для драйвера approute-wfp.sys (#18): по фильтру на правило
// (программа по пути, только пользователь, давший согласие) с целью — адресами интерфейса
// правила, и исключения (loopback, локальные подсети), которые идут напрямую.
//
// Чистая функция: состояние сети передаётся параметрами, применение — отдельно (служба).

#include "core/Config.h"
#include "core/NetAdapters.h"

#include "driver/AppRouteWfpShared.h"

#include <string>
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

WfpPlan WfpPlanFromConfig(const Config& config, const std::vector<NetAdapter>& adapters, const std::wstring& userSid);

// Цель для интерфейса a (nullptr — его сейчас нет) по политике правила.
APPROUTE_TARGET MakeWfpTarget(const NetAdapter* a, const Rule& rule);

bool SameWfpTarget(const APPROUTE_TARGET& a, const APPROUTE_TARGET& b);

// Планы дают одинаковые объекты WFP (заметки не сравниваются): повторно применять не нужно.
bool SameWfpPlan(const WfpPlan& a, const WfpPlan& b);

} // namespace approute
