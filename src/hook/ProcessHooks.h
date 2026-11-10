#pragma once

#include <string>

namespace approute::hook {

// Правило текущего процесса — то же получат дочерние.
struct RuleConfig {
    std::wstring adapterGuid;
    std::wstring proxy;   // SOCKS5-прокси вместо интерфейса (#17)
    std::wstring logPath;
    bool includeChildren = true;
};

// Перехват создания процессов (kernelbase!CreateProcessInternalW — через него идут
// CreateProcessA/W и CreateProcessAsUserA/W): ребёнок стартует приостановленным, получает
// правило в окружении и ту же DLL, затем продолжает работу.
// Вызывается между MH_Initialize и MH_EnableHook.
void CreateProcessHooks(const RuleConfig& config);

} // namespace approute::hook
