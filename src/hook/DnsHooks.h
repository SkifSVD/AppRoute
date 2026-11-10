#pragma once

namespace approute::hook {

class AdapterResolver;

// Перехват getaddrinfo / GetAddrInfoW / GetAddrInfoExW: имена разрешаются через выбранный
// интерфейс (DNS интерфейса или DoH через него), а не системным резолвером, который ходит
// через основной канал. APPROUTE_DNS=system — не перехватывать.
// Вызывается между MH_Initialize и MH_EnableHook.
void CreateDnsHooks(AdapterResolver& resolver);

} // namespace approute::hook
