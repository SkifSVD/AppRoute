#pragma once

namespace approute {
struct UnavailablePolicy;
}

namespace approute::hook {

class AdapterResolver;

// Перехват getaddrinfo / GetAddrInfoW / GetAddrInfoExW: имена разрешаются через выбранный
// интерфейс (DNS интерфейса или DoH через него), а не системным резолвером, который ходит
// через основной канал. APPROUTE_DNS=system — не перехватывать. Если интерфейс недоступен
// или резолвер не ответил: block — ошибка WSATRY_AGAIN, default — системный резолвер (#9).
// Вызывается между MH_Initialize и MH_EnableHook.
void CreateDnsHooks(AdapterResolver& resolver, const UnavailablePolicy& policy);

} // namespace approute::hook
