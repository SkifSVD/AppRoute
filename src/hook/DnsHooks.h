#pragma once

namespace approute {
struct UnavailablePolicy;
class FakeIpPool;
}

namespace approute::hook {

class AdapterResolver;

// Перехват getaddrinfo / GetAddrInfoW / GetAddrInfoExW: имена разрешаются через выбранный
// интерфейс (DNS интерфейса или DoH через него), а не системным резолвером, который ходит
// через основной канал. APPROUTE_DNS=system — не перехватывать. Если интерфейс недоступен
// или резолвер не ответил: block — ошибка WSATRY_AGAIN, default — системный резолвер (#9).
// fake — правило «прокси» (#17): имена разрешает прокси, программа получает служебные адреса
// (кроме localhost и имён без точки — их разрешает система).
// Вызывается между MH_Initialize и MH_EnableHook. true — перехват установлен.
bool CreateDnsHooks(AdapterResolver& resolver, const UnavailablePolicy& policy, FakeIpPool* fake);

} // namespace approute::hook
