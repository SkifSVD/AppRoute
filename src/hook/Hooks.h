#pragma once

namespace approute::hook {

// Читает правило из окружения (APPROUTE_ADAPTER = GUID интерфейса) и ставит перехваты Winsock.
// Без APPROUTE_ADAPTER DLL ничего не делает. Вызывается из DllMain.
void Install();
void Uninstall();

} // namespace approute::hook
