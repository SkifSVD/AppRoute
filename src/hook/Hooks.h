#pragma once

namespace approute::hook {

// Читает правило из окружения (APPROUTE_ADAPTER = GUID интерфейса, APPROUTE_LOG,
// APPROUTE_CHILDREN) и ставит перехваты Winsock и создания процессов.
// Без APPROUTE_ADAPTER DLL ничего не делает. Вызывается из DllMain.
void Install();
void Uninstall();

} // namespace approute::hook
