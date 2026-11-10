#pragma once

namespace approute::hook {

// Журнал hook-DLL: OutputDebugString (видно в DebugView) и, если задана переменная
// окружения APPROUTE_LOG, дописывание в файл (UTF-8). Потокобезопасно.
void LogInit();
void Log(const wchar_t* format, ...);

} // namespace approute::hook
