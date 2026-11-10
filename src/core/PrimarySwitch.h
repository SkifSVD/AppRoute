#pragma once

// Глобальный переключатель основного интерфейса (#14): «весь трафик через …».
//
// Выбор хранится в поле "primary" конфига ("auto" или GUID). Менеджер маршрутов
// (approute-routes watch) читает его и применяет на лету; GUI только меняет конфиг. Правила
// приложений продолжают работать независимо от выбора.

#include "core/NetAdapters.h"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace approute {

struct PrimaryChoice {
    std::optional<NET_LUID> luid;   // nullopt — основной интерфейс определить не удалось
    bool fallback = false;          // выбранный интерфейс недоступен, взят автоматический
    std::wstring note;              // пояснение для журнала и окна
};

// Основной интерфейс по значению "primary": "auto" — detected (физический с лучшей метрикой);
// GUID — этот интерфейс, если он подключён, у него есть адрес и маршрут в интернет (он есть в
// internetRoutes), иначе автоматический: VPN выключен или пускает только в свою сеть (как
// корпоративный с раздельным туннелем) — трафик идёт как обычно, а не пропадает.
PrimaryChoice ChoosePrimary(std::wstring_view configured, const std::vector<NetAdapter>& adapters,
                            std::optional<NET_LUID> detected, const std::vector<NET_LUID>& internetRoutes);

// Интерфейсы с маршрутом в интернет: IPv4 0.0.0.0/0 или расщеплённый 0/1 + 128/1 (так его
// ставят VPN). Только такой интерфейс может нести «весь трафик».
std::vector<NET_LUID> InterfacesWithInternetRoute();

// Интерфейс, через который Windows сейчас отправит трафик в интернет (IPv4): лучший маршрут к
// публичному адресу по таблице маршрутов, без отправки пакетов.
std::optional<NET_LUID> CurrentInternetInterface();

// Менеджер маршрутов держит этот мьютекс, пока работает (один экземпляр на сеанс).
inline constexpr wchar_t kRouteManagerMutex[] = L"Local\\AppRoute.RouteManager";

// Запущен ли менеджер маршрутов в этом сеансе. Работает и без прав администратора:
// мьютекс повышенного процесса виден как «доступ запрещён».
bool IsRouteManagerRunning();

// Событие при изменении файла (запись или атомарная замена) — для перечитывания конфига.
class FileChangeWatcher {
public:
    explicit FileChangeWatcher(const std::wstring& file);
    ~FileChangeWatcher();
    FileChangeWatcher(const FileChangeWatcher&) = delete;
    FileChangeWatcher& operator=(const FileChangeWatcher&) = delete;

    // Взводится при изменениях в папке файла; nullptr, если папки нет.
    HANDLE Event() const { return handle_; }
    // После обработки события — ждать следующего.
    void Rearm();

private:
    HANDLE handle_ = nullptr;
};

} // namespace approute
