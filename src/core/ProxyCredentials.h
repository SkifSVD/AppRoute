#pragma once

// Логин и пароль SOCKS5-прокси (#56, RFC 1929).
//
// Хранятся не в config.json, а в диспетчере учётных данных Windows текущего пользователя
// (Credential Manager, общий тип), по адресу прокси: "AppRoute/SOCKS5/127.0.0.1:10808". Пароль
// защищён Windows (DPAPI профиля пользователя), не попадает в конфиг, командную строку, окружение
// и журнал. hook-DLL читает его сама в процессе программы — того же пользователя.

#include "core/Win.h"

#include <optional>
#include <string>

namespace approute {

struct ProxyCredential {
    std::wstring user;
    std::wstring password;

    ~ProxyCredential();   // пароль затирается
};

// Имя записи в диспетчере учётных данных
std::wstring ProxyCredentialTarget(const SOCKADDR_INET& proxy);

std::optional<ProxyCredential> ReadProxyCredential(const SOCKADDR_INET& proxy);

// Логин и пароль — 1–255 байт в UTF-8 (ограничение RFC 1929). Ошибка — описание в error.
bool SaveProxyCredential(const SOCKADDR_INET& proxy, const ProxyCredential& credential, std::wstring* error);

// Удалить; true — запись была
bool DeleteProxyCredential(const SOCKADDR_INET& proxy);

// Проверка логина и пароля перед сохранением: текст ошибки или nullopt
std::optional<std::wstring> ValidateProxyCredential(const ProxyCredential& credential);

} // namespace approute
