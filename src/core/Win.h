#pragma once

// Единая точка подключения заголовков Windows для ядра AppRoute.
// Порядок важен: winsock2.h должен идти раньше windows.h.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
