/*
 * Общие определения службы AppRoute и драйвера approute-wfp.sys (#18).
 * Только C и заголовки Windows: файл подключают и драйвер (WDK), и служба (SDK).
 *
 * Драйвер не создаёт устройства и не принимает IOCTL. Цель правила он получает только из
 * контекста провайдера WFP (FWPM_GENERAL_CONTEXT), привязанного к фильтру; объекты WFP создаёт
 * служба через BFE, к которому допущены только администраторы.
 */
#pragma once

#include <guiddef.h>

/* Провайдер и подслой AppRoute */
/* {A8D57F59-F21A-4DEA-AB4D-737811DBA2DC} */
DEFINE_GUID(APPROUTE_WFP_PROVIDER, 0xa8d57f59, 0xf21a, 0x4dea, 0xab, 0x4d, 0x73, 0x78, 0x11, 0xdb, 0xa2, 0xdc);
/* {E9D67E30-E12C-4C21-8479-708595358619} */
DEFINE_GUID(APPROUTE_WFP_SUBLAYER, 0xe9d67e30, 0xe12c, 0x4c21, 0x84, 0x79, 0x70, 0x85, 0x95, 0x35, 0x86, 0x19);

/* Callout'ы драйвера: привязка (bind) и соединение (connect), IPv4 и IPv6 */
/* {01CF8608-7C8F-4006-AF20-47AE70D4DB73} */
DEFINE_GUID(APPROUTE_CALLOUT_BIND_V4, 0x01cf8608, 0x7c8f, 0x4006, 0xaf, 0x20, 0x47, 0xae, 0x70, 0xd4, 0xdb, 0x73);
/* {6142F853-A758-4FBA-8E29-DD6B41E2DD13} */
DEFINE_GUID(APPROUTE_CALLOUT_BIND_V6, 0x6142f853, 0xa758, 0x4fba, 0x8e, 0x29, 0xdd, 0x6b, 0x41, 0xe2, 0xdd, 0x13);
/* {37D2012A-45ED-4935-A9E4-8CD033FE03DD} */
DEFINE_GUID(APPROUTE_CALLOUT_CONNECT_V4, 0x37d2012a, 0x45ed, 0x4935, 0xa9, 0xe4, 0x8c, 0xd0, 0x33, 0xfe, 0x03, 0xdd);
/* {3382B7F4-9DF0-4574-B7CB-60DD4BDB325F} */
DEFINE_GUID(APPROUTE_CALLOUT_CONNECT_V6, 0x3382b7f4, 0x9df0, 0x4574, 0xb7, 0xcb, 0x60, 0xdd, 0x4b, 0xdb, 0x32, 0x5f);

/* Цель правила в контексте провайдера (FWP_BYTE_BLOB с этой структурой) */
#define APPROUTE_TARGET_VERSION 1

#define APPROUTE_TARGET_HAS_V4      0x00000001u   /* v4 — адрес интерфейса правила */
#define APPROUTE_TARGET_HAS_V6      0x00000002u   /* v6 — адрес интерфейса правила */
#define APPROUTE_TARGET_DEFAULT_V4  0x00000004u   /* нет IPv4-адреса — обычный маршрут, иначе блокировка */
#define APPROUTE_TARGET_DEFAULT_V6  0x00000008u   /* то же для IPv6 */

#pragma pack(push, 8)
typedef struct APPROUTE_TARGET {
    unsigned int version;          /* APPROUTE_TARGET_VERSION */
    unsigned int flags;            /* APPROUTE_TARGET_* */
    unsigned long long luid;       /* NET_LUID интерфейса правила (для журнала) */
    unsigned char v4[4];           /* сетевой порядок */
    unsigned char v6[16];
    unsigned int v6ScopeId;
} APPROUTE_TARGET;
#pragma pack(pop)
