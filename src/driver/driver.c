/*
 * approute-wfp.sys — драйвер AppRoute (#18): сокеты программ с правилом привязываются к адресу
 * интерфейса правила на уровне ядра, как бы программа ни была запущена и как бы ни создавала
 * сокеты (в том числе явная привязка к адресу другого интерфейса — звонки с ICE).
 *
 * Границы:
 *   - нет устройства для пользовательского режима и нет IOCTL: безымянный объект устройства
 *     нужен только для регистрации callout'ов;
 *   - драйвер ничего не решает сам: какие программы (путь, пользователь) и куда — задают
 *     фильтры и контекст провайдера, которые создаёт служба AppRoute через BFE (только
 *     администраторы); без фильтров callout'ы не вызываются;
 *   - драйвер меняет только локальный адрес сокета; содержимое трафика он не видит.
 *
 * Callout'ы:
 *   ALE_CONNECT_REDIRECT_V4/V6 — соединение (TCP и подключённый UDP): локальный адрес → адрес
 *                                интерфейса правила. Здесь известен адрес назначения, поэтому
 *                                исключения (локальная сеть, loopback) — фильтрами службы с
 *                                большим весом;
 *   ALE_BIND_REDIRECT_V4/V6    — привязка UDP-сокета (к «любому» адресу или адресу другого
 *                                интерфейса — сбор ICE-кандидатов): → адрес интерфейса правила.
 *                                TCP здесь не трогается: адрес назначения ещё неизвестен.
 * Блокировка при отсутствии адреса — обычными фильтрами службы, без драйвера.
 */

#include <ntddk.h>
#pragma warning(push)
#pragma warning(disable : 4201 4324)   /* заголовки WFP/NDIS: безымянные структуры, выравнивание */
#include <fwpsk.h>
#pragma warning(pop)
#include <fwpmk.h>

#include <initguid.h>
#include "AppRouteWfpShared.h"

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD DriverUnload;

static PDEVICE_OBJECT g_device = NULL;

typedef struct CALLOUT_REG {
    const GUID* key;
    BOOLEAN bind;     /* TRUE — bind redirect, FALSE — connect redirect */
    BOOLEAN v6;
    UINT32 id;
} CALLOUT_REG;

static CALLOUT_REG g_callouts[] = {
    {&APPROUTE_CALLOUT_BIND_V4, TRUE, FALSE, 0},
    {&APPROUTE_CALLOUT_BIND_V6, TRUE, TRUE, 0},
    {&APPROUTE_CALLOUT_CONNECT_V4, FALSE, FALSE, 0},
    {&APPROUTE_CALLOUT_CONNECT_V6, FALSE, TRUE, 0},
};

/* Цель из контекста провайдера фильтра; NULL — контекста нет или он не нашего формата */
static const APPROUTE_TARGET* TargetOf(const FWPS_FILTER3* filter)
{
    const FWPM_PROVIDER_CONTEXT3* pc = filter->providerContext;
    if (pc == NULL || pc->type != FWPM_GENERAL_CONTEXT || pc->dataBuffer == NULL ||
        pc->dataBuffer->size != sizeof(APPROUTE_TARGET) || pc->dataBuffer->data == NULL) {
        return NULL;
    }
    const APPROUTE_TARGET* t = (const APPROUTE_TARGET*)pc->dataBuffer->data;
    return t->version == APPROUTE_TARGET_VERSION ? t : NULL;
}

/* Адреса, которые не трогаем: loopback, link-local, multicast */
static BOOLEAN KeepV4(const UCHAR* a)
{
    return a[0] == 127 || (a[0] == 169 && a[1] == 254) || a[0] >= 224;
}

static BOOLEAN IsZero(const UCHAR* a, SIZE_T size)
{
    for (SIZE_T i = 0; i < size; ++i) {
        if (a[i] != 0) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN KeepV6(const UCHAR* a)
{
    static const UCHAR loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (RtlCompareMemory(a, loopback, 16) == 16) {
        return TRUE;
    }
    if (a[0] == 0xFE && (a[1] & 0xC0) == 0x80) {
        return TRUE;   /* link-local */
    }
    if (a[0] == 0xFF) {
        return TRUE;   /* multicast */
    }
    /* ::ffff:a.b.c.d — IPv4 на двухстековом сокете: решает IPv4-часть */
    static const UCHAR mappedPrefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
    if (RtlCompareMemory(a, mappedPrefix, 12) == 12) {
        return TRUE;
    }
    return FALSE;
}

/* Подставить адрес интерфейса правила в локальный адрес; bind — привязка (не соединение).
   TRUE — адрес изменён. */
static BOOLEAN Retarget(SOCKADDR_STORAGE* local, const APPROUTE_TARGET* t, BOOLEAN bind)
{
    if (local->ss_family == AF_INET) {
        SOCKADDR_IN* sin = (SOCKADDR_IN*)local;
        UCHAR* a = (UCHAR*)&sin->sin_addr;
        if (!(t->flags & APPROUTE_TARGET_HAS_V4) || KeepV4(a)) {
            return FALSE;
        }
        if (RtlCompareMemory(a, t->v4, 4) == 4) {
            return FALSE;   /* уже наш адрес */
        }
        RtlCopyMemory(a, t->v4, 4);
        return TRUE;
    }
    if (local->ss_family == AF_INET6) {
        SOCKADDR_IN6* sin6 = (SOCKADDR_IN6*)local;
        UCHAR* a = (UCHAR*)&sin6->sin6_addr;
        if (IsZero(a, 16) && bind) {
            /* bind к "::": двухстековый сокет может соединяться и по IPv4 — адрес выберем при
               соединении (connect redirect), иначе IPv4 через него стал бы невозможен */
            return FALSE;
        }
        if (!(t->flags & APPROUTE_TARGET_HAS_V6) || KeepV6(a)) {
            return FALSE;
        }
        if (RtlCompareMemory(a, t->v6, 16) == 16) {
            return FALSE;
        }
        RtlCopyMemory(a, t->v6, 16);
        sin6->sin6_scope_id = t->v6ScopeId;
        return TRUE;
    }
    return FALSE;
}

static void PermitAndKeepWriting(FWPS_CLASSIFY_OUT0* classifyOut, const FWPS_FILTER3* filter)
{
    classifyOut->actionType = FWP_ACTION_PERMIT;
    if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

static void NTAPI Classify(const FWPS_INCOMING_VALUES0* inFixedValues, const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
                           void* layerData, const void* classifyContext, const FWPS_FILTER3* filter,
                           UINT64 flowContext, FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);

    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) {
        return;   /* решение уже принято фильтром с большим весом */
    }
    const APPROUTE_TARGET* target = TargetOf(filter);
    if (target == NULL || classifyContext == NULL) {
        PermitAndKeepWriting(classifyOut, filter);
        return;
    }

    const UINT16 layer = inFixedValues->layerId;
    const BOOLEAN bind = layer == FWPS_LAYER_ALE_BIND_REDIRECT_V4 || layer == FWPS_LAYER_ALE_BIND_REDIRECT_V6;

    if (bind) {
        /* Привязка: только UDP. TCP получит адрес при соединении (connect redirect), когда
           известно назначение; серверные TCP-сокеты так вообще не затрагиваются */
        const UINT32 protoField = layer == FWPS_LAYER_ALE_BIND_REDIRECT_V4 ? FWPS_FIELD_ALE_BIND_REDIRECT_V4_IP_PROTOCOL
                                                                          : FWPS_FIELD_ALE_BIND_REDIRECT_V6_IP_PROTOCOL;
        if (inFixedValues->incomingValue[protoField].value.uint8 != IPPROTO_UDP) {
            PermitAndKeepWriting(classifyOut, filter);
            return;
        }
    }

    UINT64 handle = 0;
    if (!NT_SUCCESS(FwpsAcquireClassifyHandle0((void*)classifyContext, 0, &handle))) {
        PermitAndKeepWriting(classifyOut, filter);
        return;
    }
    void* writable = NULL;
    if (NT_SUCCESS(FwpsAcquireWritableLayerDataPointer0(handle, filter->filterId, 0, &writable, classifyOut)) &&
        writable != NULL) {
        BOOLEAN changed = FALSE;
        if (bind) {
            FWPS_BIND_REQUEST0* request = (FWPS_BIND_REQUEST0*)writable;
            changed = Retarget(&request->localAddressAndPort, target, TRUE);
        } else {
            FWPS_CONNECT_REQUEST0* request = (FWPS_CONNECT_REQUEST0*)writable;
            changed = Retarget(&request->localAddressAndPort, target, FALSE);
        }
        /* Изменения применяются всегда — иначе выданный указатель не освободится */
        FwpsApplyModifiedLayerData0(handle, writable, 0);
        UNREFERENCED_PARAMETER(changed);
    }
    FwpsReleaseClassifyHandle0(handle);
    PermitAndKeepWriting(classifyOut, filter);
}

static NTSTATUS NTAPI Notify(FWPS_CALLOUT_NOTIFY_TYPE notifyType, const GUID* filterKey, FWPS_FILTER3* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static void UnregisterCallouts(void)
{
    for (ULONG i = 0; i < RTL_NUMBER_OF(g_callouts); ++i) {
        if (g_callouts[i].id != 0) {
            FwpsCalloutUnregisterById0(g_callouts[i].id);
            g_callouts[i].id = 0;
        }
    }
}

static void DriverUnload(PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);
    UnregisterCallouts();
    if (g_device != NULL) {
        IoDeleteDevice(g_device);
        g_device = NULL;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);
    driverObject->DriverUnload = DriverUnload;

    /* Безымянное устройство: открыть его из пользовательского режима нельзя */
    NTSTATUS status = IoCreateDevice(driverObject, 0, NULL, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &g_device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (ULONG i = 0; i < RTL_NUMBER_OF(g_callouts); ++i) {
        FWPS_CALLOUT3 callout = {0};
        callout.calloutKey = *g_callouts[i].key;
        callout.classifyFn = Classify;
        callout.notifyFn = Notify;
        status = FwpsCalloutRegister3(g_device, &callout, &g_callouts[i].id);
        if (!NT_SUCCESS(status)) {
            DriverUnload(driverObject);
            return status;
        }
    }
    return STATUS_SUCCESS;
}
