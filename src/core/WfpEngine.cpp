// Ключи слоёв и условий WFP (FWPM_LAYER_*, FWPM_CONDITION_*) — определения в этой единице
#include <initguid.h>

#include "core/WfpEngine.h"

#include "core/Util.h"

#include <fwpmu.h>
#include <sddl.h>

#include <format>
#include <memory>

namespace approute {

namespace {

constexpr UINT8 kWeightExempt = 15;
constexpr UINT8 kWeightBlock = 12;
constexpr UINT8 kWeightCallout = 10;

struct LocalDeleter {
    void operator()(void* p) const { LocalFree(p); }
};

bool Fail(std::wstring* error, const std::wstring& what, DWORD code)
{
    if (error) {
        *error = std::format(L"{}: {} (0x{:08X})", what, Win32ErrorMessage(code), code);
    }
    return false;
}

FWPM_DISPLAY_DATA0 Display(const wchar_t* name, const wchar_t* description = L"")
{
    FWPM_DISPLAY_DATA0 d{};
    d.name = const_cast<wchar_t*>(name);
    d.description = const_cast<wchar_t*>(description);
    return d;
}

struct Callout {
    const GUID* key;
    const GUID* layer;
    const wchar_t* name;
};

const Callout kCallouts[] = {
    {&APPROUTE_CALLOUT_CONNECT_V4, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, L"AppRoute connect redirect v4"},
    {&APPROUTE_CALLOUT_CONNECT_V6, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, L"AppRoute connect redirect v6"},
    {&APPROUTE_CALLOUT_BIND_V4, &FWPM_LAYER_ALE_BIND_REDIRECT_V4, L"AppRoute bind redirect v4"},
    {&APPROUTE_CALLOUT_BIND_V6, &FWPM_LAYER_ALE_BIND_REDIRECT_V6, L"AppRoute bind redirect v6"},
};

FWP_V4_ADDR_AND_MASK V4Mask(const WfpExemption& e)
{
    FWP_V4_ADDR_AND_MASK m{};
    m.addr = ntohl(e.prefix.Ipv4.sin_addr.s_addr);
    m.mask = e.length == 0 ? 0 : 0xFFFFFFFFu << (32 - e.length);
    return m;
}

FWP_V6_ADDR_AND_MASK V6Mask(const WfpExemption& e)
{
    FWP_V6_ADDR_AND_MASK m{};
    std::memcpy(m.addr, &e.prefix.Ipv6.sin6_addr, 16);
    m.prefixLength = e.length;
    return m;
}

} // namespace

WfpEngine::~WfpEngine()
{
    Close();
}

bool WfpEngine::Open(std::wstring* error)
{
    if (engine_) {
        return true;
    }
    FWPM_SESSION0 session{};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;   // объекты удаляются вместе с сессией
    session.displayData = Display(L"AppRoute", L"Правила AppRoute для программ (драйвер approute-wfp)");
    const DWORD rc = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine_);
    if (rc != ERROR_SUCCESS) {
        engine_ = nullptr;
        return Fail(error, L"нет доступа к службе фильтрации (BFE)", rc);
    }
    return true;
}

void WfpEngine::Close()
{
    if (engine_) {
        FwpmEngineClose0(engine_);   // динамическая сессия: все наши объекты удаляются
        engine_ = nullptr;
    }
    baseAdded_ = false;
    filterIds_.clear();
    contextIds_.clear();
}

bool WfpEngine::EnsureBaseObjects(std::wstring* error)
{
    if (baseAdded_) {
        return true;
    }
    FWPM_PROVIDER0 provider{};
    provider.providerKey = APPROUTE_WFP_PROVIDER;
    provider.displayData = Display(L"AppRoute", L"Маршрутизация по приложениям");
    DWORD rc = FwpmProviderAdd0(engine_, &provider, nullptr);
    if (rc != ERROR_SUCCESS && rc != static_cast<DWORD>(FWP_E_ALREADY_EXISTS)) {
        return Fail(error, L"не удалось добавить провайдера WFP", rc);
    }
    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = APPROUTE_WFP_SUBLAYER;
    sublayer.displayData = Display(L"AppRoute");
    sublayer.providerKey = const_cast<GUID*>(&APPROUTE_WFP_PROVIDER);
    sublayer.weight = 0x100;
    rc = FwpmSubLayerAdd0(engine_, &sublayer, nullptr);
    if (rc != ERROR_SUCCESS && rc != static_cast<DWORD>(FWP_E_ALREADY_EXISTS)) {
        return Fail(error, L"не удалось добавить подслой WFP", rc);
    }
    for (const Callout& c : kCallouts) {
        FWPM_CALLOUT0 callout{};
        callout.calloutKey = *c.key;
        callout.displayData = Display(c.name);
        callout.providerKey = const_cast<GUID*>(&APPROUTE_WFP_PROVIDER);
        callout.applicableLayer = *c.layer;
        // Без этого флага WFP не передаёт драйверу контекст провайдера фильтра (цель правила):
        // FWPS_FILTER3::providerContext приходит NULL
        callout.flags = FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT;
        rc = FwpmCalloutAdd0(engine_, &callout, nullptr, nullptr);
        if (rc != ERROR_SUCCESS && rc != static_cast<DWORD>(FWP_E_ALREADY_EXISTS)) {
            return Fail(error, L"не удалось добавить callout WFP", rc);
        }
    }
    baseAdded_ = true;
    return true;
}

void WfpEngine::RemoveRuleObjects()
{
    for (const UINT64 id : filterIds_) {
        FwpmFilterDeleteById0(engine_, id);
    }
    for (const UINT64 id : contextIds_) {
        FwpmProviderContextDeleteById0(engine_, id);
    }
    filterIds_.clear();
    contextIds_.clear();
}

bool WfpEngine::Apply(const WfpPlan& plan, std::vector<std::wstring>* notes, std::wstring* error)
{
    if (!engine_ && !Open(error)) {
        return false;
    }
    DWORD rc = FwpmTransactionBegin0(engine_, 0);
    if (rc != ERROR_SUCCESS) {
        return Fail(error, L"не удалось начать транзакцию WFP", rc);
    }
    std::vector<UINT64> oldFilters = filterIds_;
    std::vector<UINT64> oldContexts = contextIds_;
    const auto abort = [&](const std::wstring& what, DWORD code) {
        FwpmTransactionAbort0(engine_);
        filterIds_ = std::move(oldFilters);
        contextIds_ = std::move(oldContexts);
        return Fail(error, what, code);
    };
    if (!EnsureBaseObjects(error)) {
        FwpmTransactionAbort0(engine_);
        baseAdded_ = false;
        return false;
    }
    RemoveRuleObjects();

    // Пользователь, давший согласие: ALE_USER_ID сравнивается с дескриптором, разрешающим ему
    // «совпадение фильтра» (FWP_ACTRL_MATCH_FILTER — право CC)
    PSECURITY_DESCRIPTOR userSd = nullptr;
    ULONG userSdSize = 0;
    const std::wstring sddl = L"O:SYG:SYD:(A;;CC;;;" + plan.userSid + L")";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &userSd, &userSdSize)) {
        return abort(L"неверный SID пользователя", GetLastError());
    }
    std::unique_ptr<void, LocalDeleter> userSdGuard(userSd);
    FWP_BYTE_BLOB userBlob{userSdSize, static_cast<UINT8*>(userSd)};

    const auto addFilter = [&](const GUID& layer, FWP_ACTION_TYPE action, const GUID* callout, UINT8 weight,
                               std::vector<FWPM_FILTER_CONDITION0>& conditions, const GUID* context,
                               const wchar_t* name) -> DWORD {
        FWPM_FILTER0 f{};
        f.displayData = Display(name);
        f.providerKey = const_cast<GUID*>(&APPROUTE_WFP_PROVIDER);
        f.layerKey = layer;
        f.subLayerKey = APPROUTE_WFP_SUBLAYER;
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = weight;
        f.numFilterConditions = static_cast<UINT32>(conditions.size());
        f.filterCondition = conditions.data();
        f.action.type = action;
        if (callout) {
            f.action.calloutKey = *callout;
        }
        if (context) {
            f.flags |= FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT;
            f.providerContextKey = *context;
        }
        UINT64 id = 0;
        const DWORD r = FwpmFilterAdd0(engine_, &f, nullptr, &id);
        if (r == ERROR_SUCCESS) {
            filterIds_.push_back(id);
        }
        return r;
    };

    for (const WfpAppFilter& rule : plan.filters) {
        FWP_BYTE_BLOB* appId = nullptr;
        rc = FwpmGetAppIdFromFileName0(rule.appPath.c_str(), &appId);
        if (rc != ERROR_SUCCESS) {
            if (notes) {
                notes->push_back(std::format(L"{}: программа не найдена ({}) — правило драйвером не применяется",
                                             rule.app, Win32ErrorMessage(rc)));
            }
            continue;
        }
        struct AppIdFree {
            FWP_BYTE_BLOB* p;
            ~AppIdFree() { FwpmFreeMemory0(reinterpret_cast<void**>(&p)); }
        } appIdFree{appId};

        // Контекст провайдера: цель для драйвера
        APPROUTE_TARGET target = rule.target;
        FWP_BYTE_BLOB data{sizeof(target), reinterpret_cast<UINT8*>(&target)};
        FWPM_PROVIDER_CONTEXT2 pc{};
        UuidCreate(&pc.providerContextKey);
        pc.displayData = Display(L"AppRoute: цель правила");
        pc.providerKey = const_cast<GUID*>(&APPROUTE_WFP_PROVIDER);
        pc.type = FWPM_GENERAL_CONTEXT;
        pc.dataBuffer = &data;
        UINT64 contextId = 0;
        rc = FwpmProviderContextAdd2(engine_, &pc, nullptr, &contextId);
        if (rc != ERROR_SUCCESS) {
            return abort(L"не удалось добавить контекст правила", rc);
        }
        contextIds_.push_back(contextId);

        std::vector<FWPM_FILTER_CONDITION0> base(2);
        base[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        base[0].matchType = FWP_MATCH_EQUAL;
        base[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        base[0].conditionValue.byteBlob = appId;
        base[1].fieldKey = FWPM_CONDITION_ALE_USER_ID;
        base[1].matchType = FWP_MATCH_EQUAL;
        base[1].conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
        base[1].conditionValue.sd = &userBlob;

        // Callout'ы драйвера
        for (const Callout& c : kCallouts) {
            std::vector<FWPM_FILTER_CONDITION0> conditions = base;
            rc = addFilter(*c.layer, FWP_ACTION_CALLOUT_TERMINATING, c.key, kWeightCallout, conditions,
                           &pc.providerContextKey, L"AppRoute: программа → интерфейс правила");
            if (rc != ERROR_SUCCESS) {
                return abort(L"не удалось добавить фильтр правила", rc);
            }
        }
        // Нет адреса нужного семейства и политика «блокировать»
        const struct {
            UINT32 has;
            UINT32 allowDefault;
            const GUID* layer;
        } families[] = {
            {APPROUTE_TARGET_HAS_V4, APPROUTE_TARGET_DEFAULT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V4},
            {APPROUTE_TARGET_HAS_V6, APPROUTE_TARGET_DEFAULT_V6, &FWPM_LAYER_ALE_AUTH_CONNECT_V6},
        };
        for (const auto& f : families) {
            if ((target.flags & f.has) || (target.flags & f.allowDefault)) {
                continue;
            }
            std::vector<FWPM_FILTER_CONDITION0> conditions = base;
            rc = addFilter(*f.layer, FWP_ACTION_BLOCK, nullptr, kWeightBlock, conditions, nullptr,
                           L"AppRoute: интерфейс правила недоступен — блокировка");
            if (rc != ERROR_SUCCESS) {
                return abort(L"не удалось добавить блокирующий фильтр", rc);
            }
        }
    }

    // Исключения: напрямую, без подмены адреса и без блокировки
    for (const WfpExemption& e : plan.exemptions) {
        const bool v4 = e.prefix.si_family == AF_INET;
        FWP_V4_ADDR_AND_MASK m4 = v4 ? V4Mask(e) : FWP_V4_ADDR_AND_MASK{};
        FWP_V6_ADDR_AND_MASK m6 = v4 ? FWP_V6_ADDR_AND_MASK{} : V6Mask(e);
        std::vector<FWPM_FILTER_CONDITION0> conditions(1);
        conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conditions[0].matchType = FWP_MATCH_EQUAL;
        if (v4) {
            conditions[0].conditionValue.type = FWP_V4_ADDR_MASK;
            conditions[0].conditionValue.v4AddrMask = &m4;
        } else {
            conditions[0].conditionValue.type = FWP_V6_ADDR_MASK;
            conditions[0].conditionValue.v6AddrMask = &m6;
        }
        for (const GUID* layer : {v4 ? &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4 : &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
                                  v4 ? &FWPM_LAYER_ALE_AUTH_CONNECT_V4 : &FWPM_LAYER_ALE_AUTH_CONNECT_V6}) {
            rc = addFilter(*layer, FWP_ACTION_PERMIT, nullptr, kWeightExempt, conditions, nullptr,
                           L"AppRoute: локальный адрес — напрямую");
            if (rc != ERROR_SUCCESS) {
                return abort(L"не удалось добавить исключение", rc);
            }
        }
    }

    rc = FwpmTransactionCommit0(engine_);
    if (rc != ERROR_SUCCESS) {
        return abort(L"не удалось применить фильтры WFP", rc);
    }
    return true;
}

bool IsWfpDriverRunning()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return false;
    }
    SC_HANDLE service = OpenServiceW(scm, L"approute-wfp", SERVICE_QUERY_STATUS);
    bool running = false;
    if (service) {
        SERVICE_STATUS status{};
        running = QueryServiceStatus(service, &status) && status.dwCurrentState == SERVICE_RUNNING;
        CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);
    return running;
}

} // namespace approute
