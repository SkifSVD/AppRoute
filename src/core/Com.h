#pragma once

// COM в текущем потоке на время области видимости (IShellLink и т.п.), если его ещё не
// инициализировали; уже инициализированный в другом режиме COM не трогается.

#include "core/Win.h"

#include <objbase.h>

namespace approute {

class ComScope {
public:
    ComScope() : hr_(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)) {}
    ~ComScope()
    {
        if (SUCCEEDED(hr_)) {
            CoUninitialize();
        }
    }
    ComScope(const ComScope&) = delete;
    ComScope& operator=(const ComScope&) = delete;

private:
    HRESULT hr_;
};

// Минимальный владелец COM-указателя
template <class T>
struct ComPtr {
    T* p = nullptr;
    ComPtr() = default;
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    ~ComPtr()
    {
        if (p) {
            p->Release();
        }
    }
    T** operator&() { return &p; }
    T* operator->() const { return p; }
    explicit operator bool() const { return p != nullptr; }
};

} // namespace approute
