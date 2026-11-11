#include "core/Version.h"

#include "AppRouteVersion.h"   // создаётся при сборке: cmake/GitVersion.cmake

namespace approute {

const wchar_t* AppRouteVersion()
{
    return APPROUTE_VERSION_W;
}

const wchar_t* AppRouteBuild()
{
    return APPROUTE_BUILD_W;
}

} // namespace approute
