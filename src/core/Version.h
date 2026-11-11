#pragma once

// Версия AppRoute (#63): из project(AppRoute VERSION ...) в CMakeLists.txt, при сборке к ней
// добавляется коммит git ("0.1.0+1a2b3c4d", с "-dirty" при незакоммиченных изменениях).

namespace approute {

// "0.1.0"
const wchar_t* AppRouteVersion();

// "0.1.0+1a2b3c4d" — для журналов и --version; без git — как AppRouteVersion()
const wchar_t* AppRouteBuild();

} // namespace approute
