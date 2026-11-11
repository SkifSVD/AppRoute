add_executable(approute-tests main.cpp Test.h RouteManagerTests.cpp ConflictGuardTests.cpp NrptTests.cpp RuleEditTests.cpp AddWizardTests.cpp ShortcutTests.cpp PrimarySwitchTests.cpp ManagerTests.cpp ServiceTests.cpp Socks5Tests.cpp WfpPlanTests.cpp PackagedAppsTests.cpp AutostartTests.cpp SetupTests.cpp HookLogTests.cpp)
target_link_libraries(approute-tests PRIVATE approute_core)
add_test(NAME approute-tests COMMAND approute-tests)
