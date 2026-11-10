add_executable(approute-tests main.cpp Test.h RouteManagerTests.cpp ConflictGuardTests.cpp NrptTests.cpp RuleEditTests.cpp AddWizardTests.cpp ShortcutTests.cpp)
target_link_libraries(approute-tests PRIVATE approute_core)
add_test(NAME approute-tests COMMAND approute-tests)
