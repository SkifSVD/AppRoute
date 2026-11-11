add_executable(approute-gui WIN32
    main.cpp
    resource.h
    approute-gui.rc
    approute-gui.manifest
)

target_link_libraries(approute-gui PRIVATE approute_core comctl32 comdlg32 uxtheme)
approute_version_resource(approute-gui "AppRoute — маршрутизация по приложениям")
