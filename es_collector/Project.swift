import ProjectDescription

let project = Project(
    name: "ESCollector",
    organizationName: "cuckoo",
    settings: .settings(
        base: [
            "CODE_SIGN_STYLE": "Automatic",
            "DEVELOPMENT_TEAM": "HUAKL3MKPR"
        ]
    ),
    targets: [
        .target(
            name: "ESCollectorHost",
            destinations: .macOS,
            product: .app,
            bundleId: "dev.nvme0n1p.se",
            deploymentTargets: .macOS("13.0"),
            infoPlist: .file(path: "Resources/Host/Info.plist"),
            sources: ["Sources/HostApp/**"],
            resources: [],
            entitlements: .file(path: "Entitlements/Host.entitlements"),
            dependencies: [
                .target(name: "ESCollectorExtension"),
                .sdk(name: "AppKit", type: .framework),
                .sdk(name: "CoreGraphics", type: .framework),
                .sdk(name: "SystemExtensions", type: .framework),
            ],
            settings: .settings(
                base: [
                    "CODE_SIGN_STYLE": "Automatic",
                    "DEVELOPMENT_TEAM": "HUAKL3MKPR",
                    "CODE_SIGN_IDENTITY": "Apple Development",
                ]
            )
        ),
        .target(
            name: "ESCollectorExtension",
            destinations: .macOS,
            product: .systemExtension,
            productName: "dev.nvme0n1p.se.rotinom",
            bundleId: "dev.nvme0n1p.se.rotinom",
            deploymentTargets: .macOS("13.0"),
            infoPlist: .file(path: "Resources/Extension/Info.plist"),
            sources: ["Sources/Extension/**"],
            resources: [],
            entitlements: .file(path: "Entitlements/Extension.entitlements"),
            dependencies: [
                .sdk(name: "EndpointSecurity", type: .library),
                .sdk(name: "bsm", type: .library),
            ],
            settings: .settings(
                base: [
                    "CODE_SIGN_STYLE": "Automatic",
                    "DEVELOPMENT_TEAM": "HUAKL3MKPR",
                    "CODE_SIGN_IDENTITY": "Apple Development",
                    "EXECUTABLE_NAME": "ESCollectorExtension",
                ]
            )
        ),
    ]
)
