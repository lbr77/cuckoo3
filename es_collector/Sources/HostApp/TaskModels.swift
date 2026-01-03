import Foundation

struct CollectorTask: Codable {
    let taskId: String
    let targetPid: Int?
    let targetPath: String?
    let durationSeconds: Int
    let tcpdumpInterface: String
    let screenshotIntervalSeconds: Int
    let apiURL: String
    let apiToken: String
    let resetCommand: String?

    static let defaultTask = CollectorTask(
        taskId: "local-0001_1",
        targetPid: nil,
        targetPath: nil,
        durationSeconds: 60,
        tcpdumpInterface: "en0",
        screenshotIntervalSeconds: 5,
        apiURL: "http://127.0.0.1:8090",
        apiToken: "REPLACE_ME",
        resetCommand: nil
    )

    func withTargetPid(_ pid: Int?) -> CollectorTask {
        return CollectorTask(
            taskId: taskId,
            targetPid: pid,
            targetPath: targetPath,
            durationSeconds: durationSeconds,
            tcpdumpInterface: tcpdumpInterface,
            screenshotIntervalSeconds: screenshotIntervalSeconds,
            apiURL: apiURL,
            apiToken: apiToken,
            resetCommand: resetCommand
        )
    }

    func withTargetPath(_ path: String?) -> CollectorTask {
        return CollectorTask(
            taskId: taskId,
            targetPid: targetPid,
            targetPath: path,
            durationSeconds: durationSeconds,
            tcpdumpInterface: tcpdumpInterface,
            screenshotIntervalSeconds: screenshotIntervalSeconds,
            apiURL: apiURL,
            apiToken: apiToken,
            resetCommand: resetCommand
        )
    }

    func withTaskId(_ newTaskId: String) -> CollectorTask {
        return CollectorTask(
            taskId: newTaskId,
            targetPid: targetPid,
            targetPath: targetPath,
            durationSeconds: durationSeconds,
            tcpdumpInterface: tcpdumpInterface,
            screenshotIntervalSeconds: screenshotIntervalSeconds,
            apiURL: apiURL,
            apiToken: apiToken,
            resetCommand: resetCommand
        )
    }
}

struct ExtensionConfig: Codable {
    let targetPid: Int?
    let targetPath: String?
    let outputPath: String
    let outputDir: String?
}
