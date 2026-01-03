import Foundation

enum Paths {
    static let baseDir = "/var/tmp/escollector_tasks"
    static let taskFile = "/var/tmp/escollector_task.json"
    static let extensionConfigFile = "/var/tmp/escollector_config.json"

    static func analysisId(from taskId: String) -> String {
        return taskId.split(separator: "_").first.map(String.init) ?? taskId
    }

    static func analysisDir(taskId: String) -> String {
        let analysisId = analysisId(from: taskId)
        return "\(baseDir)/\(analysisId)"
    }

    static func taskDir(taskId: String) -> String {
        let analysisId = analysisId(from: taskId)
        return "\(baseDir)/\(analysisId)/tasks/\(taskId)"
    }

    static func eventsPath(taskId: String) -> String {
        return "\(taskDir(taskId: taskId))/events.jsonl"
    }

    static func eventsDir(taskId: String) -> String {
        return "\(taskDir(taskId: taskId))/events"
    }

    static func pcapPath(taskId: String) -> String {
        return "\(taskDir(taskId: taskId))/pcap.pcap"
    }

    static func screenshotsDir(taskId: String) -> String {
        return "\(taskDir(taskId: taskId))/screenshots"
    }
}
