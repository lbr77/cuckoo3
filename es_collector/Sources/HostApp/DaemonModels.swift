import Foundation

struct DaemonConfig: Codable {
    let apiURL: String
    let apiToken: String
    let pollIntervalSeconds: Int
    let taskEndpoint: String
    let taskAckEndpoint: String?
    let taskCompleteEndpoint: String?
    let downloadDir: String

    static let defaultConfig = DaemonConfig(
        apiURL: "http://127.0.0.1:8090",
        apiToken: "REPLACE_ME",
        pollIntervalSeconds: 10,
        taskEndpoint: "/escollector/task",
        taskAckEndpoint: nil,
        taskCompleteEndpoint: nil,
        downloadDir: "/var/tmp/escollector_tasks"
    )
}

struct RemoteTaskResponse: Codable {
    let task: CollectorTask
    let packageURL: String?
    let packageSHA256: String?
    let packageUnzip: Bool?
    let command: [String]?
    let commandString: String?
    let workingDir: String?
    let terminateOnCompletion: Bool?

    enum CodingKeys: String, CodingKey {
        case task
        case packageURL = "package_url"
        case packageSHA256 = "package_sha256"
        case packageUnzip = "package_unzip"
        case command
        case commandString = "command_string"
        case workingDir = "working_dir"
        case terminateOnCompletion = "terminate_on_completion"
    }
}
