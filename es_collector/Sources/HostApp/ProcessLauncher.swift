import Foundation

enum ProcessLauncher {
    static func launch(command: [String], workingDir: String?) throws -> Process {
        guard let executable = command.first else {
            throw NSError(domain: "ESCollector", code: 30, userInfo: [NSLocalizedDescriptionKey: "Empty command"])
        }
        let process = Process()
        if executable.contains("/") {
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = Array(command.dropFirst())
        } else {
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = command
        }
        if let workingDir = workingDir {
            process.currentDirectoryURL = URL(fileURLWithPath: workingDir)
        }
        try process.run()
        return process
    }

    static func launch(commandString: String, workingDir: String?) throws -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", commandString]
        if let workingDir = workingDir {
            process.currentDirectoryURL = URL(fileURLWithPath: workingDir)
        }
        try process.run()
        return process
    }

    static func waitForExit(_ process: Process, onExit: @escaping () -> Void) {
        DispatchQueue.global().async {
            process.waitUntilExit()
            onExit()
        }
    }
}
