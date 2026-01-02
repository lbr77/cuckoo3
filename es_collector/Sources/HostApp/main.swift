import Foundation

enum CLI {
    static func run() -> Int32 {
        var args = Array(CommandLine.arguments.dropFirst())
        let taskFile = consumeOption("--task-file", from: &args) ?? Paths.taskFile
        let daemonConfigFile = consumeOption("--daemon-config", from: &args)

        guard let command = args.first else {
            printUsage()
            return 1
        }

        switch command {
        case "help", "-h", "--help":
            printUsage()
            return 0
        case "extension":
            return handleExtension(Array(args.dropFirst()))
        case "task":
            return handleTask(Array(args.dropFirst()), taskFile: taskFile)
        case "daemon":
            return handleDaemon(Array(args.dropFirst()), configFile: daemonConfigFile)
        default:
            logError("Unknown command: \(command)")
            printUsage()
            return 1
        }
    }

    private static func handleExtension(_ args: [String]) -> Int32 {
        guard let subcommand = args.first else {
            logError("Missing extension subcommand")
            printUsage()
            return 1
        }
        let manager = ExtensionManager()
        let result: Result<Void, Error>
        switch subcommand {
        case "activate":
            result = manager.activate()
        case "deactivate":
            result = manager.deactivate()
        default:
            logError("Unknown extension subcommand: \(subcommand)")
            printUsage()
            return 1
        }
        return handleResult(result, successMessage: "Extension \(subcommand) request completed")
    }

    private static func handleTask(_ args: [String], taskFile: String) -> Int32 {
        guard let subcommand = args.first else {
            logError("Missing task subcommand")
            printUsage()
            return 1
        }
        let runner = TaskRunner()
        switch subcommand {
        case "run", "start":
            do {
                let task = try runner.loadTask(from: taskFile)
                logInfo("Loaded task \(task.taskId)")
            } catch {
                logError("Failed to load task: \(error.localizedDescription)")
                return 1
            }
            let result = runner.runTask()
            return handleResult(result, successMessage: "Task completed")
        case "run-command":
            var runArgs = Array(args.dropFirst())
            let delayMsValue = consumeOption("--delay-ms", from: &runArgs)
            let delaySecondsValue = consumeOption("--delay", from: &runArgs)
            let commandArgs = extractCommandArgs(from: runArgs)
            guard !commandArgs.isEmpty else {
                logError("Missing command for run-command")
                printUsage()
                return 1
            }
            do {
                let task: CollectorTask
                if FileManager.default.fileExists(atPath: taskFile) {
                    task = try runner.loadTask(from: taskFile)
                    logInfo("Loaded task \(task.taskId)")
                } else {
                    task = .defaultTask
                    runner.setTask(task)
                    logInfo("Task file not found, using default task")
                }
                let resolvedTarget = resolveExecutable(commandArgs.first ?? "")
                let taskWithPath = task.withTargetPath(resolvedTarget)
                runner.setTask(taskWithPath)

                let waitForCompletion = runner.prepareCompletionWait()
                try runner.startTask()

                let delayMs = delayMsValue.flatMap { Int($0) } ?? 300
                let delaySeconds = delaySecondsValue.flatMap { Double($0) } ?? 0
                let totalDelay = max(0.0, delaySeconds) + (Double(max(0, delayMs)) / 1000.0)
                let escaped = commandArgs.map { shellEscape($0) }.joined(separator: " ")
                let cmd = "sleep \(totalDelay); exec \(escaped)"
                let process = try ProcessLauncher.launch(commandString: cmd, workingDir: nil)
                logInfo("Started pid \(process.processIdentifier)")
                runner.updateTargetPid(Int(process.processIdentifier))
                ProcessLauncher.waitForExit(process) {
                    runner.uploadAndReset()
                }
                let result = waitForCompletion()
                return handleResult(result, successMessage: "Task completed")
            } catch {
                logError("Failed to start command: \(error.localizedDescription)")
                return 1
            }
        case "upload-reset":
            do {
                let task = try runner.loadTask(from: taskFile)
                logInfo("Loaded task \(task.taskId)")
            } catch {
                logError("Failed to load task: \(error.localizedDescription)")
                return 1
            }
            let semaphore = DispatchSemaphore(value: 0)
            var finalResult: Result<Void, Error> = .success(())
            runner.uploadAndReset { result in
                finalResult = result
                semaphore.signal()
            }
            semaphore.wait()
            return handleResult(finalResult, successMessage: "Upload and reset completed")
        case "print":
            do {
                let task = try runner.loadTask(from: taskFile)
                let data = try JSONEncoder().encode(task)
                if let json = String(data: data, encoding: .utf8) {
                    print(json)
                }
                return 0
            } catch {
                logError("Failed to load task: \(error.localizedDescription)")
                return 1
            }
        default:
            logError("Unknown task subcommand: \(subcommand)")
            printUsage()
            return 1
        }
    }

    private static func handleDaemon(_ args: [String], configFile: String?) -> Int32 {
        guard let subcommand = args.first else {
            logError("Missing daemon subcommand")
            printUsage()
            return 1
        }
        guard subcommand == "run" else {
            logError("Unknown daemon subcommand: \(subcommand)")
            printUsage()
            return 1
        }
        do {
            let path = configFile ?? "/var/tmp/escollector_daemon.json"
            let config = try FileIO.readJSON(DaemonConfig.self, from: path)
            let daemon = DaemonRunner(config: config)
            daemon.runForever()
            return 0
        } catch {
            logError("Failed to load daemon config: \(error.localizedDescription)")
            return 1
        }
    }

    private static func handleResult(_ result: Result<Void, Error>, successMessage: String) -> Int32 {
        switch result {
        case .success:
            logInfo(successMessage)
            return 0
        case .failure(let error):
            logError(error.localizedDescription)
            return 1
        }
    }

    private static func consumeOption(_ name: String, from args: inout [String]) -> String? {
        guard let index = args.firstIndex(of: name), index + 1 < args.count else { return nil }
        let value = args[index + 1]
        args.removeSubrange(index...index + 1)
        return value
    }

    private static func extractCommandArgs(from args: [String]) -> [String] {
        if let separatorIndex = args.firstIndex(of: "--") {
            return Array(args[(separatorIndex + 1)...])
        }
        return args
    }

    private static func shellEscape(_ arg: String) -> String {
        if arg.isEmpty {
            return "''"
        }
        return "'" + arg.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func resolveExecutable(_ command: String) -> String? {
        if command.isEmpty {
            return nil
        }
        if command.contains("/") {
            return command
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        process.arguments = [command]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return nil
        }
        guard process.terminationStatus == 0 else {
            return nil
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
        return output?.isEmpty == false ? output : nil
    }

    private static func printUsage() {
        let usage = """
        Usage:
          ESCollectorHost extension activate
          ESCollectorHost extension deactivate
          ESCollectorHost task run
          ESCollectorHost task run-command [--delay <seconds> | --delay-ms <ms>] -- <command> [args...]
          ESCollectorHost task upload-reset
          ESCollectorHost task print
          ESCollectorHost daemon run

        Options:
          --task-file <path>    Default: \(Paths.taskFile)
          --daemon-config <path>  Default: /var/tmp/escollector_daemon.json
        """
        print(usage)
    }

    private static func logInfo(_ message: String) {
        FileHandle.standardError.write(Data("[CLI] \(message)\n".utf8))
    }

    private static func logError(_ message: String) {
        FileHandle.standardError.write(Data("[CLI] Error: \(message)\n".utf8))
    }
}

exit(CLI.run())
