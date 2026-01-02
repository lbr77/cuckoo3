import CryptoKit
import Foundation

final class DaemonRunner {
    private let config: DaemonConfig
    private let session: URLSession

    init(config: DaemonConfig) {
        self.config = config
        let cfg = URLSessionConfiguration.default
        cfg.timeoutIntervalForRequest = 30
        cfg.timeoutIntervalForResource = 300
        self.session = URLSession(configuration: cfg)
    }

    func runForever() {
        logInfo("Daemon starting. Poll interval \(config.pollIntervalSeconds)s")
        while true {
            autoreleasepool {
                do {
                    if let response = try fetchTask() {
                        handleTask(response)
                    } else {
                        sleep(UInt32(max(1, config.pollIntervalSeconds)))
                    }
                } catch {
                    logError("Fetch failed: \(error.localizedDescription)")
                    sleep(UInt32(max(1, config.pollIntervalSeconds)))
                }
            }
        }
    }

    private func handleTask(_ response: RemoteTaskResponse) {
        var task = response.task

        if let ackEndpoint = config.taskAckEndpoint {
            _ = notify(endpoint: ackEndpoint, taskId: task.taskId)
        }

        let workingDir = response.workingDir ?? taskWorkingDir(taskId: task.taskId)
        try? FileIO.ensureDir(workingDir)
        if let packageURL = response.packageURL {
            do {
                let downloaded = try downloadPackage(from: packageURL, taskId: task.taskId, expectedSHA256: response.packageSHA256)
                let pkgDir = downloaded.deletingLastPathComponent().path
                try maybeUnzip(downloaded, into: pkgDir, shouldUnzip: response.packageUnzip ?? isZip(path: downloaded.path))
                logInfo("Package ready at \(downloaded.path)")
            } catch {
                logError("Package download failed: \(error.localizedDescription)")
                return
            }
        }

        if let command = response.command, !command.isEmpty {
            runCommandTask(task: task, command: command, workingDir: workingDir, terminateOnCompletion: response.terminateOnCompletion ?? false)
            return
        }

        if let commandString = response.commandString, !commandString.isEmpty {
            runCommandTask(task: task, commandString: commandString, workingDir: workingDir, terminateOnCompletion: response.terminateOnCompletion ?? false)
            return
        }

        guard task.targetPid != nil else {
            logError("Task \(task.taskId) missing targetPid and command")
            return
        }

        let runner = TaskRunner()
        runner.setTask(task)
        let result = runner.runTask()
        _ = finalize(result: result, taskId: task.taskId)
    }

    private func runCommandTask(task: CollectorTask, command: [String], workingDir: String, terminateOnCompletion: Bool) {
        do {
            let process = try ProcessLauncher.launch(command: command, workingDir: workingDir)
            runTaskWithProcess(task: task, process: process, terminateOnCompletion: terminateOnCompletion)
        } catch {
            logError("Launch failed: \(error.localizedDescription)")
        }
    }

    private func runCommandTask(task: CollectorTask, commandString: String, workingDir: String, terminateOnCompletion: Bool) {
        do {
            let process = try ProcessLauncher.launch(commandString: commandString, workingDir: workingDir)
            runTaskWithProcess(task: task, process: process, terminateOnCompletion: terminateOnCompletion)
        } catch {
            logError("Launch failed: \(error.localizedDescription)")
        }
    }

    private func runTaskWithProcess(task: CollectorTask, process: Process, terminateOnCompletion: Bool) {
        let runner = TaskRunner()
        let updated = task.withTargetPid(Int(process.processIdentifier))
        runner.setTask(updated)
        ProcessLauncher.waitForExit(process) { [weak self] in
            runner.uploadAndReset()
            self?.logInfo("Process exited pid=\(process.processIdentifier)")
        }
        let result = runner.runTask()
        if terminateOnCompletion {
            if process.isRunning {
                process.terminate()
            }
            runner.uploadAndReset()
        }
        _ = finalize(result: result, taskId: task.taskId)
    }

    private func finalize(result: Result<Void, Error>, taskId: String) -> Bool {
        switch result {
        case .success:
            if let completeEndpoint = config.taskCompleteEndpoint {
                _ = notify(endpoint: completeEndpoint, taskId: taskId)
            }
            return true
        case .failure(let error):
            logError("Task \(taskId) failed: \(error.localizedDescription)")
            return false
        }
    }

    private func fetchTask() throws -> RemoteTaskResponse? {
        let endpoint = urlJoin(config.apiURL, config.taskEndpoint)
        guard let url = URL(string: endpoint) else {
            throw NSError(domain: "ESCollector", code: 40, userInfo: [NSLocalizedDescriptionKey: "Invalid task endpoint"])
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("token \(config.apiToken)", forHTTPHeaderField: "Authorization")

        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<RemoteTaskResponse?, Error> = .success(nil)

        session.dataTask(with: request) { data, response, error in
            defer { semaphore.signal() }
            if let error = error {
                result = .failure(error)
                return
            }
            guard let http = response as? HTTPURLResponse else {
                result = .failure(NSError(domain: "ESCollector", code: 41, userInfo: [NSLocalizedDescriptionKey: "Invalid response"]))
                return
            }
            if http.statusCode == 204 {
                result = .success(nil)
                return
            }
            guard http.statusCode == 200, let data = data else {
                result = .failure(NSError(domain: "ESCollector", code: 42, userInfo: [NSLocalizedDescriptionKey: "Task fetch failed: \(http.statusCode)"]))
                return
            }
            do {
                let task = try JSONDecoder().decode(RemoteTaskResponse.self, from: data)
                result = .success(task)
            } catch {
                result = .failure(error)
            }
        }.resume()

        semaphore.wait()
        switch result {
        case .success(let response):
            return response
        case .failure(let error):
            throw error
        }
    }

    private func downloadPackage(from packageURL: String, taskId: String, expectedSHA256: String?) throws -> URL {
        guard let url = URL(string: packageURL) else {
            throw NSError(domain: "ESCollector", code: 43, userInfo: [NSLocalizedDescriptionKey: "Invalid package URL"])
        }
        let packageDir = "\(config.downloadDir)/\(taskId)/package"
        try FileIO.ensureDir(packageDir)
        let filename = url.lastPathComponent.isEmpty ? "package.bin" : url.lastPathComponent
        let destination = URL(fileURLWithPath: packageDir).appendingPathComponent(filename)

        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<Void, Error> = .success(())

        session.downloadTask(with: url) { tempURL, response, error in
            defer { semaphore.signal() }
            if let error = error {
                result = .failure(error)
                return
            }
            guard let tempURL = tempURL else {
                result = .failure(NSError(domain: "ESCollector", code: 44, userInfo: [NSLocalizedDescriptionKey: "Empty download"]))
                return
            }
            do {
                if FileManager.default.fileExists(atPath: destination.path) {
                    try FileManager.default.removeItem(at: destination)
                }
                try FileManager.default.moveItem(at: tempURL, to: destination)
            } catch {
                result = .failure(error)
            }
        }.resume()

        semaphore.wait()
        switch result {
        case .success:
            if let expected = expectedSHA256 {
                let actual = try sha256Hex(of: destination)
                if actual.lowercased() != expected.lowercased() {
                    throw NSError(domain: "ESCollector", code: 45, userInfo: [NSLocalizedDescriptionKey: "SHA256 mismatch"])
                }
            }
            return destination
        case .failure(let error):
            throw error
        }
    }

    private func maybeUnzip(_ file: URL, into dir: String, shouldUnzip: Bool) throws {
        guard shouldUnzip else { return }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        process.arguments = ["-o", file.path, "-d", dir]
        try process.run()
        process.waitUntilExit()
    }

    private func isZip(path: String) -> Bool {
        return path.lowercased().hasSuffix(".zip")
    }

    private func sha256Hex(of file: URL) throws -> String {
        let data = try Data(contentsOf: file)
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func taskWorkingDir(taskId: String) -> String {
        return "\(config.downloadDir)/\(taskId)"
    }

    private func notify(endpoint: String, taskId: String) -> Bool {
        let urlString = urlJoin(config.apiURL, endpoint)
        guard let url = URL(string: urlString) else {
            return false
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("token \(config.apiToken)", forHTTPHeaderField: "Authorization")
        let body = ["task_id": taskId]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body, options: [])
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let semaphore = DispatchSemaphore(value: 0)
        var ok = false
        session.dataTask(with: request) { _, response, _ in
            defer { semaphore.signal() }
            if let http = response as? HTTPURLResponse, http.statusCode == 200 {
                ok = true
            }
        }.resume()
        semaphore.wait()
        return ok
    }

    private func urlJoin(_ base: String, _ path: String) -> String {
        let baseTrimmed = base.hasSuffix("/") ? String(base.dropLast()) : base
        if path.hasPrefix("/") {
            return baseTrimmed + path
        }
        return baseTrimmed + "/" + path
    }

    private func logInfo(_ message: String) {
        FileHandle.standardError.write(Data("[Daemon] \(message)\n".utf8))
    }

    private func logError(_ message: String) {
        FileHandle.standardError.write(Data("[Daemon] Error: \(message)\n".utf8))
    }
}
