import Foundation

final class TaskRunner {
    private(set) var status: String = "Idle"
    private(set) var currentTask: CollectorTask = .defaultTask

    private let tcpdump = TcpdumpRunner()
    private let screenshotter = Screenshotter()
    private let uploader = Uploader()
    private let archiver = ZipArchiver()
    private let timerQueue = DispatchQueue(label: "escollector.taskrunner.timers")
    private let stateQueue = DispatchQueue(label: "escollector.taskrunner.state")
    private var screenshotTimer: DispatchSourceTimer?
    private var taskTimer: DispatchSourceTimer?
    private var completionHandler: ((Result<Void, Error>) -> Void)?
    private var isFinalizing = false

    func loadTask(from path: String = Paths.taskFile) throws -> CollectorTask {
        let task = try FileIO.readJSON(CollectorTask.self, from: path)
        currentTask = task
        status = "Task loaded: \(task.taskId)"
        return task
    }

    func setTask(_ task: CollectorTask) {
        currentTask = task
        status = "Task set: \(task.taskId)"
    }

    func runTask() -> Result<Void, Error> {
        let waitForCompletion = prepareCompletionWait()
        do {
            try startTask()
        } catch {
            completionHandler = nil
            return .failure(error)
        }
        return waitForCompletion()
    }

    func startTask() throws {
        try ensureEmptyAnalysisDir()
        let taskId = currentTask.taskId
        let analysisDir = Paths.analysisDir(taskId: taskId)
        let taskDir = Paths.taskDir(taskId: taskId)
        try FileIO.ensureDir(analysisDir)
        try FileIO.ensureDir(taskDir)
        try FileIO.ensureDir(Paths.screenshotsDir(taskId: taskId))
        try writeExtensionConfig()
        try writeAnalysisJSON()
        try writeTaskJSON()
        try tcpdump.start(interface: currentTask.tcpdumpInterface, outputPath: Paths.pcapPath(taskId: taskId))
        startScreenshots()
        startTaskTimer()
        status = "Running task \(taskId)"
    }

    func updateTargetPid(_ pid: Int) {
        currentTask = currentTask.withTargetPid(pid)
        do {
            try writeExtensionConfig()
        } catch {
            status = "Failed to update target pid: \(error.localizedDescription)"
        }
    }

    private func ensureEmptyAnalysisDir() throws {
        var taskId = currentTask.taskId
        let fileManager = FileManager.default
        var attempt = 0
        while true {
            let analysisDir = Paths.analysisDir(taskId: taskId)
            if !fileManager.fileExists(atPath: analysisDir) {
                break
            }
            let contents = try fileManager.contentsOfDirectory(atPath: analysisDir)
            if contents.isEmpty {
                break
            }
            attempt += 1
            taskId = incrementTaskId(base: currentTask.taskId, attempt: attempt)
        }
        if taskId != currentTask.taskId {
            currentTask = currentTask.withTaskId(taskId)
            status = "Task id updated to \(taskId) due to existing data"
        }
    }

    private func incrementTaskId(base: String, attempt: Int) -> String {
        if let underscoreIndex = base.lastIndex(of: "_") {
            let analysisId = String(base[..<underscoreIndex])
            let suffix = String(base[underscoreIndex...])
            return "\(analysisId)-\(attempt)\(suffix)"
        }
        return "\(base)-\(attempt)"
    }

    func stopTask() {
        tcpdump.stop()
        stopScreenshots()
        stopTaskTimer()
        status = "Task stopped"
    }

    func uploadAndReset(completion: ((Result<Void, Error>) -> Void)? = nil) {
        let shouldProceed = stateQueue.sync { () -> Bool in
            if isFinalizing { return false }
            isFinalizing = true
            return true
        }
        guard shouldProceed else { return }

        stopTask()
        do {
            let zipPath = "\(Paths.analysisDir(taskId: currentTask.taskId)).zip"
            try archiver.archive(sourceDir: Paths.analysisDir(taskId: currentTask.taskId), destinationZip: zipPath)
            uploader.upload(zipPath: zipPath, apiURL: currentTask.apiURL, apiToken: currentTask.apiToken) { [weak self] result in
                guard let self = self else { return }
                switch result {
                case .success:
                    self.status = "Uploaded successfully"
                    self.runResetCommand()
                    self.finishTask(.success(()))
                case .failure(let error):
                    self.status = "Upload failed: \(error.localizedDescription)"
                    self.finishTask(.failure(error))
                }
                completion?(result)
            }
        } catch {
            status = "Archive failed: \(error.localizedDescription)"
            finishTask(.failure(error))
            completion?(.failure(error))
        }
    }

    private func finishTask(_ result: Result<Void, Error>) {
        stateQueue.sync {
            completionHandler?(result)
            completionHandler = nil
        }
    }

    func prepareCompletionWait() -> () -> Result<Void, Error> {
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<Void, Error> = .success(())
        completionHandler = { completion in
            result = completion
            semaphore.signal()
        }
        return {
            semaphore.wait()
            return result
        }
    }

    private func startScreenshots() {
        let interval = max(1, currentTask.screenshotIntervalSeconds)
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.schedule(deadline: .now() + .seconds(interval), repeating: .seconds(interval))
        timer.setEventHandler { [weak self] in
            self?.captureScreenshot()
        }
        timer.resume()
        screenshotTimer = timer
    }

    private func stopScreenshots() {
        screenshotTimer?.cancel()
        screenshotTimer = nil
    }

    private func startTaskTimer() {
        let duration = max(1, currentTask.durationSeconds)
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.schedule(deadline: .now() + .seconds(duration), repeating: .never)
        timer.setEventHandler { [weak self] in
            self?.uploadAndReset()
        }
        timer.resume()
        taskTimer = timer
    }

    private func stopTaskTimer() {
        taskTimer?.cancel()
        taskTimer = nil
    }

    private func captureScreenshot() {
        let filename = "\(Int(Date().timeIntervalSince1970)).jpg"
        let path = "\(Paths.screenshotsDir(taskId: currentTask.taskId))/\(filename)"
        do {
            try screenshotter.capture(to: URL(fileURLWithPath: path))
        } catch {
            status = "Screenshot failed: \(error.localizedDescription)"
        }
    }

    private func writeExtensionConfig() throws {
        let config = ExtensionConfig(
            targetPid: currentTask.targetPid,
            targetPath: currentTask.targetPath,
            outputPath: Paths.eventsPath(taskId: currentTask.taskId)
        )
        try FileIO.writeJSON(config, to: Paths.extensionConfigFile)
    }

    private func writeAnalysisJSON() throws {
        let analysisId = Paths.analysisId(from: currentTask.taskId)
        let payload: [String: Any] = [
            "id": analysisId,
            "created_on": isoTimestamp(),
            "category": "file",
            "kind": "standard",
            "state": "running",
            "score": 0,
            "tasks": [
                [
                    "id": currentTask.taskId,
                    "platform": "macos",
                    "os_version": "",
                    "state": "running",
                    "score": 0,
                ],
            ],
            "settings": [
                "timeout": currentTask.durationSeconds,
                "manual": false,
                "priority": 1,
            ],
        ]
        try writeJSONDictionary(payload, to: "\(Paths.analysisDir(taskId: currentTask.taskId))/analysis.json")
    }

    private func writeTaskJSON() throws {
        let payload: [String: Any] = [
            "id": currentTask.taskId,
            "analysis_id": Paths.analysisId(from: currentTask.taskId),
            "platform": "macos",
            "os_version": "",
            "state": "running",
            "score": 0,
        ]
        let path = "\(Paths.taskDir(taskId: currentTask.taskId))/task.json"
        try writeJSONDictionary(payload, to: path)
    }

    private func writeJSONDictionary(_ payload: [String: Any], to path: String) throws {
        let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted])
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
    }

    private func isoTimestamp() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: Date())
    }

    private func runResetCommand() {
        guard let reset = currentTask.resetCommand, !reset.isEmpty else { return }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/sh")
        proc.arguments = ["-c", reset]
        try? proc.run()
    }
}
