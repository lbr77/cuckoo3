import EndpointSecurity
import Darwin
import Foundation
import os

final class ESCollector {
    private let log = Logger(subsystem: "com.cuckoo.escollector", category: "es")
    private let stateQueue = DispatchQueue(label: "com.cuckoo.escollector.state")
    private let stateKey = DispatchSpecificKey<Void>()
    private var client: OpaquePointer?
    private var targetPid: pid_t?
    private var targetPath: String?
    private var trackedPids = Set<pid_t>()
    private var configTimer: DispatchSourceTimer?
    private let configPath = "/var/tmp/escollector_config.json"
    private var outputPath = "/var/tmp/escollector_events.jsonl"
    private var outputHandle: FileHandle?

    init() {
        stateQueue.setSpecific(key: stateKey, value: ())
    }

    func start() {
        syncOnStateQueue {
            if client != nil {
                return
            }
        }

        openOutput()
        startConfigWatcher()

        var newClient: OpaquePointer?
        let result = es_new_client(&newClient) { [weak self] _, message in
            self?.handle(message: message)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let created = newClient else {
            log.error("Failed to create ES client: \(String(describing: result))")
            return
        }

        client = created

        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_CREATE,
            ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
            ES_EVENT_TYPE_NOTIFY_MOUNT,
            ES_EVENT_TYPE_NOTIFY_RENAME,
            ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_UNLINK,
        ]
        let subResult = events.withUnsafeBufferPointer { buffer in
            guard let base = buffer.baseAddress else {
                return ES_RETURN_ERROR
            }
            return es_subscribe(created, base, UInt32(buffer.count))
        }
        if subResult != ES_RETURN_SUCCESS {
            log.error("Failed to subscribe to ES events: \(String(describing: subResult))")
        } else {
            log.info("ES collector started")
        }
    }

    func stop() {
        syncOnStateQueue {
            if let client = client {
                es_unsubscribe_all(client)
                es_delete_client(client)
                self.client = nil
                trackedPids.removeAll()
            }
        }
        stopConfigWatcher()
        closeOutput()
    }

    func setTargetPid(_ pid: pid_t?) {
        syncOnStateQueue {
            targetPid = pid
            trackedPids = pid.map { [$0] } ?? []
        }
    }

    func setTargetPath(_ path: String?) {
        syncOnStateQueue {
            targetPath = path
        }
    }

    private func handle(message: UnsafePointer<es_message_t>) {
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            handleExec(message)
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            handleCreate(message)
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            handleKextLoad(message)
        case ES_EVENT_TYPE_NOTIFY_MOUNT:
            handleMount(message)
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            handleRename(message)
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
            handleIPCConnect(message)
        case ES_EVENT_TYPE_NOTIFY_FORK:
            handleFork(message)
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            handleUnlink(message)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            handleExit(message)
        default:
            break
        }
    }

    private func handleExec(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.event.exec.target.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        let matchesPath = shouldMatchTargetPath(process: proc)
        if matchesPath && targetPid == nil {
            setTargetPid(pid)
            log.info("matched target path, pid=\(pid)")
        }
        if shouldTrack(pid: pid) || matchesPath {
            log.info("exec pid=\(pid)")
            writeEvent(
                eventType: "process::exec",
                process: proc,
                message: message,
                props: execProps(message, process: proc)
            )
        }
    }

    private func handleCreate(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        guard shouldTrack(pid: pid) else { return }

        var props: [String: String] = [:]
        let file = message.pointee.event.create.destination.new_path.dir.pointee
        props["path"] = getString(tok: file.path)
        props["size"] = String(file.stat.st_size)
        props.merge(processProps(proc)) { current, _ in current }

        writeEvent(eventType: "file::create", process: proc, message: message, props: props)
    }

    private func handleKextLoad(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        guard shouldTrack(pid: pid) else { return }

        var props: [String: String] = [:]
        props["identifier"] = getString(tok: message.pointee.event.kextload.identifier)
        props.merge(processProps(proc)) { current, _ in current }

        writeEvent(eventType: "process:kext::load", process: proc, message: message, props: props)
    }

    private func handleMount(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        guard shouldTrack(pid: pid) else { return }

        var props: [String: String] = [:]
        let remoteBytes = message.pointee.event.mount.statfs.pointee.f_mntfromname
        let remoteName = String(tupleOfCChars: remoteBytes)
        props["remotename"] = remoteName

        let localBytes = message.pointee.event.mount.statfs.pointee.f_mntonname
        let localName = String(tupleOfCChars: localBytes)
        props["localname"] = localName
        props.merge(processProps(proc)) { current, _ in current }

        writeEvent(eventType: "file::mount", process: proc, message: message, props: props)
    }

    private func handleRename(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        guard shouldTrack(pid: pid) else { return }

        var props: [String: String] = [:]
        let srcFile = message.pointee.event.rename.source.pointee
        props["srcpath"] = getString(tok: srcFile.path)
        props["srcsize"] = String(srcFile.stat.st_size)

        let destType = message.pointee.event.rename.destination_type
        props["desttype"] = String(destType.rawValue)
        switch destType {
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            let destFile = message.pointee.event.rename.destination.existing_file.pointee
            props["destfile"] = getString(tok: destFile.path)
            props["destdir"] = getString(tok: destFile.path)
        case ES_DESTINATION_TYPE_NEW_PATH:
            props["destfile"] = getString(tok: message.pointee.event.rename.destination.new_path.filename)
            let destDir = message.pointee.event.rename.destination.new_path.dir.pointee
            props["destdir"] = getString(tok: destDir.path)
        default:
            break
        }
        props.merge(processProps(proc)) { current, _ in current }

        writeEvent(eventType: "file::rename", process: proc, message: message, props: props)
    }

    private func handleIPCConnect(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        guard shouldTrack(pid: pid) else { return }

        let conn = message.pointee.event.uipc_connect
        var props: [String: String] = [:]

        let domainString: String
        switch conn.domain {
        case AF_UNIX:
            domainString = "AF_UNIX"
        case AF_INET:
            domainString = "AF_INET"
        case AF_LOCAL:
            domainString = "AF_LOCAL"
        default:
            domainString = String(conn.domain)
        }

        let typeString: String
        switch conn.type {
        case SOCK_STREAM:
            typeString = "SOCK_STREAM"
        case SOCK_DGRAM:
            typeString = "SOCK_DGRAM"
        case SOCK_RAW:
            typeString = "SOCK_RAW"
        default:
            typeString = String(conn.type)
        }

        let protoString: String
        switch conn.protocol {
        case IPPROTO_IP:
            protoString = "IPPROTO_IP"
        case IPPROTO_UDP:
            protoString = "IPPROTO_UDP"
        case IPPROTO_TCP:
            protoString = "IPPROTO_TCP"
        default:
            protoString = String(conn.protocol)
        }

        props["domain"] = domainString
        props["proto"] = protoString
        props["type"] = typeString

        let file = conn.file.pointee
        props["path"] = getString(tok: file.path)
        props.merge(processProps(proc)) { current, _ in current }

        writeEvent(eventType: "network::ipcconnect", process: proc, message: message, props: props)
    }

    private func handleFork(_ message: UnsafePointer<es_message_t>) {
        let parentProc = message.pointee.process.pointee
        let parentPid = audit_token_to_pid(parentProc.audit_token)
        let childProc = message.pointee.event.fork.child.pointee
        let childPid = audit_token_to_pid(childProc.audit_token)
        guard let targetPid = targetPid else { return }
        if parentPid == targetPid || trackedPids.contains(parentPid) {
            trackedPids.insert(childPid)
            log.info("fork parent=\(parentPid) child=\(childPid)")
            var props = processProps(childProc)
            props["child_pid"] = String(childPid)
            props["child_ppid"] = String(parentPid)
            props["child_path"] = getString(tok: childProc.executable.pointee.path)
            writeEvent(eventType: "process::fork", process: parentProc, message: message, props: props)
        }
    }

    private func handleUnlink(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        guard shouldTrack(pid: pid) else { return }

        var props: [String: String] = [:]
        let dir = message.pointee.event.unlink.parent_dir.pointee.path
        props["dir"] = getString(tok: dir)
        let path = message.pointee.event.unlink.target.pointee.path
        props["path"] = getString(tok: path)
        props.merge(processProps(proc)) { current, _ in current }

        writeEvent(eventType: "file::unlink", process: proc, message: message, props: props)
    }

    private func handleExit(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        if trackedPids.remove(pid) != nil {
            log.info("exit pid=\(pid)")
            var props = processProps(proc)
            props["pid"] = String(pid)
            writeEvent(eventType: "process::exit", process: proc, message: message, props: props)
        }
    }

    private func shouldTrack(pid: pid_t) -> Bool {
        guard let targetPid = targetPid else {
            return false
        }
        return pid == targetPid || trackedPids.contains(pid)
    }

    private func shouldMatchTargetPath(process: es_process_t) -> Bool {
        guard let targetPath = targetPath, !targetPath.isEmpty else {
            return false
        }
        let execPath = getString(tok: process.executable.pointee.path)
        return execPath == targetPath
    }

    private func startConfigWatcher() {
        let timer = DispatchSource.makeTimerSource(queue: stateQueue)
        timer.schedule(deadline: .now(), repeating: .milliseconds(200))
        timer.setEventHandler { [weak self] in
            self?.reloadConfig()
        }
        timer.resume()
        configTimer = timer
    }

    private func stopConfigWatcher() {
        configTimer?.cancel()
        configTimer = nil
    }

    private func reloadConfig() {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)) else {
            return
        }
        guard let json = try? JSONSerialization.jsonObject(with: data, options: []),
              let dict = json as? [String: Any] else {
            return
        }
        if let pidValue = dict["targetPid"] as? Int {
            let pid = pid_t(pidValue)
            if pid != targetPid {
                setTargetPid(pid)
                log.info("target pid updated to \(pid)")
            }
        }
        if let pathValue = dict["targetPath"] as? String {
            if pathValue != targetPath {
                setTargetPath(pathValue)
                log.info("target path updated to \(pathValue)")
            }
        }
        if let output = dict["outputPath"] as? String, output != outputPath {
            outputPath = output
            closeOutput()
            openOutput()
            log.info("output path updated to \(output)")
        }
    }

    private func openOutput() {
        let url = URL(fileURLWithPath: outputPath)
        if !FileManager.default.fileExists(atPath: outputPath) {
            FileManager.default.createFile(atPath: outputPath, contents: nil)
        }
        outputHandle = try? FileHandle(forWritingTo: url)
        try? outputHandle?.seekToEnd()
    }

    private func closeOutput() {
        try? outputHandle?.close()
        outputHandle = nil
    }

    private func writeEvent(_ event: [String: Any]) {
        guard let handle = outputHandle else { return }
        guard let data = try? JSONSerialization.data(withJSONObject: event, options: []) else {
            return
        }
        handle.write(data)
        handle.write("\n".data(using: .utf8) ?? Data())
    }

    private func writeEvent(
        eventType: String,
        process: es_process_t,
        message: UnsafePointer<es_message_t>,
        props: [String: String]
    ) {
        let event: [String: Any] = [
            "eventtype": eventType,
            "processpath": getString(tok: process.executable.pointee.path),
            "pid": Int(audit_token_to_pid(process.audit_token)),
            "ppid": Int(process.ppid),
            "isplatform": process.is_platform_binary,
            "timestamp": Int(message.pointee.time.tv_sec * 1000) + Int(message.pointee.time.tv_nsec / (1000 * 1000)),
            "username": getUsername(id: audit_token_to_euid(process.audit_token)),
            "signingid": getString(tok: process.signing_id),
            "props": props,
        ]
        writeEvent(event)
    }

    private func execProps(_ message: UnsafePointer<es_message_t>, process: es_process_t) -> [String: String] {
        var props = processProps(process)
        var execEvent = message.pointee.event.exec
        let argc = es_exec_arg_count(&execEvent)
        props["argc"] = String(argc)
        if argc > 0 {
            var argv: [String] = []
            for index in 0..<argc {
                argv.append(getString(tok: es_exec_arg(&execEvent, index)))
            }
            props["argv"] = argv.joined(separator: " ")
        }
        return props
    }

    private func processProps(_ process: es_process_t) -> [String: String] {
        return [
            "teamid": getString(tok: process.team_id),
            "signingid": getString(tok: process.signing_id),
            "isplatformbin": String(process.is_platform_binary),
            "size": String(process.executable.pointee.stat.st_size),
            "ppid": String(process.ppid),
        ]
    }

    private func getUsername(id: uid_t) -> String {
        guard let passwd = getpwuid(id)?.pointee.pw_name else { return "" }
        return String(cString: passwd)
    }

    private func tokenToString(_ token: es_string_token_t) -> String {
        guard let base = token.data else { return "" }
        let data = Data(bytes: base, count: token.length)
        return String(data: data, encoding: .utf8) ?? ""
    }

    private func getString(tok: es_string_token_t) -> String {
        return tokenToString(tok)
    }

    private func syncOnStateQueue(_ block: () -> Void) {
        if DispatchQueue.getSpecific(key: stateKey) != nil {
            block()
        } else {
            stateQueue.sync {
                block()
            }
        }
    }
}

extension String {
    init<T>(tupleOfCChars: T, length: Int = Int.max) {
        self = withUnsafePointer(to: tupleOfCChars) {
            let lengthOfTuple = MemoryLayout<T>.size / MemoryLayout<CChar>.size
            return $0.withMemoryRebound(to: UInt8.self, capacity: lengthOfTuple) {
                String(bytes: UnsafeBufferPointer(start: $0, count: Swift.min(length, lengthOfTuple)), encoding: .utf8) ?? ""
            }
        }
    }
}
