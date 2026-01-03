import EndpointSecurity
import Darwin
import Foundation
import os

final class ESCollector {
    private let buildVersion = "escollector-2025-02-10"
    private let log = Logger(subsystem: "com.cuckoo.escollector", category: "es")
    private let stateQueue = DispatchQueue(label: "com.cuckoo.escollector.state")
    private let stateKey = DispatchSpecificKey<Void>()
    private var client: OpaquePointer?
    private var targetPid: pid_t?
    private var targetPath: String?
    private var trackedPids = Set<pid_t>()
    private var processMuteInverted = false
    private var pathMuteInverted = false
    private var processMuteApplied = false
    private var lastMutedPath: String?
    private var configTimer: DispatchSourceTimer?
    private let configPath = "/var/tmp/escollector_config.json"
    private var outputPath = "/var/tmp/escollector_events.jsonl"
    private var outputDir: String?
    private var outputHandle: FileHandle?
    private var kindHandles: [String: FileHandle] = [:]

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
            ES_EVENT_TYPE_NOTIFY_ACCESS,
            ES_EVENT_TYPE_NOTIFY_CHDIR,
            ES_EVENT_TYPE_NOTIFY_CHROOT,
            ES_EVENT_TYPE_NOTIFY_CLONE,
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_COPYFILE,
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_CREATE,
            ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
            ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR,
            ES_EVENT_TYPE_NOTIFY_DUP,
            ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA,
            ES_EVENT_TYPE_NOTIFY_FCNTL,
            ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE,
            ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE,
            ES_EVENT_TYPE_NOTIFY_FSGETPATH,
            ES_EVENT_TYPE_NOTIFY_GETATTRLIST,
            ES_EVENT_TYPE_NOTIFY_GETEXTATTR,
            ES_EVENT_TYPE_NOTIFY_GET_TASK,
            ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
            ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT,
            ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME,
            ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN,
            ES_EVENT_TYPE_NOTIFY_RENAME,
            ES_EVENT_TYPE_NOTIFY_UNLINK,
            ES_EVENT_TYPE_NOTIFY_LINK,
            ES_EVENT_TYPE_NOTIFY_LISTEXTATTR,
            ES_EVENT_TYPE_NOTIFY_LOOKUP,
            ES_EVENT_TYPE_NOTIFY_MMAP,
            ES_EVENT_TYPE_NOTIFY_MOUNT,
            ES_EVENT_TYPE_NOTIFY_MPROTECT,
            ES_EVENT_TYPE_NOTIFY_OPEN,
            ES_EVENT_TYPE_NOTIFY_PROC_CHECK,
            ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME,
            ES_EVENT_TYPE_NOTIFY_PTY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_PTY_GRANT,
            ES_EVENT_TYPE_NOTIFY_READDIR,
            ES_EVENT_TYPE_NOTIFY_READLINK,
            ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
            ES_EVENT_TYPE_NOTIFY_REMOUNT,
            ES_EVENT_TYPE_NOTIFY_SEARCHFS,
            ES_EVENT_TYPE_NOTIFY_SETACL,
            ES_EVENT_TYPE_NOTIFY_SETATTRLIST,
            ES_EVENT_TYPE_NOTIFY_SETEGID,
            ES_EVENT_TYPE_NOTIFY_SETEUID,
            ES_EVENT_TYPE_NOTIFY_SETEXTATTR,
            ES_EVENT_TYPE_NOTIFY_SETGID,
            ES_EVENT_TYPE_NOTIFY_SETFLAGS,
            ES_EVENT_TYPE_NOTIFY_SETMODE,
            ES_EVENT_TYPE_NOTIFY_SETOWNER,
            ES_EVENT_TYPE_NOTIFY_SETREGID,
            ES_EVENT_TYPE_NOTIFY_SETREUID,
            ES_EVENT_TYPE_NOTIFY_SETTIME,
            ES_EVENT_TYPE_NOTIFY_SETUID,
            ES_EVENT_TYPE_NOTIFY_SIGNAL,
            ES_EVENT_TYPE_NOTIFY_STAT,
            ES_EVENT_TYPE_NOTIFY_TRACE,
            ES_EVENT_TYPE_NOTIFY_TRUNCATE,
            ES_EVENT_TYPE_NOTIFY_UIPC_BIND,
            ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
            ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
            ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD,
            ES_EVENT_TYPE_NOTIFY_UNMOUNT,
            ES_EVENT_TYPE_NOTIFY_UTIMES,
            ES_EVENT_TYPE_NOTIFY_WRITE,
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
        applyPathMutingIfPossible()
        writeVersionMarker()
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
        closeKindOutputs()
    }

    func setTargetPid(_ pid: pid_t?) {
        syncOnStateQueue {
            targetPid = pid
            trackedPids = pid.map { [$0] } ?? []
            processMuteApplied = false
        }
    }

    func setTargetPath(_ path: String?) {
        syncOnStateQueue {
            targetPath = path
            applyPathMutingIfPossible()
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
            handleGeneric(message)
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
        applyProcessMutingIfPossible(process: proc)
        if shouldTrack(pid: pid) || matchesPath {
            log.info("exec pid=\(pid)")
            writeDerivedEvent(
                eventType: "process::exec",
                kind: "process",
                process: proc,
                message: message,
                props: execProps(message, process: proc)
            )
        }
    }

    private func handleCreate(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        applyProcessMutingIfPossible(process: proc)
        guard shouldTrack(pid: pid) else { return }

        var props: [String: String] = [:]
        let file = message.pointee.event.create.destination.new_path.dir.pointee
        props["path"] = getString(tok: file.path)
        props["size"] = String(file.stat.st_size)
        props.merge(processProps(proc)) { current, _ in current }

        writeDerivedEvent(eventType: "file::create", kind: "file", process: proc, message: message, props: props)
    }

    private func handleKextLoad(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        applyProcessMutingIfPossible(process: proc)
        guard shouldTrack(pid: pid) else { return }

        var props: [String: String] = [:]
        props["identifier"] = getString(tok: message.pointee.event.kextload.identifier)
        props.merge(processProps(proc)) { current, _ in current }

        writeDerivedEvent(eventType: "process:kext::load", kind: "suspicious_event", process: proc, message: message, props: props)
    }

    private func handleMount(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        applyProcessMutingIfPossible(process: proc)
        guard shouldTrack(pid: pid) else { return }

        var props: [String: String] = [:]
        let remoteBytes = message.pointee.event.mount.statfs.pointee.f_mntfromname
        let remoteName = String(tupleOfCChars: remoteBytes)
        props["remotename"] = remoteName

        let localBytes = message.pointee.event.mount.statfs.pointee.f_mntonname
        let localName = String(tupleOfCChars: localBytes)
        props["localname"] = localName
        props.merge(processProps(proc)) { current, _ in current }

        writeDerivedEvent(eventType: "file::mount", kind: "file", process: proc, message: message, props: props)
    }

    private func handleRename(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        applyProcessMutingIfPossible(process: proc)
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

        writeDerivedEvent(eventType: "file::rename", kind: "file", process: proc, message: message, props: props)
    }

    private func handleIPCConnect(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        applyProcessMutingIfPossible(process: proc)
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

        writeDerivedEvent(eventType: "network::ipcconnect", kind: "networkflow", process: proc, message: message, props: props)
    }

    private func handleFork(_ message: UnsafePointer<es_message_t>) {
        let parentProc = message.pointee.process.pointee
        let parentPid = audit_token_to_pid(parentProc.audit_token)
        let childProc = message.pointee.event.fork.child.pointee
        let childPid = audit_token_to_pid(childProc.audit_token)
        guard let targetPid = targetPid else { return }
        applyProcessMutingIfPossible(process: parentProc)
        if parentPid == targetPid || trackedPids.contains(parentPid) {
            trackedPids.insert(childPid)
            muteProcess(childProc)
            log.info("fork parent=\(parentPid) child=\(childPid)")
            var props = processProps(childProc)
            props["child_pid"] = String(childPid)
            props["child_ppid"] = String(parentPid)
            props["child_path"] = getString(tok: childProc.executable.pointee.path)
            writeDerivedEvent(eventType: "process::fork", kind: "process", process: parentProc, message: message, props: props)
        }
    }

    private func handleUnlink(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        applyProcessMutingIfPossible(process: proc)
        guard shouldTrack(pid: pid) else { return }

        var props: [String: String] = [:]
        let dir = message.pointee.event.unlink.parent_dir.pointee.path
        props["dir"] = getString(tok: dir)
        let path = message.pointee.event.unlink.target.pointee.path
        props["path"] = getString(tok: path)
        props.merge(processProps(proc)) { current, _ in current }

        writeDerivedEvent(eventType: "file::unlink", kind: "file", process: proc, message: message, props: props)
    }

    private func handleExit(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        applyProcessMutingIfPossible(process: proc)
        if trackedPids.remove(pid) != nil {
            log.info("exit pid=\(pid)")
            var props = processProps(proc)
            props["pid"] = String(pid)
            writeDerivedEvent(eventType: "process::exit", kind: "process", process: proc, message: message, props: props)
        }
    }

    private func handleGeneric(_ message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process.pointee
        let pid = audit_token_to_pid(proc.audit_token)
        applyProcessMutingIfPossible(process: proc)
        guard shouldTrack(pid: pid) else { return }

        var props = processProps(proc)
        props["es_event_type"] = String(message.pointee.event_type.rawValue)
        props["event_name"] = eventName(for: message.pointee.event_type)
        props.merge(eventProps(for: message)) { current, _ in current }
        writeEvent(
            eventType: "notify::\(eventName(for: message.pointee.event_type))",
            process: proc,
            message: message,
            props: props
        )
        emitDerivedEvents(message: message, process: proc, props: props)
    }

    private func eventName(for eventType: es_event_type_t) -> String {
        switch eventType {
        case ES_EVENT_TYPE_NOTIFY_ACCESS: return "access"
        case ES_EVENT_TYPE_NOTIFY_CHDIR: return "chdir"
        case ES_EVENT_TYPE_NOTIFY_CHROOT: return "chroot"
        case ES_EVENT_TYPE_NOTIFY_CLONE: return "clone"
        case ES_EVENT_TYPE_NOTIFY_CLOSE: return "close"
        case ES_EVENT_TYPE_NOTIFY_COPYFILE: return "copyfile"
        case ES_EVENT_TYPE_NOTIFY_CREATE: return "create"
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED: return "cs_invalidated"
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR: return "deleteextattr"
        case ES_EVENT_TYPE_NOTIFY_DUP: return "dup"
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA: return "exchangedata"
        case ES_EVENT_TYPE_NOTIFY_EXEC: return "exec"
        case ES_EVENT_TYPE_NOTIFY_EXIT: return "exit"
        case ES_EVENT_TYPE_NOTIFY_FCNTL: return "fcntl"
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE: return "file_provider_materialize"
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE: return "file_provider_update"
        case ES_EVENT_TYPE_NOTIFY_FORK: return "fork"
        case ES_EVENT_TYPE_NOTIFY_FSGETPATH: return "fsgetpath"
        case ES_EVENT_TYPE_NOTIFY_GETATTRLIST: return "getattrlist"
        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR: return "getextattr"
        case ES_EVENT_TYPE_NOTIFY_GET_TASK: return "get_task"
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ: return "get_task_read"
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT: return "get_task_inspect"
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME: return "get_task_name"
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN: return "iokit_open"
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD: return "kextload"
        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD: return "kextunload"
        case ES_EVENT_TYPE_NOTIFY_LINK: return "link"
        case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR: return "listextattr"
        case ES_EVENT_TYPE_NOTIFY_LOOKUP: return "lookup"
        case ES_EVENT_TYPE_NOTIFY_MMAP: return "mmap"
        case ES_EVENT_TYPE_NOTIFY_MOUNT: return "mount"
        case ES_EVENT_TYPE_NOTIFY_MPROTECT: return "mprotect"
        case ES_EVENT_TYPE_NOTIFY_OPEN: return "open"
        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK: return "proc_check"
        case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME: return "proc_suspend_resume"
        case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE: return "pty_close"
        case ES_EVENT_TYPE_NOTIFY_PTY_GRANT: return "pty_grant"
        case ES_EVENT_TYPE_NOTIFY_READDIR: return "readdir"
        case ES_EVENT_TYPE_NOTIFY_READLINK: return "readlink"
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE: return "remote_thread_create"
        case ES_EVENT_TYPE_NOTIFY_REMOUNT: return "remount"
        case ES_EVENT_TYPE_NOTIFY_RENAME: return "rename"
        case ES_EVENT_TYPE_NOTIFY_SEARCHFS: return "searchfs"
        case ES_EVENT_TYPE_NOTIFY_SETACL: return "setacl"
        case ES_EVENT_TYPE_NOTIFY_SETATTRLIST: return "setattrlist"
        case ES_EVENT_TYPE_NOTIFY_SETEGID: return "setegid"
        case ES_EVENT_TYPE_NOTIFY_SETEUID: return "seteuid"
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR: return "setextattr"
        case ES_EVENT_TYPE_NOTIFY_SETGID: return "setgid"
        case ES_EVENT_TYPE_NOTIFY_SETFLAGS: return "setflags"
        case ES_EVENT_TYPE_NOTIFY_SETMODE: return "setmode"
        case ES_EVENT_TYPE_NOTIFY_SETOWNER: return "setowner"
        case ES_EVENT_TYPE_NOTIFY_SETREGID: return "setregid"
        case ES_EVENT_TYPE_NOTIFY_SETREUID: return "setreuid"
        case ES_EVENT_TYPE_NOTIFY_SETTIME: return "settime"
        case ES_EVENT_TYPE_NOTIFY_SETUID: return "setuid"
        case ES_EVENT_TYPE_NOTIFY_SIGNAL: return "signal"
        case ES_EVENT_TYPE_NOTIFY_STAT: return "stat"
        case ES_EVENT_TYPE_NOTIFY_TRACE: return "trace"
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE: return "truncate"
        case ES_EVENT_TYPE_NOTIFY_UIPC_BIND: return "uipc_bind"
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT: return "uipc_connect"
        case ES_EVENT_TYPE_NOTIFY_UNLINK: return "unlink"
        case ES_EVENT_TYPE_NOTIFY_UNMOUNT: return "unmount"
        case ES_EVENT_TYPE_NOTIFY_UTIMES: return "utimes"
        case ES_EVENT_TYPE_NOTIFY_WRITE: return "write"
        default: return "unknown"
        }
    }

    private func eventProps(for message: UnsafePointer<es_message_t>) -> [String: String] {
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            let openEvent = message.pointee.event.open
            return [
                "path": filePath(openEvent.file),
                "fflag": String(openEvent.fflag),
            ]
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            let writeEvent = message.pointee.event.write
            return ["path": filePath(writeEvent.target)]
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            let closeEvent = message.pointee.event.close
            return [
                "path": filePath(closeEvent.target),
                "modified": String(closeEvent.modified),
                "was_mapped_writable": String(closeEvent.was_mapped_writable),
            ]
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            let truncateEvent = message.pointee.event.truncate
            return ["path": filePath(truncateEvent.target)]
        case ES_EVENT_TYPE_NOTIFY_ACCESS:
            let accessEvent = message.pointee.event.access
            return [
                "path": filePath(accessEvent.target),
                "mode": String(accessEvent.mode),
            ]
        case ES_EVENT_TYPE_NOTIFY_CHDIR:
            let chdirEvent = message.pointee.event.chdir
            return ["path": filePath(chdirEvent.target)]
        case ES_EVENT_TYPE_NOTIFY_CHROOT:
            let chrootEvent = message.pointee.event.chroot
            return ["path": filePath(chrootEvent.target)]
        case ES_EVENT_TYPE_NOTIFY_STAT:
            let statEvent = message.pointee.event.stat
            return ["path": filePath(statEvent.target)]
        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            let setmodeEvent = message.pointee.event.setmode
            return [
                "path": filePath(setmodeEvent.target),
                "mode": String(setmodeEvent.mode),
            ]
        case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
            let setflagsEvent = message.pointee.event.setflags
            return [
                "path": filePath(setflagsEvent.target),
                "flags": String(setflagsEvent.flags),
            ]
        case ES_EVENT_TYPE_NOTIFY_SETOWNER:
            let setownerEvent = message.pointee.event.setowner
            return [
                "path": filePath(setownerEvent.target),
                "uid": String(setownerEvent.uid),
                "gid": String(setownerEvent.gid),
            ]
        case ES_EVENT_TYPE_NOTIFY_SETACL:
            let setaclEvent = message.pointee.event.setacl
            return [
                "path": filePath(setaclEvent.target),
                "set_or_clear": String(setaclEvent.set_or_clear.rawValue),
            ]
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
            let setextattrEvent = message.pointee.event.setextattr
            return [
                "path": filePath(setextattrEvent.target),
                "extattr": getString(tok: setextattrEvent.extattr),
            ]
        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
            let getextattrEvent = message.pointee.event.getextattr
            return [
                "path": filePath(getextattrEvent.target),
                "extattr": getString(tok: getextattrEvent.extattr),
            ]
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
            let deleteextattrEvent = message.pointee.event.deleteextattr
            return [
                "path": filePath(deleteextattrEvent.target),
                "extattr": getString(tok: deleteextattrEvent.extattr),
            ]
        case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
            let listextattrEvent = message.pointee.event.listextattr
            return ["path": filePath(listextattrEvent.target)]
        case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
            let getattrEvent = message.pointee.event.getattrlist
            return attrlistProps(attr: getattrEvent.attrlist, path: filePath(getattrEvent.target))
        case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
            let setattrEvent = message.pointee.event.setattrlist
            return attrlistProps(attr: setattrEvent.attrlist, path: filePath(setattrEvent.target))
        case ES_EVENT_TYPE_NOTIFY_LOOKUP:
            let lookupEvent = message.pointee.event.lookup
            return [
                "source_dir": filePath(lookupEvent.source_dir),
                "relative_target": getString(tok: lookupEvent.relative_target),
            ]
        case ES_EVENT_TYPE_NOTIFY_READDIR:
            let readdirEvent = message.pointee.event.readdir
            return ["path": filePath(readdirEvent.target)]
        case ES_EVENT_TYPE_NOTIFY_READLINK:
            let readlinkEvent = message.pointee.event.readlink
            return ["path": filePath(readlinkEvent.source)]
        case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
            let fsgetpathEvent = message.pointee.event.fsgetpath
            return ["path": filePath(fsgetpathEvent.target)]
        case ES_EVENT_TYPE_NOTIFY_CLONE:
            let cloneEvent = message.pointee.event.clone
            return [
                "source": filePath(cloneEvent.source),
                "target_dir": filePath(cloneEvent.target_dir),
                "target_name": getString(tok: cloneEvent.target_name),
            ]
        case ES_EVENT_TYPE_NOTIFY_COPYFILE:
            let copyEvent = message.pointee.event.copyfile
            var props: [String: String] = [
                "source": filePath(copyEvent.source),
                "target_dir": filePath(copyEvent.target_dir),
                "target_name": getString(tok: copyEvent.target_name),
                "mode": String(copyEvent.mode),
                "flags": String(copyEvent.flags),
            ]
            if let targetFile = copyEvent.target_file {
                props["target_file"] = filePath(targetFile)
            }
            return props
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
            let exchEvent = message.pointee.event.exchangedata
            return [
                "file1": filePath(exchEvent.file1),
                "file2": filePath(exchEvent.file2),
            ]
        case ES_EVENT_TYPE_NOTIFY_LINK:
            let linkEvent = message.pointee.event.link
            return [
                "source": filePath(linkEvent.source),
                "target_dir": filePath(linkEvent.target_dir),
                "target_filename": getString(tok: linkEvent.target_filename),
            ]
        case ES_EVENT_TYPE_NOTIFY_FCNTL:
            let fcntlEvent = message.pointee.event.fcntl
            return [
                "path": filePath(fcntlEvent.target),
                "cmd": String(fcntlEvent.cmd),
            ]
        case ES_EVENT_TYPE_NOTIFY_DUP:
            let dupEvent = message.pointee.event.dup
            return ["path": filePath(dupEvent.target)]
        case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
            let bindEvent = message.pointee.event.uipc_bind
            return [
                "dir": filePath(bindEvent.dir),
                "filename": getString(tok: bindEvent.filename),
                "mode": String(bindEvent.mode),
            ]
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
            let conn = message.pointee.event.uipc_connect
            return [
                "path": filePath(conn.file),
                "domain": String(conn.domain),
                "type": String(conn.type),
                "protocol": String(conn.protocol),
            ]
        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            let signalEvent = message.pointee.event.signal
            return [
                "sig": String(signalEvent.sig),
                "target_pid": String(audit_token_to_pid(signalEvent.target.pointee.audit_token)),
                "target_path": getString(tok: signalEvent.target.pointee.executable.pointee.path),
            ]
        case ES_EVENT_TYPE_NOTIFY_TRACE:
            let traceEvent = message.pointee.event.trace
            return [
                "target_pid": String(audit_token_to_pid(traceEvent.target.pointee.audit_token)),
                "target_path": getString(tok: traceEvent.target.pointee.executable.pointee.path),
            ]
        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
            let remoteEvent = message.pointee.event.remote_thread_create
            return [
                "target_pid": String(audit_token_to_pid(remoteEvent.target.pointee.audit_token)),
                "target_path": getString(tok: remoteEvent.target.pointee.executable.pointee.path),
            ]
        case ES_EVENT_TYPE_NOTIFY_GET_TASK:
            let getTaskEvent = message.pointee.event.get_task
            return [
                "target_pid": String(audit_token_to_pid(getTaskEvent.target.pointee.audit_token)),
                "target_path": getString(tok: getTaskEvent.target.pointee.executable.pointee.path),
                "type": String(getTaskEvent.type.rawValue),
            ]
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
            let getTaskReadEvent = message.pointee.event.get_task_read
            return [
                "target_pid": String(audit_token_to_pid(getTaskReadEvent.target.pointee.audit_token)),
                "target_path": getString(tok: getTaskReadEvent.target.pointee.executable.pointee.path),
                "type": String(getTaskReadEvent.type.rawValue),
            ]
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT:
            let getTaskInspectEvent = message.pointee.event.get_task_inspect
            return [
                "target_pid": String(audit_token_to_pid(getTaskInspectEvent.target.pointee.audit_token)),
                "target_path": getString(tok: getTaskInspectEvent.target.pointee.executable.pointee.path),
                "type": String(getTaskInspectEvent.type.rawValue),
            ]
        case ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME:
            let getTaskNameEvent = message.pointee.event.get_task_name
            return [
                "target_pid": String(audit_token_to_pid(getTaskNameEvent.target.pointee.audit_token)),
                "target_path": getString(tok: getTaskNameEvent.target.pointee.executable.pointee.path),
                "type": String(getTaskNameEvent.type.rawValue),
            ]
        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
            let procCheck = message.pointee.event.proc_check
            var props: [String: String] = [
                "type": String(procCheck.type.rawValue),
                "flavor": String(procCheck.flavor),
            ]
            if let target = procCheck.target {
                props["target_pid"] = String(audit_token_to_pid(target.pointee.audit_token))
                props["target_path"] = getString(tok: target.pointee.executable.pointee.path)
            }
            return props
        case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME:
            let procSuspend = message.pointee.event.proc_suspend_resume
            var props: [String: String] = [
                "type": String(procSuspend.type.rawValue),
            ]
            if let target = procSuspend.target {
                props["target_pid"] = String(audit_token_to_pid(target.pointee.audit_token))
                props["target_path"] = getString(tok: target.pointee.executable.pointee.path)
            }
            return props
        case ES_EVENT_TYPE_NOTIFY_SETUID:
            let setuidEvent = message.pointee.event.setuid
            return ["uid": String(setuidEvent.uid)]
        case ES_EVENT_TYPE_NOTIFY_SETGID:
            let setgidEvent = message.pointee.event.setgid
            return ["gid": String(setgidEvent.gid)]
        case ES_EVENT_TYPE_NOTIFY_SETEUID:
            let seteuidEvent = message.pointee.event.seteuid
            return ["euid": String(seteuidEvent.euid)]
        case ES_EVENT_TYPE_NOTIFY_SETEGID:
            let setegidEvent = message.pointee.event.setegid
            return ["egid": String(setegidEvent.egid)]
        case ES_EVENT_TYPE_NOTIFY_SETREUID:
            let setreuidEvent = message.pointee.event.setreuid
            return [
                "ruid": String(setreuidEvent.ruid),
                "euid": String(setreuidEvent.euid),
            ]
        case ES_EVENT_TYPE_NOTIFY_SETREGID:
            let setregidEvent = message.pointee.event.setregid
            return [
                "rgid": String(setregidEvent.rgid),
                "egid": String(setregidEvent.egid),
            ]
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            let mmapEvent = message.pointee.event.mmap
            return [
                "path": filePath(mmapEvent.source),
                "protection": String(mmapEvent.protection),
                "max_protection": String(mmapEvent.max_protection),
                "flags": String(mmapEvent.flags),
                "file_pos": String(mmapEvent.file_pos),
            ]
        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            let mprotectEvent = message.pointee.event.mprotect
            return [
                "protection": String(mprotectEvent.protection),
                "address": String(mprotectEvent.address),
                "size": String(mprotectEvent.size),
            ]
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
            let iokitEvent = message.pointee.event.iokit_open
            return [
                "user_client_type": String(iokitEvent.user_client_type),
                "user_client_class": getString(tok: iokitEvent.user_client_class),
                "parent_registry_id": String(iokitEvent.parent_registry_id),
                "parent_path": getString(tok: iokitEvent.parent_path),
            ]
        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
            let kextEvent = message.pointee.event.kextunload
            return ["identifier": getString(tok: kextEvent.identifier)]
        case ES_EVENT_TYPE_NOTIFY_SETTIME:
            return [:]
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            return [:]
        case ES_EVENT_TYPE_NOTIFY_REMOUNT:
            let remountEvent = message.pointee.event.remount
            return mountProps(statfsPtr: remountEvent.statfs, extra: [
                "remount_flags": String(remountEvent.remount_flags),
                "disposition": String(remountEvent.disposition.rawValue),
            ])
        case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
            let unmountEvent = message.pointee.event.unmount
            return mountProps(statfsPtr: unmountEvent.statfs, extra: [:])
        case ES_EVENT_TYPE_NOTIFY_UTIMES:
            let utimesEvent = message.pointee.event.utimes
            return [
                "path": filePath(utimesEvent.target),
                "atime_sec": String(utimesEvent.atime.tv_sec),
                "mtime_sec": String(utimesEvent.mtime.tv_sec),
            ]
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
            let fpUpdate = message.pointee.event.file_provider_update
            return [
                "source": filePath(fpUpdate.source),
                "target_path": getString(tok: fpUpdate.target_path),
            ]
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
            let fpMat = message.pointee.event.file_provider_materialize
            var props: [String: String] = [
                "source": filePath(fpMat.source),
                "target": filePath(fpMat.target),
            ]
            if let instigator = fpMat.instigator {
                props["instigator_pid"] = String(audit_token_to_pid(instigator.pointee.audit_token))
                props["instigator_path"] = getString(tok: instigator.pointee.executable.pointee.path)
            }
            return props
        case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
            let ptyGrant = message.pointee.event.pty_grant
            return ["dev": String(ptyGrant.dev)]
        case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE:
            let ptyClose = message.pointee.event.pty_close
            return ["dev": String(ptyClose.dev)]
        case ES_EVENT_TYPE_NOTIFY_SEARCHFS:
            let searchEvent = message.pointee.event.searchfs
            return attrlistProps(attr: searchEvent.attrlist, path: filePath(searchEvent.target))
        default:
            return [:]
        }
    }

    private func emitDerivedEvents(
        message: UnsafePointer<es_message_t>,
        process: es_process_t,
        props: [String: String]
    ) {
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            let openEvent = message.pointee.event.open
            let action = (openEvent.fflag & FWRITE) != 0 ? "open_modify" : "open_read"
            var derived = props
            derived["action"] = action
            writeDerivedEvent(eventType: "file::open", kind: "file", process: process, message: message, props: derived)
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            writeDerivedEvent(eventType: "file::write", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            writeDerivedEvent(eventType: "file::close", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            writeDerivedEvent(eventType: "file::truncate", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_COPYFILE:
            writeDerivedEvent(eventType: "file::copy", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_CLONE:
            writeDerivedEvent(eventType: "file::clone", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
            writeDerivedEvent(eventType: "file::exchangedata", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_LINK:
            writeDerivedEvent(eventType: "file::link", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_FCNTL:
            writeDerivedEvent(eventType: "file::fcntl", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_DUP:
            writeDerivedEvent(eventType: "file::dup", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
            writeDerivedEvent(eventType: "file::setextattr", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
            writeDerivedEvent(eventType: "file::deleteextattr", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            writeDerivedEvent(eventType: "file::setmode", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
            writeDerivedEvent(eventType: "file::setflags", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_SETOWNER:
            writeDerivedEvent(eventType: "file::setowner", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_SETACL:
            writeDerivedEvent(eventType: "file::setacl", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
            writeDerivedEvent(eventType: "file::setattrlist", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_UTIMES:
            writeDerivedEvent(eventType: "file::utimes", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_ACCESS,
             ES_EVENT_TYPE_NOTIFY_LOOKUP,
             ES_EVENT_TYPE_NOTIFY_READDIR,
             ES_EVENT_TYPE_NOTIFY_READLINK,
             ES_EVENT_TYPE_NOTIFY_STAT,
             ES_EVENT_TYPE_NOTIFY_FSGETPATH,
             ES_EVENT_TYPE_NOTIFY_GETATTRLIST,
             ES_EVENT_TYPE_NOTIFY_LISTEXTATTR,
             ES_EVENT_TYPE_NOTIFY_GETEXTATTR,
             ES_EVENT_TYPE_NOTIFY_SEARCHFS:
            writeDerivedEvent(eventType: "file::query", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_CHDIR:
            writeDerivedEvent(eventType: "process::chdir", kind: "process", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_CHROOT:
            writeDerivedEvent(eventType: "process::chroot", kind: "process", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            writeDerivedEvent(eventType: "process::signal", kind: "process", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME:
            writeDerivedEvent(eventType: "process::suspend_resume", kind: "process", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
            writeDerivedEvent(eventType: "process::proc_check", kind: "process", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_SETUID,
             ES_EVENT_TYPE_NOTIFY_SETGID,
             ES_EVENT_TYPE_NOTIFY_SETEUID,
             ES_EVENT_TYPE_NOTIFY_SETEGID,
             ES_EVENT_TYPE_NOTIFY_SETREUID,
             ES_EVENT_TYPE_NOTIFY_SETREGID:
            writeDerivedEvent(eventType: "process::cred_change", kind: "process", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_GET_TASK,
             ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
             ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT,
             ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME,
             ES_EVENT_TYPE_NOTIFY_TRACE,
             ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
            writeDerivedEvent(eventType: "process_injection::access", kind: "process_injection", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_MMAP,
             ES_EVENT_TYPE_NOTIFY_MPROTECT:
            writeDerivedEvent(eventType: "process_injection::memory", kind: "process_injection", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
            writeDerivedEvent(eventType: "kernel::kext_unload", kind: "suspicious_event", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
            writeDerivedEvent(eventType: "device::iokit_open", kind: "suspicious_event", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            writeDerivedEvent(eventType: "process::cs_invalidated", kind: "process", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_SETTIME:
            writeDerivedEvent(eventType: "system::settime", kind: "suspicious_event", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_REMOUNT:
            writeDerivedEvent(eventType: "system::remount", kind: "suspicious_event", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
            writeDerivedEvent(eventType: "system::unmount", kind: "suspicious_event", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
            writeDerivedEvent(eventType: "network::uipc_bind", kind: "networkflow", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
            writeDerivedEvent(eventType: "file::provider_update", kind: "file", process: process, message: message, props: props)
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
            writeDerivedEvent(eventType: "file::provider_materialize", kind: "file", process: process, message: message, props: props)
        default:
            break
        }
    }

    private func filePath(_ file: UnsafePointer<es_file_t>?) -> String {
        guard let file = file else { return "" }
        return getString(tok: file.pointee.path)
    }

    private func attrlistProps(attr: attrlist, path: String) -> [String: String] {
        return [
            "path": path,
            "attr_bitmapcount": String(attr.bitmapcount),
            "attr_common": String(attr.commonattr),
            "attr_vol": String(attr.volattr),
            "attr_dir": String(attr.dirattr),
            "attr_file": String(attr.fileattr),
            "attr_fork": String(attr.forkattr),
        ]
    }

    private func mountProps(statfsPtr: UnsafePointer<statfs>, extra: [String: String]) -> [String: String] {
        let remoteBytes = statfsPtr.pointee.f_mntfromname
        let localBytes = statfsPtr.pointee.f_mntonname
        var props: [String: String] = [
            "remotename": String(tupleOfCChars: remoteBytes),
            "localname": String(tupleOfCChars: localBytes),
        ]
        props.merge(extra) { current, _ in current }
        return props
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

    private func applyProcessMutingIfPossible(process: es_process_t) {
        guard let client = client else { return }
        guard let targetPid = targetPid else { return }
        if processMuteApplied {
            return
        }
        let pid = audit_token_to_pid(process.audit_token)
        guard pid == targetPid else { return }

        if !processMuteInverted {
            let invertResult = es_invert_muting(client, ES_MUTE_INVERSION_TYPE_PROCESS)
            if invertResult == ES_RETURN_SUCCESS {
                processMuteInverted = true
            } else {
                log.error("invert muting process failed: \(String(describing: invertResult))")
            }
        }

        if muteProcess(process) {
            processMuteApplied = true
            log.info("process muting applied for pid=\(pid)")
        }
    }

    @discardableResult
    private func muteProcess(_ process: es_process_t) -> Bool {
        guard let client = client else { return false }
        guard processMuteInverted else { return false }
        var token = process.audit_token
        let muteResult = withUnsafePointer(to: &token) { ptr in
            es_mute_process(client, ptr)
        }
        if muteResult != ES_RETURN_SUCCESS {
            log.error("mute process failed: \(String(describing: muteResult))")
            return false
        }
        return true
    }

    private func applyPathMutingIfPossible() {
        guard let client = client else { return }
        guard let targetPath = targetPath, !targetPath.isEmpty else {
            if pathMuteInverted {
                let invertResult = es_invert_muting(client, ES_MUTE_INVERSION_TYPE_PATH)
                if invertResult == ES_RETURN_SUCCESS {
                    pathMuteInverted = false
                }
                _ = es_unmute_all_paths(client)
                lastMutedPath = nil
            }
            return
        }

        if lastMutedPath == targetPath && pathMuteInverted {
            return
        }

        _ = es_unmute_all_paths(client)
        if !pathMuteInverted {
            let invertResult = es_invert_muting(client, ES_MUTE_INVERSION_TYPE_PATH)
            if invertResult == ES_RETURN_SUCCESS {
                pathMuteInverted = true
            } else {
                log.error("invert muting path failed: \(String(describing: invertResult))")
            }
        }

        let muteResult = targetPath.withCString { cstr in
            es_mute_path(client, cstr, ES_MUTE_PATH_TYPE_LITERAL)
        }
        if muteResult == ES_RETURN_SUCCESS {
            lastMutedPath = targetPath
            log.info("path muting applied for \(targetPath)")
        } else {
            log.error("mute path failed: \(String(describing: muteResult))")
        }
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
        if let dir = dict["outputDir"] as? String, dir != outputDir {
            outputDir = dir
            closeKindOutputs()
            openKindOutputs()
            log.info("output dir updated to \(dir)")
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

    private func writeVersionMarker() {
        let event: [String: Any] = [
            "eventtype": "system::version",
            "version": buildVersion,
            "timestamp": Int(Date().timeIntervalSince1970 * 1000),
            "outputPath": outputPath,
            "outputDir": outputDir ?? "",
        ]
        writeEvent(event)
        writeVersionFile()
    }

    private func writeVersionFile() {
        let path = "/tmp/escollector_version.txt"
        let payload = [
            "version=\(buildVersion)",
            "timestamp=\(Int(Date().timeIntervalSince1970))",
            "outputPath=\(outputPath)",
            "outputDir=\(outputDir ?? "")",
        ].joined(separator: "\n") + "\n"
        try? payload.data(using: .utf8)?.write(to: URL(fileURLWithPath: path), options: .atomic)
    }

    private func closeOutput() {
        try? outputHandle?.close()
        outputHandle = nil
    }

    private func openKindOutputs() {
        guard let outputDir = outputDir else { return }
        try? FileManager.default.createDirectory(atPath: outputDir, withIntermediateDirectories: true)
        kindHandles.removeAll()
    }

    private func closeKindOutputs() {
        for handle in kindHandles.values {
            try? handle.close()
        }
        kindHandles.removeAll()
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
        let event = buildEvent(eventType: eventType, process: process, message: message, props: props)
        writeEvent(event)
    }

    private func writeDerivedEvent(
        eventType: String,
        kind: String,
        process: es_process_t,
        message: UnsafePointer<es_message_t>,
        props: [String: String]
    ) {
        var event = buildEvent(eventType: eventType, process: process, message: message, props: props)
        event["kind"] = kind
        writeEvent(event)
        writeKindEvent(kind: kind, event: event)
    }

    private func buildEvent(
        eventType: String,
        process: es_process_t,
        message: UnsafePointer<es_message_t>,
        props: [String: String]
    ) -> [String: Any] {
        return [
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
    }

    private func writeKindEvent(kind: String, event: [String: Any]) {
        guard let outputDir = outputDir else { return }
        let handle: FileHandle
        if let existing = kindHandles[kind] {
            handle = existing
        } else {
            let path = "\(outputDir)/\(kind).jsonl"
            if !FileManager.default.fileExists(atPath: path) {
                FileManager.default.createFile(atPath: path, contents: nil)
            }
            guard let newHandle = try? FileHandle(forWritingTo: URL(fileURLWithPath: path)) else { return }
            try? newHandle.seekToEnd()
            kindHandles[kind] = newHandle
            handle = newHandle
        }
        guard let data = try? JSONSerialization.data(withJSONObject: event, options: []) else { return }
        handle.write(data)
        handle.write("\n".data(using: .utf8) ?? Data())
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
