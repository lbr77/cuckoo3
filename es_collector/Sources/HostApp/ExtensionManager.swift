import Foundation
import SystemExtensions

final class ExtensionManager: NSObject, OSSystemExtensionRequestDelegate {
    private var currentRequest: OSSystemExtensionRequest?
    private var currentRequestKind: RequestKind?
    private let semaphore = DispatchSemaphore(value: 0)
    private let queue = DispatchQueue(label: "escollector.extension.request")
    private var result: Result<Void, Error>?

    private enum RequestKind {
        case activate
        case deactivate
    }

    func activate() -> Result<Void, Error> {
        return submit(kind: .activate)
    }

    func deactivate() -> Result<Void, Error> {
        return submit(kind: .deactivate)
    }

    private func submit(kind: RequestKind) -> Result<Void, Error> {
        guard currentRequest == nil else {
            return .failure(NSError(domain: "ESCollector", code: 20, userInfo: [NSLocalizedDescriptionKey: "Request already in progress"]))
        }
        guard let bundleId = extensionBundleIdentifier() else {
            return .failure(NSError(domain: "ESCollector", code: 21, userInfo: [NSLocalizedDescriptionKey: "Extension bundle identifier not found"]))
        }
        let request: OSSystemExtensionRequest
        switch kind {
        case .activate:
            request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: bundleId, queue: queue)
        case .deactivate:
            request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: bundleId, queue: queue)
        }
        request.delegate = self
        currentRequest = request
        currentRequestKind = kind
        log("Submitting \(kind) request for \(bundleId)")
        OSSystemExtensionManager.shared.submitRequest(request)
        _ = semaphore.wait(timeout: .distantFuture)
        return result ?? .failure(NSError(domain: "ESCollector", code: 22, userInfo: [NSLocalizedDescriptionKey: "No result from system extension request"]))
    }

    private func extensionBundleIdentifier() -> String? {
        guard let bundle = extensionBundle() else { return nil }
        return bundle.bundleIdentifier
    }

    private func extensionBundle() -> Bundle? {
        let appURL = Bundle.main.bundleURL
        let systemExtensionsURL = URL(
            fileURLWithPath: "Contents/Library/SystemExtensions",
            relativeTo: appURL
        )
        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: systemExtensionsURL,
            includingPropertiesForKeys: nil,
            options: .skipsHiddenFiles
        ) else {
            return nil
        }
        guard let extensionURL = entries.first(where: { $0.pathExtension == "systemextension" }) else {
            return nil
        }
        return Bundle(url: extensionURL)
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        log("Replacing \(existing.bundleVersion) -> \(ext.bundleVersion)")
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        let error = NSError(domain: "ESCollector", code: 23, userInfo: [
            NSLocalizedDescriptionKey: "Needs user approval in System Settings"
        ])
        finish(with: .failure(error))
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        log("Request completed with result \(result.rawValue)")
        if result != .completed {
            let error = NSError(domain: "ESCollector", code: 24, userInfo: [
                NSLocalizedDescriptionKey: "Unexpected result: \(result.rawValue)"
            ])
            finish(with: .failure(error))
            return
        }
        finish(with: .success(()))
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        finish(with: .failure(error))
    }

    private func finish(with result: Result<Void, Error>) {
        self.result = result
        currentRequest = nil
        currentRequestKind = nil
        semaphore.signal()
    }

    private func log(_ message: String) {
        FileHandle.standardError.write(Data("[ExtensionManager] \(message)\n".utf8))
    }
}
