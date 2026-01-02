import Foundation

final class ESCollectorExtension: NSObject, NSExtensionRequestHandling {
    private let collector = ESCollector()
    private var context: NSExtensionContext?

    func beginRequest(with context: NSExtensionContext) {
        self.context = context
        collector.start()
    }
}
