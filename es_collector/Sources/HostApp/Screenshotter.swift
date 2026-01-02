import AppKit
import Foundation

final class Screenshotter {
    func capture(to url: URL) throws {
        guard let image = CGWindowListCreateImage(
            .infinite,
            .optionOnScreenOnly,
            kCGNullWindowID,
            .bestResolution
        ) else {
            throw NSError(domain: "ESCollector", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to capture screen"])
        }
        let bitmap = NSBitmapImageRep(cgImage: image)
        guard let data = bitmap.representation(using: .jpeg, properties: [.compressionFactor: 0.7]) else {
            throw NSError(domain: "ESCollector", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to encode screenshot"])
        }
        try data.write(to: url, options: .atomic)
    }
}
