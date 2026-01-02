import Foundation

final class ZipArchiver {
    func archive(sourceDir: String, destinationZip: String) throws {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        proc.currentDirectoryURL = URL(fileURLWithPath: sourceDir)
        proc.arguments = ["-r", destinationZip, "."]
        try proc.run()
        proc.waitUntilExit()
        if proc.terminationStatus != 0 {
            throw NSError(domain: "ESCollector", code: 3, userInfo: [NSLocalizedDescriptionKey: "zip failed"])
        }
    }
}
