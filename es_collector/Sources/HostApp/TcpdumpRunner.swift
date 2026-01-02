import Foundation

final class TcpdumpRunner {
    private var process: Process?

    func start(interface: String, outputPath: String) throws {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/sbin/tcpdump")
        proc.arguments = ["-i", interface, "-w", outputPath]
        try proc.run()
        process = proc
    }

    func stop() {
        guard let process = process else { return }
        process.terminate()
        self.process = nil
    }
}
