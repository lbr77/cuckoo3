import Foundation

enum FileIO {
    static func ensureDir(_ path: String) throws {
        try FileManager.default.createDirectory(
            atPath: path,
            withIntermediateDirectories: true,
            attributes: nil
        )
    }

    static func writeJSON<T: Encodable>(_ value: T, to path: String) throws {
        let data = try JSONEncoder().encode(value)
        let url = URL(fileURLWithPath: path)
        try data.write(to: url, options: .atomic)
    }

    static func readJSON<T: Decodable>(_ type: T.Type, from path: String) throws -> T {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try JSONDecoder().decode(type, from: data)
    }
}
