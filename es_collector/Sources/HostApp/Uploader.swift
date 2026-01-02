import Foundation

final class Uploader {
    func upload(zipPath: String, apiURL: String, apiToken: String, completion: @escaping (Result<Void, Error>) -> Void) {
        let endpoint = apiURL.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/import/analysis"
        guard let url = URL(string: endpoint) else {
            completion(.failure(NSError(domain: "ESCollector", code: 4, userInfo: [NSLocalizedDescriptionKey: "Invalid API URL"])))
            return
        }

        let boundary = "Boundary-\(UUID().uuidString)"
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("token \(apiToken)", forHTTPHeaderField: "Authorization")
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")

        guard let fileData = try? Data(contentsOf: URL(fileURLWithPath: zipPath)) else {
            completion(.failure(NSError(domain: "ESCollector", code: 5, userInfo: [NSLocalizedDescriptionKey: "Failed to read zip"])))
            return
        }

        var body = Data()
        body.append("--\(boundary)\r\n".data(using: .utf8) ?? Data())
        body.append("Content-Disposition: form-data; name=\"file\"; filename=\"analysis.zip\"\r\n".data(using: .utf8) ?? Data())
        body.append("Content-Type: application/zip\r\n\r\n".data(using: .utf8) ?? Data())
        body.append(fileData)
        body.append("\r\n--\(boundary)--\r\n".data(using: .utf8) ?? Data())
        request.httpBody = body

        URLSession.shared.dataTask(with: request) { _, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                completion(.failure(NSError(domain: "ESCollector", code: 6, userInfo: [NSLocalizedDescriptionKey: "Upload failed"])))
                return
            }
            self.notify(apiURL: apiURL, apiToken: apiToken, completion: completion)
        }.resume()
    }

    private func notify(apiURL: String, apiToken: String, completion: @escaping (Result<Void, Error>) -> Void) {
        let endpoint = apiURL.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/import/analysis"
        guard let url = URL(string: endpoint) else {
            completion(.failure(NSError(domain: "ESCollector", code: 7, userInfo: [NSLocalizedDescriptionKey: "Invalid API URL"])))
            return
        }
        var request = URLRequest(url: url)
        request.httpMethod = "PUT"
        request.setValue("token \(apiToken)", forHTTPHeaderField: "Authorization")
        URLSession.shared.dataTask(with: request) { _, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                completion(.failure(NSError(domain: "ESCollector", code: 8, userInfo: [NSLocalizedDescriptionKey: "Notify failed"])))
                return
            }
            completion(.success(()))
        }.resume()
    }
}
