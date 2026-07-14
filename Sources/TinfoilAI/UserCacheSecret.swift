import Foundation
import Security

/// Provisions the per-user prompt-cache secret defined by the secure prompt
/// caching contract. The router derives the request's prefix-cache namespace
/// from it: requests carrying the same secret (under the same API identity)
/// share cached prompt prefixes, requests carrying different secrets cannot
/// observe each other's cache timing. The secret itself is stripped by the
/// router and never reaches the model.
///
/// Resolution order, mirroring the other Tinfoil clients:
///
///  1. a non-empty per-request `user_cache_secret` field in the body, e.g.
///     set via `ChatQuery.extraBody`,
///  2. the `userCacheSecret` parameter of `TinfoilAI.create`,
///  3. the `TINFOIL_USER_CACHE_SECRET` environment variable,
///  4. a generated secret persisted at `~/.tinfoil/user_cache_secret` (0600),
///     shared with other Tinfoil SDKs using the same home directory.
///
/// Injection happens in the EHBP session, before the body is sealed, so the
/// secret is only ever visible to the verified enclave.
internal enum UserCacheSecret {
    /// Router-only request-body field. A non-empty string scopes the prompt
    /// cache to that secret.
    static let bodyField = "user_cache_secret"

    /// Environment variable that provisions the secret. An empty value is
    /// treated as unset.
    static let environmentVariable = "TINFOIL_USER_CACHE_SECRET"
    private static let homeEnvironmentVariable = "HOME"

    /// Persisted-secret path components under the home directory. The other
    /// Tinfoil SDKs use the same file, so one machine gets one cache
    /// namespace across tools.
    static let directoryName = ".tinfoil"
    static let fileName = "user_cache_secret"
    private static let directoryMode: mode_t = 0o700
    private static let secretFileMode: mode_t = 0o600

    /// OpenAI-compatible endpoints whose bodies carry the field. Matched by
    /// suffix with no `/v1` prefix required, so custom base URLs
    /// (path-prefixed proxies or `/v1`-less roots) still qualify. Other
    /// endpoints (embeddings, audio, files) are excluded: their engines do
    /// not prefix-cache and may reject unknown fields.
    static let eligiblePathSuffixes = [
        "/chat/completions",
        "/completions",
        "/responses",
    ]

    // MARK: - Resolution

    /// Resolves the client-level secret: a non-empty explicit
    /// `TinfoilAI.create` parameter wins, then a non-empty environment value,
    /// then the persisted (or generated) secret. Never throws: persistence
    /// failures degrade to an in-memory secret.
    static func resolve(
        explicit: String?,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        homeDirectory: URL? = defaultHomeDirectory
    ) -> String {
        if let explicit, !explicit.isEmpty {
            return explicit
        }
        if let env = environment[environmentVariable], !env.isEmpty {
            return env
        }
        return loadOrGenerate(homeDirectory: homeDirectory)
    }

    /// Home directory holding the persisted secret. Command-line processes
    /// honor `$HOME`, matching the other Tinfoil SDKs, while iOS falls back
    /// to the app container reported by `NSHomeDirectory()`.
    static var defaultHomeDirectory: URL? {
        homeDirectory()
    }

    static func homeDirectory(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        fallback: String = NSHomeDirectory()
    ) -> URL? {
        let home = environment[homeEnvironmentVariable] ?? fallback
        return home.isEmpty ? nil : URL(fileURLWithPath: home, isDirectory: true)
    }

    /// Returns a fresh 256-bit random secret, hex-encoded. Never falls back
    /// to a weak generator.
    static func generate() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            return ""
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Process-lifetime fallback for when the secret cannot be persisted. An
    /// unpersisted secret still isolates this process's cache namespace, but
    /// continuity is lost on restart — like a session ID, it silently resets
    /// the namespace every deploy.
    private static let ephemeral = generate()

    /// Returns the secret persisted under the home directory, generating and
    /// persisting one on first use. When the home directory is unavailable or
    /// unwritable it falls back to a process-lifetime in-memory secret.
    static func loadOrGenerate(homeDirectory: URL?) -> String {
        guard let homeDirectory else {
            return ephemeral
        }
        let directory = homeDirectory.appendingPathComponent(directoryName, isDirectory: true)

        var directoryStatus = stat()
        if lstat(directory.path, &directoryStatus) == 0 {
            guard directoryStatus.st_mode & S_IFMT == S_IFDIR else {
                return ephemeral
            }
        } else {
            guard errno == ENOENT else {
                return ephemeral
            }
            do {
                try FileManager.default.createDirectory(
                    at: directory,
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: directoryMode]
                )
            } catch {
                return ephemeral
            }
        }

        let destination = directory.appendingPathComponent(fileName, isDirectory: false)
        switch readPersistedSecret(at: destination) {
        case .value(let existing):
            return existing
        case .failure, .invalid:
            return ephemeral
        case .absent:
            break
        }

        let secret = generate()
        if secret.isEmpty {
            return ""
        }

        let candidate = directory.appendingPathComponent(
            "\(fileName).\(getpid()).\(UUID().uuidString).tmp",
            isDirectory: false
        )
        defer { _ = unlink(candidate.path) }
        var candidateFD = openRetryingOnInterruption(
            candidate.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
            secretFileMode
        )
        guard candidateFD >= 0 else {
            return ephemeral
        }
        defer {
            if candidateFD >= 0 {
                _ = close(candidateFD)
            }
        }

        guard writeAll(Data(secret.utf8), to: candidateFD) else {
            return ephemeral
        }
        guard close(candidateFD) == 0 else {
            candidateFD = -1
            return ephemeral
        }
        candidateFD = -1

        let linkResult = linkRetryingOnInterruption(candidate.path, destination.path)
        if linkResult == 0 {
            return secret
        }
        guard errno == EEXIST else {
            return ephemeral
        }

        switch readPersistedSecret(at: destination) {
        case .value(let persisted):
            return persisted
        case .absent, .failure, .invalid:
            return ephemeral
        }
    }

    /// Reads the persisted secret, trimming surrounding whitespace (the file
    /// may be hand-edited or written by another SDK with a trailing newline).
    /// Blank and invalid UTF-8 files are unusable because language runtimes
    /// do not normalize them consistently.
    private enum PersistedSecret {
        case value(String)
        case absent
        case invalid
        case failure
    }

    private static func readPersistedSecret(at file: URL) -> PersistedSecret {
        let fd = openRetryingOnInterruption(file.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else {
            return errno == ENOENT ? .absent : .failure
        }
        defer { _ = close(fd) }

        guard descriptorHasType(fd, type: S_IFREG) else {
            return .failure
        }
        return readSecret(from: fd)
    }

    private static func readSecret(from fd: Int32) -> PersistedSecret {
        guard lseek(fd, 0, SEEK_SET) >= 0 else {
            return .failure
        }
        var contents = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                read(fd, $0.baseAddress, $0.count)
            }
            if count > 0 {
                contents.append(buffer, count: count)
            } else if count == 0 {
                break
            } else if errno != EINTR {
                return .failure
            }
        }
        guard let decoded = String(data: contents, encoding: .utf8) else {
            return .invalid
        }
        let trimmed = decoded.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? .invalid : .value(trimmed)
    }

    private static func writeAll(_ contents: Data, to fd: Int32) -> Bool {
        contents.withUnsafeBytes { bytes in
            guard let baseAddress = bytes.baseAddress else {
                return contents.isEmpty
            }
            var offset = 0
            while offset < bytes.count {
                let count = write(fd, baseAddress.advanced(by: offset), bytes.count - offset)
                if count > 0 {
                    offset += count
                } else if count == 0 || errno != EINTR {
                    return false
                }
            }
            return true
        }
    }

    private static func openRetryingOnInterruption(
        _ path: String,
        _ flags: Int32,
        _ mode: mode_t = 0
    ) -> Int32 {
        var fd: Int32
        repeat {
            fd = open(path, flags, mode)
        } while fd < 0 && errno == EINTR
        return fd
    }

    private static func descriptorHasType(
        _ fd: Int32,
        type: mode_t
    ) -> Bool {
        var status = stat()
        return fstat(fd, &status) == 0
            && status.st_mode & S_IFMT == type
    }

    private static func linkRetryingOnInterruption(_ source: String, _ destination: String) -> Int32 {
        var result: Int32
        repeat {
            result = link(source, destination)
        } while result != 0 && errno == EINTR
        return result
    }

    // MARK: - Injection

    /// Applies the client-level secret to an outgoing request, returning the
    /// body to hand to the sealing client: the injected bytes when the
    /// request is eligible, the caller's original bytes otherwise. When the
    /// body changes, any Content-Length entry in `headers` is updated to
    /// describe the injected bytes.
    static func provision(
        request: URLRequest,
        headers: inout [String: String],
        clientSecret: String
    ) -> Data? {
        guard !clientSecret.isEmpty,
              let body = request.httpBody,
              isEligible(method: request.httpMethod, path: request.url?.path ?? "", body: body),
              let injected = inject(into: body, secret: clientSecret)
        else {
            return request.httpBody
        }
        for key in headers.keys where key.caseInsensitiveCompare("Content-Length") == .orderedSame {
            headers[key] = String(injected.count)
        }
        return injected
    }

    /// Reports whether the request can carry the field: a POST with a body
    /// to one of the supported endpoints.
    static func isEligible(method: String?, path: String, body: Data?) -> Bool {
        guard method?.uppercased() == "POST", let body, !body.isEmpty else {
            return false
        }
        return eligiblePathSuffixes.contains { path.hasSuffix($0) }
    }

    /// Adds the field to a JSON-object body by splicing it in ahead of the
    /// closing brace, leaving every caller-written byte — including number
    /// formatting, which a float round-trip would corrupt — exactly as the
    /// caller serialized it. Returns nil — forward the original bytes — for
    /// non-object bodies, trailing data, or a body that already carries a
    /// non-empty or non-string field. An empty string is replaced with the
    /// resolved client secret.
    static func inject(into body: Data, secret: String) -> Data? {
        guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              !containsTrailingComma(in: body)
        else {
            return nil
        }

        if let existing = object[bodyField] {
            guard let existing = existing as? String,
                  existing.isEmpty,
                  let valueRange = topLevelValueRange(in: body, for: bodyField),
                  let replacement = try? JSONSerialization.data(
                      withJSONObject: secret,
                      options: [.fragmentsAllowed]
                  )
            else {
                return nil
            }
            var injected = body
            injected.replaceSubrange(valueRange, with: replacement)
            return injected
        }

        guard let field = try? JSONSerialization.data(withJSONObject: [bodyField: secret]) else {
            return nil
        }

        // Splice the field in front of the closing brace, keeping the
        // caller's trailing whitespace framing.
        guard let closingBraceIndex = body.lastIndex(where: {
            $0 != 0x20 && $0 != 0x09 && $0 != 0x0A && $0 != 0x0D
        }), body[closingBraceIndex] == UInt8(ascii: "}") else {
            return nil
        }
        var injected = Data(body[..<closingBraceIndex])
        if !object.isEmpty {
            injected.append(UInt8(ascii: ","))
        }
        injected.append(field.dropFirst().dropLast()) // strip the one-field object's own braces
        injected.append(contentsOf: body[closingBraceIndex...])
        return injected
    }

    private static func topLevelValueRange(in body: Data, for field: String) -> Range<Data.Index>? {
        let bytes = [UInt8](body)
        var index = 0
        skipWhitespace(in: bytes, index: &index)
        guard index < bytes.count, bytes[index] == UInt8(ascii: "{") else {
            return nil
        }
        index += 1

        while index < bytes.count {
            skipWhitespace(in: bytes, index: &index)
            if index < bytes.count, bytes[index] == UInt8(ascii: "}") {
                return nil
            }
            guard let keyEnd = stringEnd(in: bytes, from: index),
                  let key = try? JSONSerialization.jsonObject(
                      with: Data(bytes[index..<keyEnd]),
                      options: [.fragmentsAllowed]
                  ) as? String
            else {
                return nil
            }
            index = keyEnd
            skipWhitespace(in: bytes, index: &index)
            guard index < bytes.count, bytes[index] == UInt8(ascii: ":") else {
                return nil
            }
            index += 1
            skipWhitespace(in: bytes, index: &index)
            let valueStart = index
            guard let valueEnd = valueEnd(in: bytes, from: valueStart) else {
                return nil
            }
            if key == field {
                return valueStart..<valueEnd
            }
            index = valueEnd
            skipWhitespace(in: bytes, index: &index)
            guard index < bytes.count else {
                return nil
            }
            if bytes[index] == UInt8(ascii: ",") {
                index += 1
            } else if bytes[index] == UInt8(ascii: "}") {
                return nil
            } else {
                return nil
            }
        }
        return nil
    }

    private static func skipWhitespace(in bytes: [UInt8], index: inout Int) {
        while index < bytes.count,
              bytes[index] == 0x20 || bytes[index] == 0x09
                || bytes[index] == 0x0A || bytes[index] == 0x0D {
            index += 1
        }
    }

    private static func stringEnd(in bytes: [UInt8], from start: Int) -> Int? {
        guard start < bytes.count, bytes[start] == UInt8(ascii: "\"") else {
            return nil
        }
        var index = start + 1
        var escaped = false
        while index < bytes.count {
            let byte = bytes[index]
            if escaped {
                escaped = false
            } else if byte == UInt8(ascii: "\\") {
                escaped = true
            } else if byte == UInt8(ascii: "\"") {
                return index + 1
            }
            index += 1
        }
        return nil
    }

    private static func valueEnd(in bytes: [UInt8], from start: Int) -> Int? {
        guard start < bytes.count else {
            return nil
        }
        if bytes[start] == UInt8(ascii: "\"") {
            return stringEnd(in: bytes, from: start)
        }
        if bytes[start] == UInt8(ascii: "{") || bytes[start] == UInt8(ascii: "[") {
            var index = start
            var depth = 0
            var inString = false
            var escaped = false
            while index < bytes.count {
                let byte = bytes[index]
                if inString {
                    if escaped {
                        escaped = false
                    } else if byte == UInt8(ascii: "\\") {
                        escaped = true
                    } else if byte == UInt8(ascii: "\"") {
                        inString = false
                    }
                } else if byte == UInt8(ascii: "\"") {
                    inString = true
                } else if byte == UInt8(ascii: "{") || byte == UInt8(ascii: "[") {
                    depth += 1
                } else if byte == UInt8(ascii: "}") || byte == UInt8(ascii: "]") {
                    depth -= 1
                    if depth == 0 {
                        return index + 1
                    }
                }
                index += 1
            }
            return nil
        }

        var index = start
        while index < bytes.count,
              bytes[index] != UInt8(ascii: ","),
              bytes[index] != UInt8(ascii: "}") {
            index += 1
        }
        var end = index
        while end > start,
              bytes[end - 1] == 0x20 || bytes[end - 1] == 0x09
                || bytes[end - 1] == 0x0A || bytes[end - 1] == 0x0D {
            end -= 1
        }
        return end > start ? end : nil
    }

    /// `JSONSerialization` accepts trailing commas on some platforms even
    /// though they are not valid JSON.
    private static func containsTrailingComma(in body: Data) -> Bool {
        let bytes = [UInt8](body)
        var inString = false
        var escaped = false
        for index in bytes.indices {
            let byte = bytes[index]
            if inString {
                if escaped {
                    escaped = false
                } else if byte == UInt8(ascii: "\\") {
                    escaped = true
                } else if byte == UInt8(ascii: "\"") {
                    inString = false
                }
            } else if byte == UInt8(ascii: "\"") {
                inString = true
            } else if byte == UInt8(ascii: "}") || byte == UInt8(ascii: "]") {
                var previous = index
                while previous > bytes.startIndex {
                    previous -= 1
                    let candidate = bytes[previous]
                    if candidate == UInt8(ascii: ",") {
                        return true
                    }
                    if candidate != 0x20 && candidate != 0x09 && candidate != 0x0A && candidate != 0x0D {
                        break
                    }
                }
            }
        }
        return false
    }
}
