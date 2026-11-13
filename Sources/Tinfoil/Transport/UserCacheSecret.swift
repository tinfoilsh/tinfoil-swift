import Foundation
import Security

/// Provisions the per-user prompt-cache secret defined by the secure prompt
/// caching contract. The router derives the request's prefix-cache namespace
/// from it: requests carrying the same secret (under the same API identity)
/// share cached prompt prefixes, requests carrying different secrets cannot
/// observe each other's cache timing.
///
/// A client of Tinfoil's inference routes, such as `RouterHTTPClient`,
/// `Client` or `GatewayHTTPClient`, resolves it in this order. A client of an
/// enclave the caller names uses only the first two, since other enclaves
/// don't read the field:
///
///  1. a non-empty per-request `user_cache_secret` field in the body, e.g.
///     set via `ChatQuery.extraBody`,
///  2. the client's `userCacheSecret` parameter; `Client` takes none, so for
///     it only steps 1 and 3 apply,
///  3. a random secret generated in memory once per process, which every
///     client in the process shares.
///
/// The SDK reads no environment variable or file for the secret. The
/// generated secret lasts only as long as the process, so an application that
/// wants a stable secret across processes or devices passes `userCacheSecret`
/// itself.
///
/// Injection happens in the EHBP session, before the body is sealed, so the
/// secret is only ever visible to the verified enclave.
internal enum UserCacheSecret {
    /// Router-only request-body field. A non-empty string scopes the prompt
    /// cache to that secret.
    static let bodyField = "user_cache_secret"

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

    /// Resolves the client-level secret: the explicit `userCacheSecret`
    /// parameter when it is non-empty, and otherwise the process's secret.
    static func resolve(explicit: String?) -> String {
        if let explicit, !explicit.isEmpty {
            return explicit
        }
        return processSecret
    }

    /// The 256-bit random secret, hex-encoded, that every client in the
    /// process shares when none is given. Generated on first use and never
    /// persisted.
    static let processSecret = generate()

    /// Returns a fresh 256-bit random secret, hex-encoded. Never falls back
    /// to a weak generator: if the system generator fails, the process stops
    /// rather than share a predictable cache namespace.
    static func generate() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("tinfoil: the system random number generator failed")
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
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
        var matchingRange: Range<Data.Index>?

        while index < bytes.count {
            skipWhitespace(in: bytes, index: &index)
            if index < bytes.count, bytes[index] == UInt8(ascii: "}") {
                return matchingRange
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
                guard matchingRange == nil else {
                    return nil
                }
                matchingRange = valueStart..<valueEnd
            }
            index = valueEnd
            skipWhitespace(in: bytes, index: &index)
            guard index < bytes.count else {
                return nil
            }
            if bytes[index] == UInt8(ascii: ",") {
                index += 1
            } else if bytes[index] == UInt8(ascii: "}") {
                return matchingRange
            } else {
                return nil
            }
        }
        return nil
    }

    static func skipWhitespace(in bytes: [UInt8], index: inout Int) {
        while index < bytes.count,
              bytes[index] == 0x20 || bytes[index] == 0x09
                || bytes[index] == 0x0A || bytes[index] == 0x0D {
            index += 1
        }
    }

    static func stringEnd(in bytes: [UInt8], from start: Int) -> Int? {
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

    static func valueEnd(in bytes: [UInt8], from start: Int) -> Int? {
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
    static func containsTrailingComma(in body: Data) -> Bool {
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
