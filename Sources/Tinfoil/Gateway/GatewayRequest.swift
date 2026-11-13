import CryptoKit
import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// How the gateway client prepares a request before routing it: the model it
/// names goes in a header, and a prompt-cache scope is derived on the client,
/// since no router sits between a gateway client and the engine.
enum GatewayRequest {
    static let modelHeader = "X-Tinfoil-Model"
    static let cachePrefixHeader = "X-Tinfoil-Cache-Prefix"
    static let sealHeader = "X-Tinfoil-Seal"
    static let cacheSaltField = "cache_salt"
    static let maximumMultipartBytes = 64 << 20

    // The salt and the cache-prefix key are derived from the secret and the
    // API key under these labels, as every SDK derives them.
    private static let cacheSaltDomainTag = "tinfoil/client-cache-salt/v2"
    private static let cacheRouteDomainTag = "tinfoil/client-cache-route/v2"

    /// Returns request ready to route. A POST with a JSON object body gets the
    /// model header from its `model` member, unless the caller set one, and,
    /// on an endpoint whose prompts are cached, a `cache_salt` member in place
    /// of any `user_cache_secret`, with a cache-prefix header that keeps a
    /// conversation on one replica. The secret itself never leaves the client.
    /// A multipart upload without a model header must carry exactly one
    /// `model` field. Other requests are returned unchanged.
    static func prepare(_ request: URLRequest, secret: String) throws -> URLRequest {
        guard request.httpMethod?.uppercased() == "POST" else {
            return request
        }
        guard request.httpBodyStream == nil else {
            throw TinfoilError.configuration("the gateway client needs a request's body as httpBody, not a stream")
        }
        guard let body = request.httpBody, !body.isEmpty,
              let (mediaType, parameters) = mediaType(request.value(forHTTPHeaderField: "Content-Type"))
        else {
            return request
        }
        var prepared = request
        if mediaType == "multipart/form-data" {
            // An explicit model header keeps the upload as it is.
            if request.value(forHTTPHeaderField: modelHeader) != nil {
                return request
            }
            let model = try multipartModel(body, boundary: parameters["boundary"] ?? "")
            prepared.setValue(model, forHTTPHeaderField: modelHeader)
            return prepared
        }
        guard mediaType == "application/json" else {
            return request
        }
        let scoped = UserCacheSecret.isEligible(method: request.httpMethod, path: request.url?.path ?? "", body: body)
        guard let members = JSONObjectMembers(body) else {
            return request
        }
        try refuseRepeatedMembers(members)
        if request.value(forHTTPHeaderField: modelHeader) == nil,
           let model = members.string("model"), !model.isEmpty {
            prepared.setValue(model, forHTTPHeaderField: modelHeader)
        }
        if scoped {
            prepared.httpBody = scopeCache(&prepared, members: members, clientSecret: secret)
        }
        return prepared
    }

    /// Refuses a body that repeats a member the client reads. A server may
    /// read a different repeat from the one the client read, so the model it
    /// verified, or the cache scope it derived, could differ from the one used.
    private static func refuseRepeatedMembers(_ members: JSONObjectMembers) throws {
        let repeated = ["model", UserCacheSecret.bodyField, cacheSaltField].filter { name in
            members.all.filter { $0.key == name }.count > 1
        }
        guard !repeated.isEmpty else {
            return
        }
        let names = repeated.map { "\"\($0)\"" }.joined(separator: ", ")
        throw TinfoilError.configuration("request body repeats the \(names) member\(repeated.count > 1 ? "s" : "")")
    }

    /// Replaces the body's `user_cache_secret` with the `cache_salt` derived
    /// from it, or from the client's secret when the body has no non-empty
    /// string one, and sets the cache-prefix header. Without a secret the body
    /// is returned unchanged. Every other member keeps the caller's bytes.
    private static func scopeCache(_ request: inout URLRequest, members: JSONObjectMembers, clientSecret: String) -> Data {
        let bodySecret = members.string(UserCacheSecret.bodyField) ?? ""
        let secret = bodySecret.isEmpty ? clientSecret : bodySecret
        guard !secret.isEmpty else {
            return members.body
        }
        let apiKey = Data(bearerCredential(request.value(forHTTPHeaderField: "Authorization") ?? "").utf8)
        let salt = derive(secret: secret, apiKey: apiKey, tag: cacheSaltDomainTag)
        request.setValue(nil, forHTTPHeaderField: cachePrefixHeader)
        if let head = promptHead(members) {
            let key = SymmetricKey(data: derive(secret: secret, apiKey: apiKey, tag: cacheRouteDomainTag))
            let prefix = HMAC<SHA256>.authenticationCode(for: head, using: key)
            request.setValue(prefix.map { String(format: "%02x", $0) }.joined(), forHTTPHeaderField: cachePrefixHeader)
        }
        let encodedSalt = salt.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return members.replacing(
            removing: UserCacheSecret.bodyField,
            setting: cacheSaltField,
            to: Data("\"\(encodedSalt)\"".utf8)
        )
    }

    private static func derive(secret: String, apiKey: Data, tag: String) -> Data {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(secret.utf8)),
            salt: apiKey,
            info: Data(tag.utf8),
            outputByteCount: SHA256.byteCount
        )
        return key.withUnsafeBytes { Data($0) }
    }

    /// The credential of a Bearer authorization, whose scheme is
    /// case-insensitive, and "" for any other scheme
    static func bearerCredential(_ authorization: String) -> String {
        let trimmed = authorization.trimmingCharacters(in: .whitespaces)
        guard let space = trimmed.firstIndex(of: " "),
              trimmed[..<space].caseInsensitiveCompare("Bearer") == .orderedSame
        else {
            return ""
        }
        return trimmed[trimmed.index(after: space)...].trimmingCharacters(in: .whitespaces)
    }

    /// The part of the prompt that later turns of a conversation share: the
    /// instructions, else the first element of the messages, input or prompt,
    /// or the whole member when it isn't an array. The bytes are the caller's.
    private static func promptHead(_ members: JSONObjectMembers) -> Data? {
        if let instructions = members.string("instructions"), !instructions.isEmpty {
            return members.raw("instructions")
        }
        for name in ["messages", "input", "prompt"] {
            guard let raw = members.raw(name), raw != Data("null".utf8) else {
                continue
            }
            guard raw.first == UInt8(ascii: "[") else {
                return raw
            }
            if let first = JSONObjectMembers.firstElement(ofArray: raw) {
                return first
            }
        }
        return nil
    }

    /// The media type, lowercased, and its parameters, or nil for a header
    /// that doesn't parse
    static func mediaType(_ header: String?) -> (String, [String: String])? {
        guard let header else {
            return nil
        }
        var parts = header.split(separator: ";", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        let type = parts.removeFirst().lowercased()
        guard type.split(separator: "/").count == 2 else {
            return nil
        }
        var parameters: [String: String] = [:]
        for part in parts where !part.isEmpty {
            guard let equals = part.firstIndex(of: "=") else {
                return nil
            }
            var value = String(part[part.index(after: equals)...]).trimmingCharacters(in: .whitespaces)
            if value.count >= 2, value.hasPrefix("\""), value.hasSuffix("\"") {
                value = String(value.dropFirst().dropLast())
            }
            parameters[part[..<equals].trimmingCharacters(in: .whitespaces).lowercased()] = value
        }
        return (type, parameters)
    }

    /// The upload's one non-empty `model` field.
    static func multipartModel(_ body: Data, boundary: String) throws -> String {
        guard !boundary.isEmpty else {
            throw TinfoilError.configuration("multipart upload is missing its boundary")
        }
        guard body.count <= maximumMultipartBytes else {
            throw TinfoilError.configuration("multipart upload exceeds \(maximumMultipartBytes) bytes")
        }
        guard let parts = MultipartParts(body, boundary: boundary) else {
            throw TinfoilError.configuration("invalid multipart upload")
        }
        let models = parts.all.filter { $0.name == "model" }
        guard models.count == 1, !models[0].isFile,
              let model = String(data: models[0].content, encoding: .utf8),
              !model.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            throw TinfoilError.configuration("multipart upload must contain exactly one non-empty model field")
        }
        return model
    }
}

/// The top-level members of a body that is exactly one JSON object, with the
/// byte ranges of their values as the caller wrote them
struct JSONObjectMembers {
    struct Member {
        let key: String
        /// The key as written, quotes included
        let rawKey: Range<Int>
        let value: Range<Int>
    }

    let body: Data
    let all: [Member]
    private let bytes: [UInt8]

    init?(_ body: Data) {
        guard (try? JSONSerialization.jsonObject(with: body)) is [String: Any],
              !UserCacheSecret.containsTrailingComma(in: body)
        else {
            return nil
        }
        let bytes = [UInt8](body)
        var index = 0
        UserCacheSecret.skipWhitespace(in: bytes, index: &index)
        guard index < bytes.count, bytes[index] == UInt8(ascii: "{") else {
            return nil
        }
        index += 1
        var members: [Member] = []
        UserCacheSecret.skipWhitespace(in: bytes, index: &index)
        if index < bytes.count, bytes[index] == UInt8(ascii: "}") {
            index += 1
        } else {
            while true {
                UserCacheSecret.skipWhitespace(in: bytes, index: &index)
                guard let keyEnd = UserCacheSecret.stringEnd(in: bytes, from: index),
                      let key = try? JSONSerialization.jsonObject(with: Data(bytes[index..<keyEnd]), options: .fragmentsAllowed) as? String
                else {
                    return nil
                }
                let rawKey = index..<keyEnd
                index = keyEnd
                UserCacheSecret.skipWhitespace(in: bytes, index: &index)
                guard index < bytes.count, bytes[index] == UInt8(ascii: ":") else {
                    return nil
                }
                index += 1
                UserCacheSecret.skipWhitespace(in: bytes, index: &index)
                guard let valueEnd = Self.valueEnd(bytes, from: index) else {
                    return nil
                }
                members.append(Member(key: key, rawKey: rawKey, value: index..<valueEnd))
                index = valueEnd
                UserCacheSecret.skipWhitespace(in: bytes, index: &index)
                guard index < bytes.count else {
                    return nil
                }
                index += 1
                if bytes[index - 1] == UInt8(ascii: "}") {
                    break
                }
                guard bytes[index - 1] == UInt8(ascii: ",") else {
                    return nil
                }
            }
        }
        UserCacheSecret.skipWhitespace(in: bytes, index: &index)
        guard index == bytes.count else {
            return nil
        }
        self.body = body
        self.bytes = bytes
        self.all = members
    }

    /// The value of the last member named name, as written
    func raw(_ name: String) -> Data? {
        all.last { $0.key == name }.map { Data(bytes[$0.value]) }
    }

    /// The value of the last member named name, if it is a string
    func string(_ name: String) -> String? {
        raw(name).flatMap { try? JSONSerialization.jsonObject(with: $0, options: .fragmentsAllowed) as? String }
    }

    /// The object without any member named removed, and with every member
    /// named set given value, or one added at the end. Every other member
    /// keeps its key and value as written.
    func replacing(removing removed: String, setting name: String, to value: Data) -> Data {
        var output = Data("{".utf8)
        var wroteSet = false
        var first = true
        func append(_ key: Data, _ value: Data) {
            if !first {
                output.append(UInt8(ascii: ","))
            }
            first = false
            output.append(key)
            output.append(UInt8(ascii: ":"))
            output.append(value)
        }
        for member in all where member.key != removed {
            if member.key == name {
                append(Data(bytes[member.rawKey]), value)
                wroteSet = true
            } else {
                append(Data(bytes[member.rawKey]), Data(bytes[member.value]))
            }
        }
        if !wroteSet {
            append(Data("\"\(name)\"".utf8), value)
        }
        output.append(UInt8(ascii: "}"))
        return output
    }

    /// The first element of a JSON array, as written, or nil for an empty or
    /// malformed array
    static func firstElement(ofArray raw: Data) -> Data? {
        let bytes = [UInt8](raw)
        var index = 1
        UserCacheSecret.skipWhitespace(in: bytes, index: &index)
        guard index < bytes.count, bytes[index] != UInt8(ascii: "]"),
              let end = valueEnd(bytes, from: index)
        else {
            return nil
        }
        return Data(bytes[index..<end])
    }

    /// Where the value starting at start ends: a string or container by
    /// matching its delimiters, a scalar at the next delimiter or whitespace
    private static func valueEnd(_ bytes: [UInt8], from start: Int) -> Int? {
        guard start < bytes.count else {
            return nil
        }
        switch bytes[start] {
        case UInt8(ascii: "\""), UInt8(ascii: "{"), UInt8(ascii: "["):
            return UserCacheSecret.valueEnd(in: bytes, from: start)
        default:
            var index = start
            while index < bytes.count, !",}] \t\n\r".utf8.contains(bytes[index]) {
                index += 1
            }
            return index > start ? index : nil
        }
    }
}

/// The parts of a multipart/form-data body, enough to find its form fields
struct MultipartParts {
    struct Part {
        let name: String?
        let isFile: Bool
        let content: Data
    }

    let all: [Part]

    init?(_ body: Data, boundary: String) {
        let delimiter = Data("--\(boundary)".utf8)
        let crlf = Data("\r\n".utf8)
        guard var cursor = body.range(of: delimiter)?.upperBound else {
            return nil
        }
        var parts: [Part] = []
        while true {
            if body[cursor...].starts(with: Data("--".utf8)) {
                break
            }
            // Transport padding may follow the delimiter.
            while cursor < body.endIndex, body[cursor] == 0x20 || body[cursor] == 0x09 {
                cursor += 1
            }
            guard body[cursor...].starts(with: crlf) else {
                return nil
            }
            cursor += 2
            guard let headersEnd = body.range(of: Data("\r\n\r\n".utf8), in: cursor..<body.endIndex),
                  let next = body.range(of: crlf + delimiter, in: headersEnd.upperBound..<body.endIndex)
            else {
                return nil
            }
            let headers = String(decoding: body[cursor..<headersEnd.lowerBound], as: UTF8.self)
            parts.append(Self.part(headers: headers, content: body[headersEnd.upperBound..<next.lowerBound]))
            cursor = next.upperBound
        }
        all = parts
    }

    private static func part(headers: String, content: Data) -> Part {
        for line in headers.components(separatedBy: "\r\n") {
            guard let colon = line.firstIndex(of: ":"),
                  line[..<colon].trimmingCharacters(in: .whitespaces).caseInsensitiveCompare("Content-Disposition") == .orderedSame,
                  let (disposition, parameters) = GatewayRequest.mediaType(
                      // The disposition has the media type's grammar but no slash.
                      "x/" + line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                  ),
                  disposition == "x/form-data"
            else {
                continue
            }
            return Part(name: parameters["name"], isFile: parameters["filename"] != nil, content: Data(content))
        }
        return Part(name: nil, isFile: false, content: Data(content))
    }
}
