import Foundation

/// Tinfoil-specific progress events the router can emit inline with the
/// model's assistant text. Each case maps to one comma-separated value in
/// the `X-Tinfoil-Events` request header. The router rides these events
/// as `<tinfoil-event>...</tinfoil-event>` markers carried inside the
/// normal content stream: strict OpenAI SDKs simply see the tags as text,
/// while clients that opted in parse and strip the tags before rendering.
public enum TinfoilEvent: String, Sendable, Hashable, CaseIterable {
    /// Live progress updates for router-owned web search and URL fetch
    /// tool calls. Each marker carries the same shape the non-streaming
    /// `web_search_call` output item uses, with extra `status` values
    /// (`blocked`) and an optional `error` object for detail beyond what
    /// the OpenAI spec documents.
    case webSearch = "web_search"
}

/// Name of the request header clients set to opt into the tinfoil-event
/// marker stream.
public let tinfoilEventsHeader = "X-Tinfoil-Events"

/// Formats a set of tinfoil events as the comma-separated value expected
/// by the `X-Tinfoil-Events` request header. Returns `nil` when the set
/// is empty so callers can skip adding the header entirely.
func tinfoilEventsHeaderValue(_ events: Set<TinfoilEvent>) -> String? {
    guard !events.isEmpty else { return nil }
    return events.map(\.rawValue).sorted().joined(separator: ",")
}
