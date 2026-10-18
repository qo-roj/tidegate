package redact

import (
	"regexp"
)

// StreamRedactor handles reverse-mapping of redaction tokens in streaming
// SSE responses. Tokens like [TG:IP:1] can be split across chunks, so a
// small boundary buffer is maintained to catch partial tokens.
//
// The stream redactor only does REVERSE mapping (token → original value).
// Outbound streaming responses from the cloud model don't need redaction —
// they're generated text, not user data. The concern is that the cloud model
// might mention a redaction token in its response, and the agent needs to
// see the real value.
type StreamRedactor struct {
	matcher   *TokenMatcher
	buffer    []byte
	maxBuffer int
}

// partialTokenStart matches a potential partial TG token at the end of a
// string, including a partially streamed MAC suffix. Only matches [TG:
// prefixed partial tokens, not arbitrary opening brackets.
var partialTokenStart = regexp.MustCompile(`\[TG:[A-Z0-9_]*(?::[0-9]*)?(?::[0-9a-f]*)?$`)

// NewStreamRedactor creates a StreamRedactor from a TokenMatcher.
func NewStreamRedactor(matcher *TokenMatcher) *StreamRedactor {
	return &StreamRedactor{
		matcher:   matcher,
		maxBuffer: 64, // max token length is ~20 chars, 64 is generous
	}
}

// ProcessChunk takes a chunk of streaming response and returns the
// reverse-mapped output. If a token is split across chunk boundaries,
// the partial token is held in the buffer until the next chunk arrives.
func (sr *StreamRedactor) ProcessChunk(chunk []byte) []byte {
	if sr.matcher == nil || !sr.matcher.HasMappings() {
		// No mappings — pass through unchanged
		return chunk
	}

	// Prepend any buffered data from the previous chunk
	combined := append(sr.buffer, chunk...)
	sr.buffer = nil

	text := string(combined)

	// Check if the end of text contains a potential partial token
	partialEnd := partialTokenStart.FindStringIndex(text)
	var flushPart, keepPart string

	if partialEnd != nil {
		// There's a potential partial token at the end.
		// Split: flush everything before it, keep the partial in buffer.
		splitPoint := partialEnd[0]

		// But only keep it if it's short enough to be a real token prefix
		potentialPartial := text[splitPoint:]
		if len(potentialPartial) <= sr.maxBuffer {
			flushPart = text[:splitPoint]
			keepPart = potentialPartial
		} else {
			// Too long to be a token — flush everything
			flushPart = text
			keepPart = ""
		}
	} else {
		// No partial token at end — flush everything
		flushPart = text
		keepPart = ""
	}

	// Reverse-map tokens in the flush portion
	flushPart = sr.matcher.Restore(flushPart)

	// Keep the partial in the buffer for next chunk
	sr.buffer = []byte(keepPart)

	return []byte(flushPart)
}

// Flush returns any remaining buffered data. Call when the stream ends.
func (sr *StreamRedactor) Flush() []byte {
	if len(sr.buffer) == 0 {
		return nil
	}

	// Reverse-map any remaining tokens in the buffer
	result := sr.matcher.Restore(string(sr.buffer))
	sr.buffer = nil
	return []byte(result)
}

// ProcessSSELine processes a single SSE data line and returns the
// reverse-mapped version. SSE lines start with "data: " and may contain
// JSON with content fields that include tokens.
func (sr *StreamRedactor) ProcessSSELine(line string) string {
	if sr.matcher == nil || !sr.matcher.HasMappings() {
		return line
	}

	// Only process "data:" lines, skip control lines
	if len(line) < 6 || line[:5] != "data:" {
		return line
	}

	// Reverse-map tokens in the entire data line
	return sr.matcher.Restore(line)
}
