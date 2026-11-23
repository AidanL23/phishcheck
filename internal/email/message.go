// Package email turns a raw .eml into a neutral Message that rules can inspect.
package email

// Message is everything the rules are allowed to see. Rules never touch raw
// bytes or MIME, so a rule test can build a Message literal by hand.
type Message struct {
	From        *Address      // nil if there is no From header
	ReplyTo     []*Address    // empty if there is no Reply-To header
	Subject     string        // encoded-words decoded to UTF-8
	Received    []ReceivedHop // header order: index 0 is the most recent hop
	AuthResults []AuthResult  // one per Authentication-Results header, header order
	TextParts   []string      // decoded text/plain bodies, UTF-8
	HTMLParts   []string      // decoded text/html bodies, UTF-8
	Attachments []Attachment  // metadata only; content bytes are never kept
	ParseErrors []string      // non-fatal problems, surfaced as INFO findings
	RawSHA256   string        // hex SHA-256 of the exact bytes submitted
}

// Address is one parsed mailbox from From or Reply-To.
type Address struct {
	Name    string // display name, decoded; empty if none
	Address string // local@domain; empty if the header failed to parse
	Raw     string // header value as received, kept as evidence
}

// ReceivedHop is one Received header, split into fields but not validated.
type ReceivedHop struct {
	Index int    // 0 = most recent hop
	From  string // host after "from"
	By    string // host after "by"
	With  string // protocol after "with"
	IP    string // bracketed IP, if present
	Date  string // text after the last ';'
	Raw   string // full header value, kept for the report
}

// AuthResult is one Authentication-Results header.
type AuthResult struct {
	AuthservID string // first token; identifies which server wrote the header
	SPF        string // pass, fail, softfail, none, temperror, ...
	DKIM       string
	DMARC      string
	Trusted    bool // true only if AuthservID matches the configured receiving server
	Raw        string
}

// Attachment is the metadata kept for one attachment or inline part.
type Attachment struct {
	Filename    string
	ContentType string
	Size        int64  // bytes after transfer decoding
	SHA256      string // hex; the only trace of the content we keep
}
