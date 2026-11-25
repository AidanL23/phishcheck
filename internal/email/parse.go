package email

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/jhillyerd/enmime/v2"
)

// parser is shared by all workers; ReadEnvelope never mutates it.
var parser = enmime.NewParser(
	// Don't convert HTML to text, or Day 4 extracts HTML links twice.
	enmime.DisableTextConversion(true),
	// Real mail has a few parts; thousands is a resource-exhaustion attempt.
	enmime.MaxMIMEParts(500),
)

// Parse turns raw .eml bytes into a Message. It errors only if the MIME
// structure is unreadable; smaller problems go into ParseErrors.
func Parse(raw []byte) (*Message, error) {
	// Hash before parsing so even a failed parse can be traced to its file.
	sum := sha256.Sum256(raw)
	m := &Message{RawSHA256: hex.EncodeToString(sum[:])}

	env, err := parser.ReadEnvelope(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("email: parse %s: %w", m.RawSHA256[:12], err)
	}

	// GetHeader decodes encoded-words (=?UTF-8?B?...?=) to UTF-8.
	m.Subject = env.GetHeader("Subject")

	// Bodies arrive decoded and in UTF-8. Skip empties so len()==0 means "no body".
	if env.Text != "" {
		m.TextParts = append(m.TextParts, env.Text)
	}
	if env.HTML != "" {
		m.HTMLParts = append(m.HTMLParts, env.HTML)
	}

	// Problems enmime recovered from, e.g. "[W] Plain Text from HTML: ...".
	for _, e := range env.Errors {
		m.ParseErrors = append(m.ParseErrors, e.Error())
	}

	// From, Reply-To, Received, Authentication-Results and attachments come next.
	return m, nil
}
