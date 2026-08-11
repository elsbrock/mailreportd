package report

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"strings"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // register non-UTF-8 charsets
)

// Limits bound what a single message may expand to. Reports arrive from
// arbitrary senders over SMTP, so decompression is attacker-influenced and must
// be bounded rather than trusted.
const (
	// MaxMessageSize is the largest raw message accepted from a feeder.
	MaxMessageSize = 32 << 20
	// MaxPayloadSize is the largest single decompressed report accepted.
	MaxPayloadSize = 64 << 20
	// MaxPayloadsPerMessage bounds how many report documents one message may
	// yield, which caps zip archives with many entries.
	MaxPayloadsPerMessage = 16
)

// ErrNoPayload means the message carried nothing that resembled a report. This
// is expected and common: mailboxes collect autoreplies, bounces and spam.
var ErrNoPayload = errors.New("message contains no report payload")

// Payload is one report document extracted from a message, along with the
// filename it arrived under. The filename is the strongest format hint
// available and is worth keeping for diagnostics.
type Payload struct {
	Filename string
	Data     []byte
	// Format is set when the envelope walk already knows what this is — an ARF
	// message, whose payload is the message itself rather than an attachment.
	// Zero means "sniff the content", which is the common case.
	Format Format
}

// Message is the decoded envelope of a raw RFC 5322 message.
type Message struct {
	MessageID string
	Subject   string
	From      string
	Payloads  []Payload
}

// DecodeMessage walks a raw message and extracts every report payload it
// carries, transparently decompressing gzip and zip attachments.
//
// It never fails on a single bad part: a message with one unreadable attachment
// and one good report yields the good report.
func DecodeMessage(raw []byte) (*Message, error) {
	if len(raw) > MaxMessageSize {
		return nil, fmt.Errorf("message is %d bytes, over the %d byte limit", len(raw), MaxMessageSize)
	}

	entity, err := message.Read(bytes.NewReader(raw))
	if err != nil && entity == nil {
		return nil, fmt.Errorf("read message: %w", err)
	}

	msg := &Message{
		MessageID: strings.Trim(entity.Header.Get("Message-Id"), "<> "),
		Subject:   decodeHeader(entity.Header.Get("Subject")),
		From:      parseFrom(entity.Header.Get("From")),
	}

	collect(entity, msg)

	if len(msg.Payloads) == 0 {
		// Nothing attachment-shaped. ARF failure reports are a message
		// structure rather than an attachment format, so they are recognized
		// as a whole once the generic walk comes up empty.
		if arfPayload(raw, msg) {
			return msg, nil
		}
		return msg, ErrNoPayload
	}
	return msg, nil
}

// collect walks the MIME tree depth-first, gathering anything that decompresses
// or parses as a report.
func collect(entity *message.Entity, msg *Message) {
	if len(msg.Payloads) >= MaxPayloadsPerMessage {
		return
	}

	if mr := entity.MultipartReader(); mr != nil {
		for {
			part, err := mr.NextPart()
			if err != nil {
				return
			}
			collect(part, msg)
			if len(msg.Payloads) >= MaxPayloadsPerMessage {
				return
			}
		}
	}

	filename := partFilename(entity)
	body, err := io.ReadAll(io.LimitReader(entity.Body, MaxPayloadSize+1))
	if err != nil || len(body) == 0 {
		return
	}
	if len(body) > MaxPayloadSize {
		return
	}

	for _, p := range expand(filename, body) {
		msg.Payloads = append(msg.Payloads, p)
		if len(msg.Payloads) >= MaxPayloadsPerMessage {
			return
		}
	}
}

// expand decompresses a part into zero or more report documents. Content type
// is not trusted: reporters routinely label gzip attachments as
// application/octet-stream, or as text/plain with a .gz filename.
func expand(filename string, body []byte) []Payload {
	switch {
	case isGzip(body):
		data, err := gunzip(body)
		if err != nil {
			return nil
		}
		return []Payload{{Filename: strings.TrimSuffix(filename, ".gz"), Data: data}}

	case isZip(body):
		return unzip(filename, body)

	case looksLikeAggregate(body), looksLikeTLSRPT(body):
		return []Payload{{Filename: filename, Data: body}}
	}
	return nil
}

func isGzip(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b
}

func isZip(b []byte) bool {
	return len(b) >= 4 && b[0] == 'P' && b[1] == 'K' && (b[2] == 3 || b[2] == 5 || b[2] == 7)
}

func gunzip(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	data, err := io.ReadAll(io.LimitReader(zr, MaxPayloadSize+1))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	if len(data) > MaxPayloadSize {
		return nil, fmt.Errorf("gzip payload exceeds %d bytes", MaxPayloadSize)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("gzip payload is empty")
	}
	return data, nil
}

// unzip reads archive entries with a total budget, so an archive of many small
// highly-compressible entries cannot exhaust memory.
func unzip(filename string, b []byte) []Payload {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil
	}

	var (
		out       []Payload
		remaining = int64(MaxPayloadSize)
	)
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || len(out) >= MaxPayloadsPerMessage {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, remaining+1))
		rc.Close()
		if err != nil || int64(len(data)) > remaining {
			continue
		}
		remaining -= int64(len(data))

		name := f.Name
		if name == "" {
			name = filename
		}
		if looksLikeAggregate(data) || looksLikeTLSRPT(data) {
			out = append(out, Payload{Filename: name, Data: data})
		}
	}
	return out
}

// Parse turns a payload into a normalized report, choosing the parser by
// content rather than by filename. Filenames are conventional, not guaranteed,
// and a misnamed report is still a report.
func Parse(p Payload) (*Report, error) {
	switch {
	case p.Format == FormatDMARCFailure:
		return ParseDMARCFailure(p.Data)
	case looksLikeAggregate(p.Data):
		return ParseDMARCAggregate(p.Data)
	case looksLikeTLSRPT(p.Data):
		return ParseTLSRPT(p.Data)
	}
	return nil, fmt.Errorf("unrecognized report format in %q", p.Filename)
}

func partFilename(entity *message.Entity) string {
	_, params, err := entity.Header.ContentDisposition()
	if err == nil {
		if name := params["filename"]; name != "" {
			return name
		}
	}
	_, ctParams, err := entity.Header.ContentType()
	if err == nil {
		if name := ctParams["name"]; name != "" {
			return name
		}
	}
	return ""
}

func decodeHeader(v string) string {
	dec := new(mime.WordDecoder)
	if out, err := dec.DecodeHeader(v); err == nil {
		return out
	}
	return v
}

func parseFrom(v string) string {
	if addr, err := mail.ParseAddress(v); err == nil {
		return addr.Address
	}
	return strings.TrimSpace(v)
}
