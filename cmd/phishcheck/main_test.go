package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/AidanL23/phishcheck/gen/go/phishcheck/v1"
)

// ---- clean ------------------------------------------------------------------

func TestClean(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"plain ascii", "invoice.eml", 0, "invoice.eml"},
		{"quotes and spaces pass", `say "hi" it's`, 0, `say "hi" it's`},
		{"non-ascii letters pass", "Zoë 日本語 Ñ", 0, "Zoë 日本語 Ñ"},
		{"ESC color sequence", "\x1b[31mred\x1b[0m", 0, `\x1b[31mred\x1b[0m`},
		{"CR LF TAB", "a\rb\nc\td", 0, `a\rb\nc\td`},
		{"RTL override", "invoice\u202egpj.exe", 0, `invoice\u202egpj.exe`},
		{"zero-width space", "pay\u200bpal", 0, `pay\u200bpal`},
		{"BEL and DEL", "\a\x7f", 0, `\a\x7f`},
		{"C1 CSI", "\u009b31m", 0, `\u009b31m`},
		{"invalid utf-8 becomes U+FFFD", "a\xffb", 0, "a\uFFFDb"},
		{"truncates with ellipsis", "abcdef", 3, "abc…"},
		{"exactly max: no ellipsis", "abc", 3, "abc"},
		{"max counts runes, not bytes", "日本語です", 2, "日本…"},
		{"an escape counts as one rune", "\x1b\x1b\x1b", 2, `\x1b\x1b…`},
		{"max 0 never truncates", strings.Repeat("x", 500), 0, strings.Repeat("x", 500)},
		{"empty", "", 10, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clean(tt.in, tt.max); got != tt.want {
				t.Errorf("clean(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
		})
	}
}

// onlyGraphic reports whether every rune in s is safe to print: no control or
// format characters that a terminal would act on.
func onlyGraphic(s string) bool {
	for _, r := range s {
		if !unicode.IsGraphic(r) {
			return false
		}
	}
	return true
}

// Every code point, one at a time: nothing clean() emits may be a control or
// format character. This is the property the rest of the CLI relies on.
func TestCleanEveryRuneIsSafe(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue // surrogates can't be encoded in a Go string
		}
		if out := clean(string(r), 0); !onlyGraphic(out) {
			t.Fatalf("clean(%U) = %q still contains a non-graphic rune", r, out)
		}
	}
}

// go test runs the seeds; go test -fuzz=FuzzClean ./cmd/phishcheck explores further.
func FuzzClean(f *testing.F) {
	for _, s := range []string{"", "plain", "\x1b]0;title\a", "a\u202eb", "\xff\xfe", "日本\r\n"} {
		f.Add(s, 0)
		f.Add(s, 3)
	}
	f.Fuzz(func(t *testing.T, s string, max int) {
		if max < 0 || max > 1000 {
			max = 0
		}
		out := clean(s, max)
		if !onlyGraphic(out) {
			t.Fatalf("clean(%q, %d) = %q contains a non-graphic rune", s, max, out)
		}
		if !utf8.ValidString(out) {
			t.Fatalf("clean(%q, %d) = %q is not valid UTF-8", s, max, out)
		}
		// Already-safe input is returned unchanged when not truncated.
		if max == 0 && utf8.ValidString(s) && onlyGraphic(s) && out != s {
			t.Fatalf("clean changed safe input %q to %q", s, out)
		}
	})
}

// ---- small helpers ----------------------------------------------------------

func TestEnumName(t *testing.T) {
	if got := enumName(pb.Verdict_VERDICT_LIKELY_PHISHING, "VERDICT_"); got != "LIKELY_PHISHING" {
		t.Errorf("got %q", got)
	}
	if got := enumName(pb.JobState_JOB_STATE_DONE, "JOB_STATE_"); got != "DONE" {
		t.Errorf("got %q", got)
	}
	// An unknown enum value prints as its number; no prefix to strip.
	if got := enumName(pb.Verdict(99), "VERDICT_"); got != "99" {
		t.Errorf("got %q", got)
	}
}

func TestParseInterspersed(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantPos  []string
		wantWait bool
		wantTO   time.Duration
	}{
		{"flag after file", []string{"clean.eml", "--wait"}, []string{"clean.eml"}, true, time.Minute},
		{"flag before file", []string{"--wait", "clean.eml"}, []string{"clean.eml"}, true, time.Minute},
		{"value flag between", []string{"a.eml", "--timeout", "5s", "b.eml"}, []string{"a.eml", "b.eml"}, false, 5 * time.Second},
		{"single dash form", []string{"-timeout=2s", "x"}, []string{"x"}, false, 2 * time.Second},
		{"no args", nil, nil, false, time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			wait := fs.Bool("wait", false, "")
			to := fs.Duration("timeout", time.Minute, "")
			pos := parseInterspersed(fs, tt.args)
			if !slices.Equal(pos, tt.wantPos) {
				t.Errorf("positional = %q, want %q", pos, tt.wantPos)
			}
			if *wait != tt.wantWait || *to != tt.wantTO {
				t.Errorf("wait=%v timeout=%v, want wait=%v timeout=%v", *wait, *to, tt.wantWait, tt.wantTO)
			}
		})
	}
}

func TestRPCErr(t *testing.T) {
	t.Run("unavailable wraps errUnreachable", func(t *testing.T) {
		err := rpcErr(status.Error(codes.Unavailable, "connection refused"))
		if !errors.Is(err, errUnreachable) {
			t.Fatalf("errors.Is(%v, errUnreachable) = false; submit-dir relies on it", err)
		}
		if !strings.Contains(err.Error(), "connection refused") {
			t.Errorf("lost the server detail: %v", err)
		}
	})
	t.Run("deadline gives advice", func(t *testing.T) {
		err := rpcErr(status.Error(codes.DeadlineExceeded, "ctx"))
		if !strings.Contains(err.Error(), "--timeout") {
			t.Errorf("got %v", err)
		}
	})
	for _, c := range []codes.Code{codes.ResourceExhausted, codes.NotFound, codes.InvalidArgument} {
		t.Run(c.String()+" keeps server message only", func(t *testing.T) {
			err := rpcErr(status.Error(c, "email exceeds 10 byte limit"))
			if err.Error() != "email exceeds 10 byte limit" {
				t.Errorf("got %q", err)
			}
		})
	}
	t.Run("other codes pass through", func(t *testing.T) {
		in := status.Error(codes.Internal, "could not store email")
		if got := rpcErr(in); got != in {
			t.Errorf("got %v, want the original error", got)
		}
	})
	t.Run("non-status error passes through", func(t *testing.T) {
		in := errors.New("plain")
		if got := rpcErr(in); got != in {
			t.Errorf("got %v", got)
		}
	})
}

func TestEmlFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"b.eml", "a.EML", "notes.txt", "c.eml.bak"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "folder.eml"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "b.eml"), filepath.Join(dir, "link.eml")); err != nil {
		t.Fatal(err)
	}

	got, err := emlFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(dir, "a.EML"), filepath.Join(dir, "b.eml")}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q (regular .eml files only, sorted)", got, want)
	}

	t.Run("no eml files", func(t *testing.T) {
		if _, err := emlFiles(t.TempDir()); err == nil || !strings.Contains(err.Error(), "no .eml files") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("missing dir is an error, not an empty list", func(t *testing.T) {
		if _, err := emlFiles(filepath.Join(dir, "nope")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("glob characters in the dir name", func(t *testing.T) {
		odd := filepath.Join(t.TempDir(), "case [1]*?")
		if err := os.Mkdir(odd, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(odd, "x.eml"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, err := emlFiles(odd); err != nil || len(got) != 1 {
			t.Errorf("got %q, %v", got, err)
		}
	})
}

// A file name is attacker-influenced (mail clients name a saved .eml after
// its Subject), and submitFile's errors repeat the full path. The per-file
// ERROR line must clean the error, not only the name in front of it.
func TestSubmitDirCleansErrors(t *testing.T) {
	dir := t.TempDir()
	evil := "\x1b[31mINVOICE\x1b[0m\r.eml"
	if err := os.WriteFile(filepath.Join(dir, evil), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// The empty file fails before any RPC, and grpc.NewClient doesn't
	// connect, so nothing is dialed.
	t.Setenv("PHISHCHECK_ADDR", "127.0.0.1:1")

	var err error
	stderr := captureStderr(t, func() { err = runSubmitDir(context.Background(), []string{dir}) })
	if err == nil || err.Error() != "1 of 1 files failed" {
		t.Errorf("err = %v", err)
	}
	if strings.ContainsAny(stderr, "\x1b\r") {
		t.Errorf("raw control characters reached stderr: %q", stderr)
	}
	if !strings.Contains(stderr, `\x1b[31mINVOICE\x1b[0m\r.eml is empty`) {
		t.Errorf("want the cleaned path in the error, got %q", stderr)
	}
}

func TestBatchErr(t *testing.T) {
	if err := batchErr([]dirResult{{}, {}}); err != nil {
		t.Errorf("all ok: got %v", err)
	}
	err := batchErr([]dirResult{{}, {err: errors.New("x")}, {err: errors.New("y")}})
	if err == nil || err.Error() != "2 of 3 files failed" {
		t.Errorf("got %v", err)
	}
}

// ---- report output ----------------------------------------------------------

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
// Not safe for parallel tests; none of these use t.Parallel.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}

func TestPrintReport(t *testing.T) {
	findings := []*pb.Finding{
		{RuleId: "LOW_ONE", Severity: pb.Severity_SEVERITY_LOW, Points: 1, Evidence: "low"},
		{RuleId: "HIGH_FIRST", Severity: pb.Severity_SEVERITY_HIGH, Points: 10, Evidence: "\x1b[2Jwiped"},
		{RuleId: "MED", Severity: pb.Severity_SEVERITY_MEDIUM, Points: 5, Evidence: strings.Repeat("e", 150)},
		{RuleId: "HIGH_SECOND", Severity: pb.Severity_SEVERITY_HIGH, Points: 10, Evidence: "h2"},
	}
	r := &pb.Report{
		JobId:      "job-1",
		Verdict:    pb.Verdict_VERDICT_LIKELY_PHISHING,
		Score:      26,
		Findings:   findings,
		Filename:   "invoice\u202egpj.eml\r\nverdict   CLEAN",
		Sha256:     "abc123",
		WorkerId:   "w1",
		AnalyzedAt: timestamppb.New(time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)),
	}
	before := slices.Clone(r.Findings)

	var out bytes.Buffer
	stderr := captureStderr(t, func() {
		if err := printReport(&out, r); err != nil {
			t.Fatal(err)
		}
	})
	got := out.String()

	if !strings.HasPrefix(got, "verdict   LIKELY_PHISHING (score 26)\n") {
		t.Errorf("header wrong:\n%s", got)
	}
	if !onlyGraphicLines(got) {
		t.Errorf("output contains raw control characters:\n%q", got)
	}
	if !strings.Contains(got, `invoice\u202egpj.eml\r\nverdict   CLEAN`) {
		t.Errorf("filename not cleaned (a newline here could forge a second verdict line):\n%s", got)
	}
	if !strings.Contains(got, `\x1b[2Jwiped`) {
		t.Errorf("evidence not cleaned:\n%s", got)
	}
	if !strings.Contains(got, strings.Repeat("e", 100)+"…") || strings.Contains(got, strings.Repeat("e", 101)) {
		t.Errorf("evidence not truncated to 100 runes:\n%s", got)
	}

	// HIGH first, stable within a severity, LOW last.
	order := []string{"HIGH_FIRST", "HIGH_SECOND", "MED", "LOW_ONE"}
	last := -1
	for _, id := range order {
		i := strings.Index(got, id)
		if i < last {
			t.Errorf("finding %s out of order:\n%s", id, got)
		}
		last = i
	}
	if !slices.Equal(r.Findings, before) {
		t.Error("printReport reordered the caller's findings slice")
	}
	if stderr != "" {
		t.Errorf("unexpected warning: %q", stderr)
	}
}

// onlyGraphicLines is onlyGraphic but allows the newlines printReport itself writes.
func onlyGraphicLines(s string) bool {
	return onlyGraphic(strings.ReplaceAll(s, "\n", ""))
}

func TestPrintReportEmptyAndMismatch(t *testing.T) {
	r := &pb.Report{Verdict: pb.Verdict_VERDICT_CLEAN, Score: 7} // no findings, no timestamp
	var out bytes.Buffer
	stderr := captureStderr(t, func() {
		if err := printReport(&out, r); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out.String(), "findings (0)\n  none\n") {
		t.Errorf("no-findings output wrong:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "at -\n") {
		t.Errorf("nil AnalyzedAt should print '-', not 1970:\n%s", out.String())
	}
	if !strings.Contains(stderr, "findings add up to 0 but score is 7") {
		t.Errorf("score mismatch not warned: %q", stderr)
	}
}

func TestPrintJSON(t *testing.T) {
	r := &pb.Report{JobId: "j1", Verdict: pb.Verdict_VERDICT_CLEAN, Filename: "a\x1b[31m.eml"}
	var out bytes.Buffer
	if err := printJSON(&out, r); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	// protojson deliberately randomizes its whitespace, so decode rather
	// than compare text.
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, got)
	}
	if _, ok := m["job_id"]; !ok {
		t.Error("want proto field names (job_id), not jobId")
	}
	if m["verdict"] != "VERDICT_CLEAN" {
		t.Errorf("verdict = %v, want the enum name", m["verdict"])
	}
	// EmitUnpopulated: zero values must be present so `jq .score` prints 0, not null.
	if m["score"] != float64(0) {
		t.Errorf("score = %v, want 0", m["score"])
	}
	if f, ok := m["findings"].([]any); !ok || len(f) != 0 {
		t.Errorf("findings = %v, want []", m["findings"])
	}
	if m["filename"] != "a\x1b[31m.eml" {
		t.Errorf("--json must keep the exact bytes, got %q", m["filename"])
	}
	// ...but JSON string escaping still means a raw ESC never reaches the terminal.
	if strings.ContainsRune(got, '\x1b') {
		t.Errorf("raw ESC in JSON output:\n%q", got)
	}
}

func TestPrintDirTable(t *testing.T) {
	results := []dirResult{
		{file: "a.eml", jobID: "j1", report: &pb.Report{Verdict: pb.Verdict_VERDICT_CLEAN, WorkerId: "w1"}},
		{file: "b\x1b.eml", err: errors.New("is empty")}, // upload failed: no job
		{file: "c.eml", jobID: "j3", err: errors.New("job j3 failed: boom")},
		{file: "d.eml", jobID: "j4", report: &pb.Report{Verdict: pb.Verdict_VERDICT_SUSPICIOUS, Score: 40, WorkerId: "w2"}},
	}
	var out bytes.Buffer
	stderr := captureStderr(t, func() {
		if err := printDirTable(&out, results); err != nil {
			t.Fatal(err)
		}
	})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("want header + 4 rows, got:\n%s", out.String())
	}
	checks := [][]string{
		{"FILE", "VERDICT", "SCORE", "WORKER", "JOB"},
		{"a.eml", "CLEAN", "0", "w1", "j1"},
		{`b\x1b.eml`, "ERROR", "-", "-", "-"},
		{"c.eml", "ERROR", "-", "-", "j3"},
		{"d.eml", "SUSPICIOUS", "40", "w2", "j4"},
	}
	for i, want := range checks {
		if got := strings.Fields(lines[i]); !slices.Equal(got, want) {
			t.Errorf("row %d = %q, want %q", i, got, want)
		}
	}
	// Only wait errors are repeated after the table; upload errors were
	// already printed during phase 1.
	if !strings.Contains(stderr, "c.eml: job j3 failed: boom") || strings.Contains(stderr, "is empty") {
		t.Errorf("stderr wrong: %q", stderr)
	}
	if !strings.Contains(stderr, "4 files, 2 workers: w1=1 w2=1") {
		t.Errorf("worker summary wrong: %q", stderr)
	}
}

// ---- submitFile and waitForReport, against an in-memory fake client ---------

// fakeClient implements pb.PhishCheckServiceClient with no network.
type fakeClient struct {
	submit     *fakeSubmitStream
	submitCall int
	submitCtx  context.Context // the context SubmitEmail was opened with

	watchMsgs []*pb.WatchReportResponse
	watchErr  error // returned after watchMsgs instead of io.EOF, if set
	report    *pb.GetReportResponse
	reportErr error
}

func (c *fakeClient) SubmitEmail(ctx context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[pb.SubmitEmailRequest, pb.SubmitEmailResponse], error) {
	c.submitCall++
	c.submitCtx = ctx
	return c.submit, nil
}

func (c *fakeClient) GetReport(context.Context, *pb.GetReportRequest, ...grpc.CallOption) (*pb.GetReportResponse, error) {
	return c.report, c.reportErr
}

func (c *fakeClient) WatchReport(context.Context, *pb.WatchReportRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.WatchReportResponse], error) {
	return &fakeWatchStream{msgs: c.watchMsgs, err: c.watchErr}, nil
}

// fakeSubmitStream records every message and, by default, answers like the
// real server: the SHA-256 and size of the bytes it received.
type fakeSubmitStream struct {
	grpc.ClientStream // nil; only the methods below are called

	reqs     []*pb.SubmitEmailRequest
	eofAfter int   // Send returns io.EOF once this many messages arrived (0 = never)
	sendErr  error // returned by every Send, if set
	closeErr error // returned by CloseAndRecv
	badSHA   bool  // reply with a wrong hash
}

func (s *fakeSubmitStream) Send(r *pb.SubmitEmailRequest) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	if s.eofAfter > 0 && len(s.reqs) >= s.eofAfter {
		return io.EOF // what gRPC does once the server has aborted the stream
	}
	s.reqs = append(s.reqs, r)
	return nil
}

func (s *fakeSubmitStream) data() []byte {
	var b []byte
	for _, r := range s.reqs {
		b = append(b, r.GetData()...)
	}
	return b
}

func (s *fakeSubmitStream) CloseAndRecv() (*pb.SubmitEmailResponse, error) {
	if s.closeErr != nil {
		return nil, s.closeErr
	}
	d := s.data()
	sum := sha256.Sum256(d)
	resp := &pb.SubmitEmailResponse{JobId: "job-1", Sha256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(d))}
	if s.badSHA {
		resp.Sha256 = strings.Repeat("0", 64)
	}
	return resp, nil
}

type fakeWatchStream struct {
	grpc.ClientStream
	msgs []*pb.WatchReportResponse
	err  error
}

func (s *fakeWatchStream) Recv() (*pb.WatchReportResponse, error) {
	if len(s.msgs) == 0 {
		if s.err != nil {
			return nil, s.err
		}
		return nil, io.EOF
	}
	m := s.msgs[0]
	s.msgs = s.msgs[1:]
	return m, nil
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSubmitFileChunking(t *testing.T) {
	// Sizes around the 64 KB boundary: the off-by-one cases for the
	// "handle n > 0 before io.EOF" logic.
	for _, size := range []int{1, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 17} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i * 7)
			}
			path := writeFile(t, "sample.eml", data)
			stream := &fakeSubmitStream{}
			resp, err := submitFile(context.Background(), &fakeClient{submit: stream}, path)
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetSizeBytes() != int64(size) {
				t.Errorf("size = %d, want %d", resp.GetSizeBytes(), size)
			}
			wantChunks := (size + chunkSize - 1) / chunkSize
			if len(stream.reqs) != wantChunks {
				t.Errorf("sent %d messages, want %d", len(stream.reqs), wantChunks)
			}
			for i, r := range stream.reqs {
				if len(r.GetData()) > chunkSize {
					t.Errorf("message %d carries %d bytes, over the 64 KB contract", i, len(r.GetData()))
				}
				wantName := ""
				if i == 0 {
					wantName = "sample.eml" // base name only, never the local path
				}
				if r.GetFilename() != wantName {
					t.Errorf("message %d filename = %q, want %q", i, r.GetFilename(), wantName)
				}
			}
			if !bytes.Equal(stream.data(), data) {
				t.Error("bytes received differ from the file")
			}
		})
	}
}

func TestSubmitFileChunksAreNotReused(t *testing.T) {
	// gRPC forbids touching a message after Send. If submitFile reused one
	// buffer, every recorded chunk would alias the last read.
	data := append(bytes.Repeat([]byte("A"), chunkSize), bytes.Repeat([]byte("B"), chunkSize)...)
	stream := &fakeSubmitStream{}
	if _, err := submitFile(context.Background(), &fakeClient{submit: stream}, writeFile(t, "x.eml", data)); err != nil {
		t.Fatal(err)
	}
	if stream.reqs[0].GetData()[0] != 'A' {
		t.Error("first chunk was overwritten by the second: the read buffer is shared")
	}
}

func TestSubmitFileErrors(t *testing.T) {
	t.Run("empty file never opens a stream", func(t *testing.T) {
		c := &fakeClient{submit: &fakeSubmitStream{}}
		_, err := submitFile(context.Background(), c, writeFile(t, "empty.eml", nil))
		if err == nil || !strings.Contains(err.Error(), "is empty") || c.submitCall != 0 {
			t.Errorf("err=%v calls=%d", err, c.submitCall)
		}
	})
	t.Run("directory never opens a stream", func(t *testing.T) {
		c := &fakeClient{submit: &fakeSubmitStream{}}
		_, err := submitFile(context.Background(), c, t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "submit-dir") || c.submitCall != 0 {
			t.Errorf("err=%v calls=%d", err, c.submitCall)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		_, err := submitFile(context.Background(), &fakeClient{}, filepath.Join(t.TempDir(), "nope.eml"))
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("server aborts mid-upload: real status comes from CloseAndRecv", func(t *testing.T) {
		stream := &fakeSubmitStream{
			eofAfter: 1,
			closeErr: status.Error(codes.ResourceExhausted, "email exceeds 65536 byte limit"),
		}
		_, err := submitFile(context.Background(), &fakeClient{submit: stream}, writeFile(t, "big.eml", make([]byte, 3*chunkSize)))
		if err == nil || err.Error() != "email exceeds 65536 byte limit" {
			t.Errorf("got %v, want the server's ResourceExhausted message", err)
		}
	})
	t.Run("integrity mismatch is caught", func(t *testing.T) {
		stream := &fakeSubmitStream{badSHA: true}
		_, err := submitFile(context.Background(), &fakeClient{submit: stream}, writeFile(t, "x.eml", []byte("hello")))
		if err == nil || !strings.Contains(err.Error(), "integrity mismatch") {
			t.Errorf("got %v", err)
		}
	})
}

// gRPC keeps a client stream open until its context ends. On an early
// return, submitFile skips CloseAndRecv, so it must cancel the stream itself
// rather than leave it to the caller's (possibly minutes-long) context.
func TestSubmitFileEndsStreamOnEarlyReturn(t *testing.T) {
	c := &fakeClient{submit: &fakeSubmitStream{sendErr: errors.New("marshal failed")}}
	_, err := submitFile(context.Background(), c, writeFile(t, "x.eml", []byte("hello")))
	if err == nil || !strings.Contains(err.Error(), "send chunk") {
		t.Fatalf("got %v", err)
	}
	if c.submitCtx == nil || c.submitCtx.Err() == nil {
		t.Error("stream context still live after submitFile returned: the stream leaks")
	}
}

func watchMsg(state pb.JobState, worker, errMsg string) *pb.WatchReportResponse {
	return &pb.WatchReportResponse{Status: &pb.JobStatus{State: state, WorkerId: worker, Error: errMsg}}
}

func TestWaitForReport(t *testing.T) {
	report := &pb.Report{JobId: "j1", Verdict: pb.Verdict_VERDICT_CLEAN}

	t.Run("done", func(t *testing.T) {
		c := &fakeClient{
			watchMsgs: []*pb.WatchReportResponse{
				watchMsg(pb.JobState_JOB_STATE_QUEUED, "", ""),
				watchMsg(pb.JobState_JOB_STATE_RUNNING, "w1", ""),
				watchMsg(pb.JobState_JOB_STATE_DONE, "w1", ""),
			},
			report: &pb.GetReportResponse{Report: report},
		}
		var progress bytes.Buffer
		got, err := waitForReport(context.Background(), c, "j1", &progress)
		if err != nil || got != report {
			t.Fatalf("got %v, %v", got, err)
		}
		if want := "QUEUED   -\nRUNNING  -         (w1)\nDONE     -\n"; progress.String() != want {
			t.Errorf("progress = %q, want %q", progress.String(), want)
		}
	})
	t.Run("failed: worker error is cleaned", func(t *testing.T) {
		c := &fakeClient{watchMsgs: []*pb.WatchReportResponse{
			watchMsg(pb.JobState_JOB_STATE_FAILED, "w1", "parse: bad header \x1b[2J"),
		}}
		_, err := waitForReport(context.Background(), c, "j1", io.Discard)
		if err == nil || !strings.Contains(err.Error(), `bad header \x1b[2J`) || strings.ContainsRune(err.Error(), '\x1b') {
			t.Errorf("got %q", err)
		}
	})
	t.Run("stream closed before a terminal state", func(t *testing.T) {
		c := &fakeClient{watchMsgs: []*pb.WatchReportResponse{watchMsg(pb.JobState_JOB_STATE_RUNNING, "w1", "")}}
		_, err := waitForReport(context.Background(), c, "j1", io.Discard)
		if err == nil || !strings.Contains(err.Error(), "JOB_STATE_RUNNING") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("stream closed with no messages", func(t *testing.T) {
		_, err := waitForReport(context.Background(), &fakeClient{}, "j1", io.Discard)
		if err == nil || !strings.Contains(err.Error(), "JOB_STATE_UNSPECIFIED") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("watch error", func(t *testing.T) {
		c := &fakeClient{watchErr: status.Error(codes.NotFound, "job j1 not found or expired")}
		_, err := waitForReport(context.Background(), c, "j1", io.Discard)
		if err == nil || err.Error() != "watch: job j1 not found or expired" {
			t.Errorf("got %v", err)
		}
	})
	t.Run("done but no report", func(t *testing.T) {
		c := &fakeClient{
			watchMsgs: []*pb.WatchReportResponse{watchMsg(pb.JobState_JOB_STATE_DONE, "w1", "")},
			report:    &pb.GetReportResponse{},
		}
		_, err := waitForReport(context.Background(), c, "j1", io.Discard)
		if err == nil || !strings.Contains(err.Error(), "no report") {
			t.Errorf("got %v", err)
		}
	})
}

// ---- timeline (§2.6 --wait progress) -------------------------------------------

func TestTimeline(t *testing.T) {
	base := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *timestamppb.Timestamp { return timestamppb.New(base.Add(d)) }
	st := func(s pb.JobState, worker string, attempts int32, started, finished *timestamppb.Timestamp) *pb.JobStatus {
		return &pb.JobStatus{State: s, WorkerId: worker, Attempts: attempts,
			SubmittedAt: at(0), StartedAt: started, FinishedAt: finished}
	}
	const (
		Q = pb.JobState_JOB_STATE_QUEUED
		R = pb.JobState_JOB_STATE_RUNNING
		D = pb.JobState_JOB_STATE_DONE
		F = pb.JobState_JOB_STATE_FAILED
	)

	tests := []struct {
		name     string
		statuses []*pb.JobStatus
		want     string
	}{
		{
			name: "every phase seen, sub-second offsets print as ms",
			statuses: []*pb.JobStatus{
				st(Q, "", 0, nil, nil),
				st(R, "w1", 1, at(300*time.Microsecond), nil),
				st(D, "w1", 1, at(300*time.Microsecond), at(1800*time.Microsecond)),
			},
			want: "QUEUED   0.0s\nRUNNING  +0.3ms    (w1)\nDONE     +1.8ms\n",
		},
		{
			// A fast job can be DONE before the first poll: the missed
			// phases are rebuilt from the timestamps.
			name:     "first status is already DONE",
			statuses: []*pb.JobStatus{st(D, "w1", 1, at(2*time.Second), at(3840*time.Millisecond))},
			want:     "QUEUED   0.0s\nRUNNING  +2.0s     (w1)\nDONE     +3.8s\n",
		},
		{
			// §2.4: the reclaimed attempt gets its own RUNNING line, which is
			// the crash-recovery evidence in the README screenshot.
			name: "reclaim prints a second RUNNING line",
			statuses: []*pb.JobStatus{
				st(R, "a", 1, at(1400*time.Microsecond), nil),
				st(R, "b", 2, at(60700*time.Millisecond), nil),
				st(D, "b", 2, at(60700*time.Millisecond), at(60702*time.Millisecond)),
			},
			want: "QUEUED   0.0s\nRUNNING  +1.4ms    (a)\nRUNNING  +60.7s    (b, attempt 2)\nDONE     +60.7s\n",
		},
		{
			// §2.5: three panics, then dead-lettered.
			name: "dead-lettered after three attempts",
			statuses: []*pb.JobStatus{
				st(R, "p", 1, at(time.Millisecond), nil),
				st(R, "p", 2, at(29500*time.Millisecond), nil),
				st(R, "p", 3, at(59500*time.Millisecond), nil),
				st(F, "p", 3, at(59500*time.Millisecond), at(89500*time.Millisecond)),
			},
			want: "QUEUED   0.0s\nRUNNING  +1.0ms    (p)\nRUNNING  +29.5s    (p, attempt 2)\n" +
				"RUNNING  +59.5s    (p, attempt 3)\nFAILED   +89.5s\n",
		},
		{
			// Clock skew between the API and worker hosts shows as negative.
			name:     "skew keeps the sign",
			statuses: []*pb.JobStatus{st(D, "w1", 1, at(-200*time.Millisecond), at(-150*time.Millisecond))},
			want:     "QUEUED   0.0s\nRUNNING  -200.0ms  (w1)\nDONE     -150.0ms\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			tl := &timeline{w: &buf}
			for _, s := range tt.statuses {
				tl.update(s)
			}
			if buf.String() != tt.want {
				t.Errorf("got:\n%s\nwant:\n%s", buf.String(), tt.want)
			}
		})
	}
}
