package registry

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type zipEntry struct {
	name string
	mode os.FileMode
}

func buildZip(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(e.name, "/") {
			fmt.Fprint(f, "content of "+e.name)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func file(name string) zipEntry { return zipEntry{name: name} }

func TestCheckArchive(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		entries []zipEntry
		wantLib string
		wantErr string
	}{
		{"root library", "darwin", []zipEntry{file("demo.dylib")}, "demo.dylib", ""},
		{"versioned library", "linux", []zipEntry{file("demo-v1.2.0.so")}, "demo-v1.2.0.so", ""},
		{"windows library", "windows", []zipEntry{file("demo.dll")}, "demo.dll", ""},
		{"other files are ignored", "darwin", []zipEntry{file("README.md"), file("docs/"), file("docs/LICENSE"), file("demo.dylib")}, "demo.dylib", ""},
		{"backslash", "darwin", []zipEntry{file(`docs\README.md`), file("demo.dylib")}, "", "backslash"},
		{"absolute path", "darwin", []zipEntry{file("/etc/demo"), file("demo.dylib")}, "", "is absolute"},
		{"parent escape", "darwin", []zipEntry{file("docs/../../demo"), file("demo.dylib")}, "", "escapes the archive root"},
		{"symlink", "darwin", []zipEntry{{name: "link", mode: os.ModeSymlink | 0o777}, file("demo.dylib")}, "", "not a regular file"},
		{"nested library", "darwin", []zipEntry{file("lib/demo.dylib")}, "", "must be at the zip root"},
		{"wrong library name", "darwin", []zipEntry{file("other.dylib")}, "", "must be named demo.dylib or demo-v1.2.0.dylib"},
		{"library for another OS", "darwin", []zipEntry{file("demo.so")}, "", "must be named"},
		{"upper-case extension counts as a library", "darwin", []zipEntry{file("demo.DYLIB")}, "", "must be named"},
		{"two libraries", "darwin", []zipEntry{file("demo.dylib"), file("demo-v1.2.0.dylib")}, "", "zip contains both"},
		{"no library", "darwin", []zipEntry{file("README.md")}, "", "does not contain demo.dylib"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lib, err := CheckArchive(buildZip(t, tt.entries...), "demo", "1.2.0", tt.goos)
			if tt.wantErr == "" {
				if err != nil || lib != tt.wantLib {
					t.Fatalf("want %s, got %q, %v", tt.wantLib, lib, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
	if _, err := CheckArchive([]byte("not a zip"), "demo", "1.2.0", "darwin"); err == nil || !strings.Contains(err.Error(), "open zip") {
		t.Fatalf("want open zip error, got %v", err)
	}
}

// rawZip stores content under name with the given method, without compressing
// it, and returns the archive.
func rawZip(t *testing.T, name string, method uint16, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.CreateRaw(&zip.FileHeader{
		Name: name, Method: method, CRC32: crc32.ChecksumIEEE(content),
		CompressedSize64: uint64(len(content)), UncompressedSize64: uint64(len(content)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCheckArchiveReadsLibrary(t *testing.T) {
	stored := rawZip(t, "demo.dylib", zip.Store, []byte("library bytes"))
	if _, err := CheckArchive(stored, "demo", "1.2.0", "darwin"); err != nil {
		t.Fatalf("want a stored library to pass, got %v", err)
	}
	corrupt := bytes.Replace(stored, []byte("library bytes"), []byte("library bytez"), 1)
	if _, err := CheckArchive(corrupt, "demo", "1.2.0", "darwin"); err == nil || !strings.Contains(err.Error(), "read demo.dylib: zip: checksum error") {
		t.Fatalf("want a checksum error, got %v", err)
	}
	unsupported := rawZip(t, "demo.dylib", 99, []byte("library bytes"))
	if _, err := CheckArchive(unsupported, "demo", "1.2.0", "darwin"); err == nil || !strings.Contains(err.Error(), "open demo.dylib: zip: unsupported compression algorithm") {
		t.Fatalf("want an unsupported compression error, got %v", err)
	}
}

func TestParseChecksums(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		wantName string
		wantErr  string
	}{
		{"plain", sha + "  a.zip\n", "a.zip", ""},
		{"binary marker", sha + " *a.zip\n", "a.zip", ""},
		{"blank lines and comments", "\n# sums\n\n" + strings.ToUpper(sha) + "  a.zip\n", "a.zip", ""},
		{"missing name", sha + "\n", "", "line 1: invalid checksum entry"},
		{"short hash", "abc  a.zip\n", "", "line 1: invalid sha256"},
		{"non-hex hash", strings.Repeat("g", 64) + "  a.zip\n", "", "invalid sha256"},
		{"malformed later line", sha + "  a.zip\nnope\n", "", "line 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sums, err := ParseChecksums([]byte(tt.data))
			if tt.wantErr == "" {
				if err != nil || sums[tt.wantName] != sha {
					t.Fatalf("want %s => %s, got %v, %v", tt.wantName, sha, sums, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestReleaseVersion(t *testing.T) {
	for tag, want := range map[string]string{"v1.2.0": "1.2.0", "V1.2.0": "1.2.0", "1.2.0": "1.2.0", "v": "", "vv1": "", "latest": ""} {
		got, err := ReleaseVersion(tag)
		if got != want || (err == nil) != (want != "") {
			t.Errorf("ReleaseVersion(%q) = %q, %v; want %q", tag, got, err, want)
		}
	}
}

// fakeGitHub serves a latest release for someone/cpa-plugin-demo whose assets
// download from a second host. Each asset body can be replaced, and a nil
// body leaves the asset out of the release.
type fakeGitHub struct {
	tag       string
	assets    map[string][]byte
	status    int // non-zero: every request answers with this status
	header    http.Header
	downloads string            // base URL of the asset host
	auth      map[string]string // Authorization header by request path
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{tag: "v1.2.0", assets: map[string][]byte{}, auth: map[string]string{}}
	var sums strings.Builder
	for _, p := range Platforms {
		name := ArchiveName("demo", "1.2.0", p)
		f.assets[name] = buildZip(t, file("demo"+LibraryExtension(p.GOOS)))
		sum := sha256.Sum256(f.assets[name])
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	f.assets["checksums.txt"] = []byte(sums.String())
	return f
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.auth[r.URL.Path] = r.Header.Get("Authorization")
	if f.status != 0 {
		for k, v := range f.header {
			w.Header()[k] = v
		}
		w.WriteHeader(f.status)
		return
	}
	if r.URL.Path == "/repos/someone/cpa-plugin-demo/releases/latest" {
		rel := release{TagName: f.tag}
		for name, body := range f.assets {
			if body != nil {
				rel.Assets = append(rel.Assets, releaseAsset{Name: name, URL: f.downloads + "/download/" + name})
			}
		}
		_ = json.NewEncoder(w).Encode(rel)
		return
	}
	body, ok := f.assets[strings.TrimPrefix(r.URL.Path, "/download/")]
	if !ok || body == nil {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(body)
}

func runReleaseCheck(t *testing.T, f *fakeGitHub, token string) (string, []error) {
	t.Helper()
	api := httptest.NewServer(f)
	defer api.Close()
	downloads := httptest.NewServer(f)
	defer downloads.Close()
	f.downloads = downloads.URL
	var out bytes.Buffer
	errs := Releases{Client: api.Client(), APIBase: api.URL, Token: token}.Check(context.Background(), &out, basePlugin())
	return out.String(), errs
}

func TestReleasesCheck(t *testing.T) {
	linuxArm := ArchiveName("demo", "1.2.0", Platform{"linux", "arm64"})
	tests := []struct {
		name    string
		mutate  func(*fakeGitHub)
		wantErr string
	}{
		{"valid release", func(*fakeGitHub) {}, ""},
		{"invalid tag", func(f *fakeGitHub) { f.tag = "nightly" }, `invalid release tag "nightly"`},
		{"missing checksums.txt", func(f *fakeGitHub) { f.assets["checksums.txt"] = nil }, "checksums.txt not found"},
		{"malformed checksums.txt", func(f *fakeGitHub) { f.assets["checksums.txt"] = []byte("oops\n") }, "invalid checksum entry"},
		{"missing platform zip", func(f *fakeGitHub) { f.assets[linuxArm] = nil }, "linux/arm64: release asset " + linuxArm + " not found"},
		{"platform zip missing from checksums", func(f *fakeGitHub) {
			f.assets["checksums.txt"] = []byte(strings.Join(strings.Split(string(f.assets["checksums.txt"]), "\n")[:3], "\n"))
		}, "checksums.txt has no entry for " + linuxArm},
		{"checksum mismatch", func(f *fakeGitHub) { f.assets[linuxArm] = buildZip(t, file("demo.so"), file("extra")) }, "checksum mismatch"},
		{"zip breaks the library rule", func(f *fakeGitHub) {
			f.assets[linuxArm] = buildZip(t, file("lib/demo.so"))
			sum := sha256.Sum256(f.assets[linuxArm])
			f.assets["checksums.txt"] = append(f.assets["checksums.txt"], []byte(hex.EncodeToString(sum[:])+"  "+linuxArm+"\n")...)
		}, "must be at the zip root"},
		{"rate limited", func(f *fakeGitHub) {
			f.status = http.StatusForbidden
			f.header = http.Header{"X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {"1790000000"}}
		}, "GitHub rate limit hit (403 Forbidden)"},
		{"too many requests", func(f *fakeGitHub) { f.status = http.StatusTooManyRequests }, "rate limit hit (429"},
		{"no release", func(f *fakeGitHub) { f.status = http.StatusNotFound }, "404 Not Found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeGitHub(t)
			tt.mutate(f)
			out, errs := runReleaseCheck(t, f, "")
			if tt.wantErr == "" && len(errs) == 0 && strings.Count(out, " ok ") != len(Platforms) {
				t.Fatalf("want an ok line per platform, got:\n%s", out)
			}
			assertErrs(t, errs, tt.wantErr)
		})
	}
}

func TestReleasesCheckSendsTokenToAPIOnly(t *testing.T) {
	f := newFakeGitHub(t)
	if _, errs := runReleaseCheck(t, f, "secret"); len(errs) > 0 {
		t.Fatal(errs)
	}
	for path, auth := range f.auth {
		want := ""
		if strings.HasPrefix(path, "/repos/") {
			want = "Bearer secret"
		}
		if auth != want {
			t.Errorf("%s: want Authorization %q, got %q", path, want, auth)
		}
	}
	if len(f.auth) != len(Platforms)+2 {
		t.Fatalf("want a request per asset and the release, got %v", f.auth)
	}
	f.status = http.StatusTooManyRequests
	_, errs := runReleaseCheck(t, f, "secret")
	assertErrs(t, errs, "rate limit")
	if strings.Contains(errs[0].Error(), "set GITHUB_TOKEN") {
		t.Fatalf("token hint shown although a token is set: %v", errs[0])
	}
}

func TestGetRetriesOnce(t *testing.T) {
	defer func(d time.Duration) { retryDelay = d }(retryDelay)
	retryDelay = time.Millisecond
	tests := []struct {
		name     string
		statuses []int // one per attempt, the last repeating; 0 drops the connection
		wantHits int
		wantErr  string
	}{
		{"5xx then ok", []int{http.StatusBadGateway, http.StatusOK}, 2, ""},
		{"network error then ok", []int{0, http.StatusOK}, 2, ""},
		{"5xx twice", []int{http.StatusServiceUnavailable}, 2, "503 Service Unavailable"},
		{"network error twice", []int{0}, 2, "EOF"},
		{"not found", []int{http.StatusNotFound}, 1, "404 Not Found"},
		{"forbidden", []int{http.StatusForbidden}, 1, "403 Forbidden"},
		{"too many requests", []int{http.StatusTooManyRequests}, 1, "rate limit hit (429"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				status := tt.statuses[min(int(hits.Add(1))-1, len(tt.statuses)-1)]
				if status == 0 {
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
					return
				}
				w.WriteHeader(status)
				fmt.Fprint(w, "body")
			}))
			defer server.Close()
			data, err := Releases{Client: server.Client(), APIBase: server.URL}.get(context.Background(), server.URL+"/x", "*/*")
			if got := int(hits.Load()); got != tt.wantHits {
				t.Errorf("want %d requests, got %d", tt.wantHits, got)
			}
			if tt.wantErr == "" {
				if err != nil || string(data) != "body" {
					t.Fatalf("want body, got %q, %v", data, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestReleasesCheckEscapesRepository(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.EscapedPath()
		http.NotFound(w, r)
	}))
	defer server.Close()
	p := basePlugin()
	p.Repository = "https://github.com/someone/a%3Fb"
	Releases{Client: server.Client(), APIBase: server.URL}.Check(context.Background(), io.Discard, p)
	if want := "/repos/someone/a%3Fb/releases/latest"; got != want {
		t.Fatalf("want path %s, got %s", want, got)
	}
}

func TestGetHidesSignedQuery(t *testing.T) {
	defer func(d time.Duration) { retryDelay = d }(retryDelay)
	retryDelay = time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/download" {
			http.Redirect(w, r, "/signed?X-Amz-Signature=secret", http.StatusFound)
			return
		}
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	defer server.Close()
	_, err := Releases{Client: server.Client(), APIBase: server.URL}.get(context.Background(), server.URL+"/download", "*/*")
	if err == nil || !strings.Contains(err.Error(), "/signed") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("want a transport error naming /signed without its query, got %v", err)
	}
}
