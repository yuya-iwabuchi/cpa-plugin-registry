package registry

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// maxDownload bounds each downloaded release asset.
const maxDownload = 256 << 20

// retryDelay is the pause before the one retry of a request that fails with
// a network error or a 5xx status.
var retryDelay = 2 * time.Second

type Platform struct{ GOOS, GOARCH string }

func (p Platform) String() string { return p.GOOS + "/" + p.GOARCH }

// Platforms is every platform a listed plugin's release must ship.
var Platforms = []Platform{
	{"darwin", "arm64"}, {"darwin", "amd64"},
	{"linux", "amd64"}, {"linux", "arm64"},
	{"windows", "amd64"},
}

// ArchiveName is the release asset the host downloads for a platform.
func ArchiveName(id, version string, p Platform) string {
	return fmt.Sprintf("%s_%s_%s_%s.zip", id, version, p.GOOS, p.GOARCH)
}

// LibraryExtension is the dynamic library extension the host loads on goos.
func LibraryExtension(goos string) string {
	switch goos {
	case "darwin":
		return ".dylib"
	case "windows":
		return ".dll"
	default:
		return ".so"
	}
}

// ReleaseVersion is the plugin version the host derives from a release tag.
func ReleaseVersion(tag string) (string, error) {
	version := trimV(tag)
	if !ValidVersion(version) {
		return "", fmt.Errorf("invalid release tag %q", tag)
	}
	return version, nil
}

// ParseChecksums reads a sha256sum-format file the way the host does: blank
// lines and # comments are skipped, a leading * on the name is dropped, and
// any other malformed line fails the whole file.
func ParseChecksums(data []byte) (map[string]string, error) {
	out := map[string]string{}
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("checksums.txt line %d: invalid checksum entry", n+1)
		}
		hash := strings.ToLower(fields[0])
		if _, err := hex.DecodeString(hash); err != nil || len(hash) != sha256.Size*2 {
			return nil, fmt.Errorf("checksums.txt line %d: invalid sha256", n+1)
		}
		out[strings.TrimPrefix(fields[1], "*")] = hash
	}
	return out, nil
}

// CheckArchive applies the host's zip rules and returns the name of the one
// dynamic library it would install for goos.
func CheckArchive(data []byte, id, version, goos string) (string, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("open zip: %w", err)
	}
	ext := LibraryExtension(goos)
	names := []string{id + ext, id + "-v" + version + ext}
	found := ""
	var target *zip.File
	for _, file := range reader.File {
		name, err := cleanZipName(file.Name)
		if err != nil {
			return "", err
		}
		mode := file.FileInfo().Mode()
		if mode.IsDir() {
			continue
		}
		if !mode.IsRegular() {
			return "", fmt.Errorf("zip entry %s is not a regular file", file.Name)
		}
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".dylib") && !strings.HasSuffix(lower, ".so") && !strings.HasSuffix(lower, ".dll") {
			continue
		}
		if name != names[0] && name != names[1] {
			if base := path.Base(name); base == names[0] || base == names[1] {
				return "", fmt.Errorf("library %s must be at the zip root", name)
			}
			return "", fmt.Errorf("library %s must be named %s or %s", name, names[0], names[1])
		}
		if found != "" {
			return "", fmt.Errorf("zip contains both %s and %s", found, name)
		}
		found, target = name, file
	}
	if found == "" {
		return "", fmt.Errorf("zip does not contain %s", names[0])
	}
	// Reading the whole entry runs its decompressor and CRC check, as the
	// host's install does.
	rc, err := target.Open()
	if err != nil {
		return "", fmt.Errorf("open %s: %w", found, err)
	}
	defer rc.Close()
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return "", fmt.Errorf("read %s: %w", found, err)
	}
	return found, nil
}

func cleanZipName(name string) (string, error) {
	switch {
	case strings.TrimSpace(name) == "":
		return "", errors.New("zip entry has empty name")
	case strings.Contains(name, `\`):
		return "", fmt.Errorf("zip entry %s uses backslash path separators", name)
	case path.IsAbs(name):
		return "", fmt.Errorf("zip entry %s is absolute", name)
	}
	cleaned := path.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("zip entry %s escapes the archive root", name)
	}
	return cleaned, nil
}

// Releases checks plugins' latest GitHub releases against the host's install
// contract.
type Releases struct {
	Client  *http.Client
	APIBase string // e.g. https://api.github.com
	Token   string // optional bearer token
}

type release struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// Check verifies p's latest release, writing one line per platform to w, and
// returns every failure found.
func (c Releases) Check(ctx context.Context, w io.Writer, p Plugin) []error {
	owner, repo, err := RepositoryParts(p.Repository)
	if err != nil {
		return []error{err}
	}
	latest := fmt.Sprintf("%s/repos/%s/%s/releases/latest", strings.TrimSuffix(c.APIBase, "/"), url.PathEscape(owner), url.PathEscape(repo))
	body, err := c.get(ctx, latest, "application/vnd.github+json")
	if err != nil {
		return []error{fmt.Errorf("latest release: %w", err)}
	}
	var rel release
	if err := json.Unmarshal(body, &rel); err != nil {
		return []error{fmt.Errorf("decode latest release: %w", err)}
	}
	version, err := ReleaseVersion(rel.TagName)
	if err != nil {
		return []error{err}
	}
	assets := map[string]string{}
	for _, a := range rel.Assets {
		assets[strings.TrimSpace(a.Name)] = a.URL
	}
	fmt.Fprintf(w, "%s: release %s (version %s)\n", p.ID, rel.TagName, version)

	checksums, err := c.checksums(ctx, assets["checksums.txt"])
	if err != nil {
		fmt.Fprintf(w, "  checksums.txt  FAIL  %v\n", err)
		return []error{err}
	}
	var errs []error
	for _, platform := range Platforms {
		lib, err := c.checkPlatform(ctx, assets, checksums, p.ID, version, platform)
		if err != nil {
			fmt.Fprintf(w, "  %-14s FAIL  %v\n", platform, err)
			errs = append(errs, fmt.Errorf("%s: %w", platform, err))
			continue
		}
		fmt.Fprintf(w, "  %-14s ok    %s (sha256 verified, contains %s)\n", platform, ArchiveName(p.ID, version, platform), lib)
	}
	return errs
}

func (c Releases) checksums(ctx context.Context, assetURL string) (map[string]string, error) {
	if assetURL == "" {
		return nil, errors.New("release asset checksums.txt not found")
	}
	data, err := c.get(ctx, assetURL, "application/octet-stream")
	if err != nil {
		return nil, fmt.Errorf("download checksums.txt: %w", err)
	}
	return ParseChecksums(data)
}

func (c Releases) checkPlatform(ctx context.Context, assets, checksums map[string]string, id, version string, p Platform) (string, error) {
	name := ArchiveName(id, version, p)
	assetURL, ok := assets[name]
	if !ok {
		return "", fmt.Errorf("release asset %s not found", name)
	}
	want, ok := checksums[name]
	if !ok {
		return "", fmt.Errorf("checksums.txt has no entry for %s", name)
	}
	data, err := c.get(ctx, assetURL, "application/octet-stream")
	if err != nil {
		return "", fmt.Errorf("download %s: %w", name, err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != want {
		return "", fmt.Errorf("checksum mismatch for %s", name)
	}
	return CheckArchive(data, id, version, p.GOOS)
}

// transientError marks a failure that one retry may clear.
type transientError struct{ error }

func (e transientError) Unwrap() error { return e.error }

// get fetches rawURL, retrying once within ctx after a transient failure.
func (c Releases) get(ctx context.Context, rawURL, accept string) ([]byte, error) {
	data, err := c.getOnce(ctx, rawURL, accept)
	if !errors.As(err, new(transientError)) || ctx.Err() != nil {
		return data, err
	}
	select {
	case <-ctx.Done():
		return nil, err
	case <-time.After(retryDelay):
	}
	return c.getOnce(ctx, rawURL, accept)
}

func (c Releases) getOnce(ctx context.Context, rawURL, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	// Only requests to the API host carry the token, and net/http drops it on
	// a redirect to another host.
	if api, err := url.Parse(c.APIBase); err == nil && c.Token != "" && req.URL.Host == api.Host {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		// A redirected download URL carries its signature in the query.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			uerr.URL, _, _ = strings.Cut(uerr.URL, "?")
		}
		return nil, transientError{err}
	}
	defer resp.Body.Close()
	rateLimited := resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode == http.StatusForbidden && (resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != "")
	if rateLimited {
		msg := fmt.Sprintf("GitHub rate limit hit (%s) for %s", resp.Status, rawURL)
		if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
			if unix, err := strconv.ParseInt(reset, 10, 64); err == nil {
				msg += "; resets at " + time.Unix(unix, 0).UTC().Format(time.RFC3339)
			}
		}
		if c.Token == "" {
			msg += "; set GITHUB_TOKEN to raise the limit"
		}
		return nil, errors.New(msg)
	}
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("GET %s: %s", rawURL, resp.Status)
		if resp.StatusCode >= 500 {
			return nil, transientError{err}
		}
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, transientError{err}
	}
	if len(data) > maxDownload {
		return nil, fmt.Errorf("GET %s: response exceeds %d bytes", rawURL, maxDownload)
	}
	return data, nil
}
