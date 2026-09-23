// Package registry validates a CLIProxyAPI plugin registry file. It applies
// the rules the host enforces when it loads a store source (one failure makes
// the host drop the whole file) plus stricter rules that keep this registry
// tidy.
package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
)

const (
	SchemaVersion   = 1
	SchemaVersionV2 = 2

	InstallGitHubRelease = "github-release"
	InstallDirect        = "direct"
)

var (
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	versionPattern = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]*$`)

	// licenses is the SPDX identifiers this registry accepts.
	licenses = map[string]bool{
		"MIT": true, "Apache-2.0": true, "BSD-2-Clause": true, "BSD-3-Clause": true,
		"ISC": true, "MPL-2.0": true, "GPL-3.0-only": true, "AGPL-3.0-only": true,
	}
)

// Registry is the top-level registry document. Field order is the canonical
// key order of the formatted file.
type Registry struct {
	SchemaVersion int      `json:"schema_version"`
	Plugins       []Plugin `json:"plugins"`
}

type Plugin struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	Author       string    `json:"author"`
	Version      string    `json:"version,omitempty"`
	Repository   string    `json:"repository,omitempty"`
	Homepage     string    `json:"homepage,omitempty"`
	Logo         string    `json:"logo,omitempty"`
	License      string    `json:"license,omitempty"`
	Tags         []string  `json:"tags,omitempty"`
	AuthRequired bool      `json:"auth_required,omitempty"`
	Install      *Install  `json:"install,omitempty"`
	Versions     []Version `json:"versions,omitempty"`
}

type Install struct {
	Type      string     `json:"type,omitempty"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
}

type Artifact struct {
	GOOS   string `json:"goos,omitempty"`
	GOARCH string `json:"goarch,omitempty"`
	URL    string `json:"url,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
}

type Version struct {
	Version string   `json:"version"`
	Install *Install `json:"install,omitempty"`
}

// InstallType is the lower-cased install type, defaulting to github-release.
func (p Plugin) InstallType() string {
	if p.Install == nil || strings.TrimSpace(p.Install.Type) == "" {
		return InstallGitHubRelease
	}
	return strings.ToLower(strings.TrimSpace(p.Install.Type))
}

// Format renders r exactly as the registry file must be written: two-space
// indent, &, < and > unescaped, and one final newline.
func Format(r Registry) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Check decodes data and returns the trimmed registry with every rule
// violation found. A decode failure is the only error returned in that case.
func Check(data []byte) (Registry, []error) {
	var raw Registry
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return Registry{}, []error{fmt.Errorf("decode registry: %w", err)}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Registry{}, []error{errors.New("decode registry: trailing data after the top-level object")}
	}
	var errs []error
	if want, err := Format(raw); err != nil {
		errs = append(errs, err)
	} else if !bytes.Equal(want, data) {
		errs = append(errs, fmt.Errorf("file is not canonically formatted; expected:\n%s", want))
	}
	r := normalize(raw)
	return r, append(errs, validate(r)...)
}

func validate(r Registry) []error {
	var errs []error
	if r.SchemaVersion != SchemaVersion && r.SchemaVersion != SchemaVersionV2 {
		errs = append(errs, fmt.Errorf("unsupported schema_version %d", r.SchemaVersion))
	}
	// Ids are compared case-insensitively: they name library files, which
	// collide on case-insensitive filesystems.
	seen := map[string]string{}
	for i, p := range r.Plugins {
		for _, err := range validatePlugin(p, r.SchemaVersion) {
			errs = append(errs, fmt.Errorf("%s: %w", Label(i, p.ID), err))
		}
		if p.ID == "" {
			continue
		}
		key := strings.ToLower(p.ID)
		if first, ok := seen[key]; ok {
			errs = append(errs, fmt.Errorf("%s: duplicate plugin id; %q is already listed", Label(i, p.ID), first))
		} else {
			seen[key] = p.ID
		}
		if i > 0 && p.ID < r.Plugins[i-1].ID {
			errs = append(errs, fmt.Errorf("%s: entries must be sorted by id; %q sorts before %q", Label(i, p.ID), p.ID, r.Plugins[i-1].ID))
		}
	}
	return errs
}

// Label names a registry entry in messages.
func Label(index int, id string) string {
	if id == "" {
		return fmt.Sprintf("plugins[%d]", index)
	}
	return fmt.Sprintf("plugins[%d] (%s)", index, id)
}

func validatePlugin(p Plugin, schema int) []error {
	var errs []error
	installType := p.InstallType()
	if schema == SchemaVersion && installType == InstallDirect {
		errs = append(errs, fmt.Errorf("direct install requires schema_version %d", SchemaVersionV2))
	}
	required := [][2]string{{"id", p.ID}, {"name", p.Name}, {"description", p.Description}, {"author", p.Author}}
	if installType == InstallGitHubRelease {
		required = append(required, [2]string{"repository", p.Repository})
	}
	for _, field := range required {
		if field[1] == "" {
			errs = append(errs, fmt.Errorf("missing required field %s", field[0]))
		}
	}
	if p.ID != "" && !idPattern.MatchString(p.ID) {
		errs = append(errs, fmt.Errorf("invalid plugin id %q", p.ID))
	}
	if p.Version != "" && !ValidVersion(p.Version) {
		errs = append(errs, fmt.Errorf("invalid plugin version %q", p.Version))
	}

	switch installType {
	case InstallGitHubRelease:
		if p.Repository != "" {
			if _, _, err := RepositoryParts(p.Repository); err != nil {
				errs = append(errs, err)
			} else if strings.HasSuffix(p.Repository, "/") {
				errs = append(errs, errors.New("repository must not end with /"))
			}
		}
		if len(p.Versions) > 0 {
			errs = append(errs, errors.New("versions is only valid for direct installs"))
		}
	case InstallDirect:
		if p.Version == "" {
			errs = append(errs, errors.New("missing required field version"))
		}
		errs = append(errs, validateInstall(p.Install, "install")...)
		errs = append(errs, validateVersions(p.Versions)...)
	default:
		errs = append(errs, fmt.Errorf("unsupported install type %q", p.Install.Type))
	}

	for _, field := range [][2]string{{"homepage", p.Homepage}, {"logo", p.Logo}} {
		if u, err := url.Parse(field[1]); field[1] != "" && (err != nil || u.Scheme != "https" || u.Host == "") {
			errs = append(errs, fmt.Errorf("%s must be an https URL", field[0]))
		}
	}
	if p.License != "" && !licenses[p.License] {
		errs = append(errs, fmt.Errorf("license %q is not in the accepted SPDX list", p.License))
	}
	tags := map[string]bool{}
	for i, tag := range p.Tags {
		if tag == "" {
			errs = append(errs, fmt.Errorf("tags[%d] is empty", i))
		} else if tags[tag] {
			errs = append(errs, fmt.Errorf("duplicate tag %q", tag))
		}
		tags[tag] = true
	}
	return errs
}

func validateVersions(versions []Version) []error {
	var errs []error
	seen := map[string]bool{}
	for i, v := range versions {
		prefix := fmt.Sprintf("versions[%d]", i)
		if !ValidVersion(v.Version) {
			errs = append(errs, fmt.Errorf("%s: invalid plugin version %q", prefix, v.Version))
		}
		if seen[v.Version] {
			errs = append(errs, fmt.Errorf("%s: duplicate plugin version %q", prefix, v.Version))
		}
		seen[v.Version] = true
		install := Install{Type: InstallDirect}
		if v.Install != nil {
			install = *v.Install
		}
		if install.Type == "" {
			install.Type = InstallDirect
		}
		if install.Type != InstallDirect {
			errs = append(errs, fmt.Errorf("%s: install type %q does not match plugin install type %q", prefix, install.Type, InstallDirect))
			continue
		}
		errs = append(errs, validateInstall(&install, prefix+".install")...)
	}
	return errs
}

func validateInstall(install *Install, prefix string) []error {
	if install == nil || len(install.Artifacts) == 0 {
		return []error{fmt.Errorf("%s: direct install requires at least one artifact", prefix)}
	}
	var errs []error
	for i, a := range install.Artifacts {
		if err := validateArtifact(a); err != nil {
			errs = append(errs, fmt.Errorf("%s.artifacts[%d]: %w", prefix, i, err))
		}
	}
	return errs
}

func validateArtifact(a Artifact) error {
	switch {
	case a.GOOS == "":
		return errors.New("missing goos")
	case a.GOARCH == "":
		return errors.New("missing goarch")
	case a.URL == "":
		return errors.New("missing url")
	}
	u, err := url.Parse(a.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("invalid artifact url")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("artifact url must use http or https")
	}
	if u.User != nil {
		return errors.New("artifact url must not contain credentials")
	}
	if strings.ContainsAny(a.URL, "?#") {
		return errors.New("artifact url must not contain a query or fragment")
	}
	if _, err := hex.DecodeString(a.SHA256); err != nil || len(a.SHA256) != sha256.Size*2 {
		return errors.New("sha256 must be 64 hex characters")
	}
	if a.Size < 0 {
		return errors.New("invalid size")
	}
	return nil
}

// ValidVersion reports whether v is a plugin version the host accepts.
func ValidVersion(v string) bool {
	return !strings.HasPrefix(v, "v") && versionPattern.MatchString(v)
}

// trimV drops surrounding space and one leading v or V, as the host does for
// release tags and pinned versions.
func trimV(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') {
		return v[1:]
	}
	return v
}

// RepositoryParts splits a https://github.com/{owner}/{repo} URL the way the
// host does before it queries the GitHub releases API.
func RepositoryParts(repository string) (owner, repo string, err error) {
	errShape := errors.New("repository must be https://github.com/{owner}/{repo}")
	u, err := url.Parse(repository)
	if err != nil {
		return "", "", fmt.Errorf("invalid repository URL: %w", err)
	}
	if u.Scheme != "https" || u.Host != "github.com" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", errShape
	}
	segments := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(segments) != 2 || segments[0] == "" || segments[1] == "" {
		return "", "", errShape
	}
	if owner, err = url.PathUnescape(segments[0]); err != nil {
		return "", "", fmt.Errorf("invalid repository owner: %w", err)
	}
	if repo, err = url.PathUnescape(segments[1]); err != nil {
		return "", "", fmt.Errorf("invalid repository name: %w", err)
	}
	if strings.HasSuffix(repo, ".git") {
		return "", "", errShape
	}
	return owner, repo, nil
}

// normalize returns a copy of r with values trimmed and normalized the way
// the host does before validating.
func normalize(r Registry) Registry {
	out := Registry{SchemaVersion: r.SchemaVersion, Plugins: make([]Plugin, len(r.Plugins))}
	for i, p := range r.Plugins {
		for _, s := range []*string{&p.ID, &p.Name, &p.Description, &p.Author, &p.Version, &p.Repository, &p.Logo, &p.Homepage, &p.License} {
			*s = strings.TrimSpace(*s)
		}
		p.Tags = append([]string(nil), p.Tags...)
		for j := range p.Tags {
			p.Tags[j] = strings.TrimSpace(p.Tags[j])
		}
		p.Install = normalizeInstall(p.Install)
		p.Versions = append([]Version(nil), p.Versions...)
		for j := range p.Versions {
			p.Versions[j].Version = trimV(p.Versions[j].Version)
			p.Versions[j].Install = normalizeInstall(p.Versions[j].Install)
		}
		out.Plugins[i] = p
	}
	return out
}

func normalizeInstall(in *Install) *Install {
	if in == nil {
		return nil
	}
	out := Install{Type: strings.ToLower(strings.TrimSpace(in.Type)), Artifacts: append([]Artifact(nil), in.Artifacts...)}
	for i := range out.Artifacts {
		a := &out.Artifacts[i]
		a.GOOS = strings.ToLower(strings.TrimSpace(a.GOOS))
		if a.GOOS == "mac" || a.GOOS == "macos" || a.GOOS == "osx" {
			a.GOOS = "darwin"
		}
		a.GOARCH = strings.ToLower(strings.TrimSpace(a.GOARCH))
		switch a.GOARCH {
		case "x64", "x86_64":
			a.GOARCH = "amd64"
		case "aarch64":
			a.GOARCH = "arm64"
		}
		a.URL = strings.TrimSpace(a.URL)
		a.SHA256 = strings.ToLower(strings.TrimSpace(a.SHA256))
	}
	return &out
}
