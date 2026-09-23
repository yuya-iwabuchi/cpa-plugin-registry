package registry

import (
	"os"
	"strings"
	"testing"
)

const sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func basePlugin() Plugin {
	return Plugin{
		ID:          "demo",
		Name:        "Demo",
		Description: "A demo plugin.",
		Author:      "someone",
		Repository:  "https://github.com/someone/cpa-plugin-demo",
		Homepage:    "https://github.com/someone/cpa-plugin-demo",
		License:     "MIT",
		Tags:        []string{"Demo"},
	}
}

func directPlugin() Plugin {
	p := basePlugin()
	p.Repository = ""
	p.Version = "1.0.0"
	p.Install = &Install{Type: "direct", Artifacts: []Artifact{{GOOS: "linux", GOARCH: "amd64", URL: "https://example.com/demo.zip", SHA256: sha, Size: 10}}}
	return p
}

// checkRegistry formats r canonically and checks it, so only the rule under
// test can fail.
func checkRegistry(t *testing.T, r Registry) []error {
	t.Helper()
	data, err := Format(r)
	if err != nil {
		t.Fatal(err)
	}
	_, errs := Check(data)
	return errs
}

func TestPluginRules(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Plugin)
		wantErr string // empty: valid
	}{
		{"valid github-release", func(*Plugin) {}, ""},
		{"surrounding space is trimmed", func(p *Plugin) { p.Name = " Demo " }, ""},
		{"missing id", func(p *Plugin) { p.ID = " " }, "missing required field id"},
		{"missing name", func(p *Plugin) { p.Name = "" }, "missing required field name"},
		{"missing description", func(p *Plugin) { p.Description = "" }, "missing required field description"},
		{"missing author", func(p *Plugin) { p.Author = "" }, "missing required field author"},
		{"missing repository", func(p *Plugin) { p.Repository = "" }, "missing required field repository"},
		{"id with dots and dashes", func(p *Plugin) { p.ID = "a.b_c-d" }, ""},
		{"id starting with dash", func(p *Plugin) { p.ID = "-demo" }, "invalid plugin id"},
		{"id with slash", func(p *Plugin) { p.ID = "a/b" }, "invalid plugin id"},
		{"id of 128 chars", func(p *Plugin) { p.ID = strings.Repeat("a", 128) }, ""},
		{"id of 129 chars", func(p *Plugin) { p.ID = strings.Repeat("a", 129) }, "invalid plugin id"},
		{"version", func(p *Plugin) { p.Version = "1.2.3-rc.1+build" }, ""},
		{"version with v", func(p *Plugin) { p.Version = "v1.2.3" }, "invalid plugin version"},
		{"version not starting with digit", func(p *Plugin) { p.Version = "latest" }, "invalid plugin version"},
		{"repository http", func(p *Plugin) { p.Repository = "http://github.com/a/b" }, "repository must be"},
		{"repository other host", func(p *Plugin) { p.Repository = "https://gitlab.com/a/b" }, "repository must be"},
		{"repository host case", func(p *Plugin) { p.Repository = "https://GitHub.com/a/b" }, "repository must be"},
		{"repository query", func(p *Plugin) { p.Repository = "https://github.com/a/b?x=1" }, "repository must be"},
		{"repository fragment", func(p *Plugin) { p.Repository = "https://github.com/a/b#readme" }, "repository must be"},
		{"repository one segment", func(p *Plugin) { p.Repository = "https://github.com/a" }, "repository must be"},
		{"repository three segments", func(p *Plugin) { p.Repository = "https://github.com/a/b/c" }, "repository must be"},
		{"repository empty segment", func(p *Plugin) { p.Repository = "https://github.com/a//b" }, "repository must be"},
		{"repository .git", func(p *Plugin) { p.Repository = "https://github.com/a/b.git" }, "repository must be"},
		{"repository trailing slash", func(p *Plugin) { p.Repository = "https://github.com/a/b/" }, "must not end with /"},
		{"explicit github-release type", func(p *Plugin) { p.Install = &Install{Type: "GitHub-Release"} }, ""},
		{"unknown install type", func(p *Plugin) { p.Install = &Install{Type: "npm"} }, `unsupported install type "npm"`},
		{"direct in schema 1", func(p *Plugin) { *p = directPlugin() }, "direct install requires schema_version 2"},
		{"versions on github-release", func(p *Plugin) { p.Versions = []Version{{Version: "1.0.0"}} }, "versions is only valid for direct installs"},
		{"homepage http", func(p *Plugin) { p.Homepage = "http://example.com" }, "homepage must be an https URL"},
		{"logo https", func(p *Plugin) { p.Logo = "https://example.com/logo.png" }, ""},
		{"logo relative", func(p *Plugin) { p.Logo = "logo.png" }, "logo must be an https URL"},
		{"license unknown", func(p *Plugin) { p.License = "WTFPL" }, "not in the accepted SPDX list"},
		{"license apache", func(p *Plugin) { p.License = "Apache-2.0" }, ""},
		{"empty tag", func(p *Plugin) { p.Tags = []string{"A", " "} }, "tags[1] is empty"},
		{"duplicate tag", func(p *Plugin) { p.Tags = []string{"A", "A"} }, `duplicate tag "A"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := basePlugin()
			tt.mutate(&p)
			assertErrs(t, checkRegistry(t, Registry{SchemaVersion: 1, Plugins: []Plugin{p}}), tt.wantErr)
		})
	}
}

func TestDirectRules(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Plugin)
		wantErr string
	}{
		{"valid direct", func(*Plugin) {}, ""},
		{"direct type is case-insensitive", func(p *Plugin) { p.Install.Type = "Direct" }, ""},
		{"no repository needed", func(p *Plugin) { p.Repository = "" }, ""},
		{"missing version", func(p *Plugin) { p.Version = "" }, "missing required field version"},
		{"no artifacts", func(p *Plugin) { p.Install.Artifacts = nil }, "at least one artifact"},
		{"missing goos", func(p *Plugin) { p.Install.Artifacts[0].GOOS = "" }, "missing goos"},
		{"goos alias", func(p *Plugin) { p.Install.Artifacts[0].GOOS = "macOS" }, ""},
		{"missing goarch", func(p *Plugin) { p.Install.Artifacts[0].GOARCH = "" }, "missing goarch"},
		{"missing url", func(p *Plugin) { p.Install.Artifacts[0].URL = "" }, "missing url"},
		{"url without host", func(p *Plugin) { p.Install.Artifacts[0].URL = "https:///x.zip" }, "invalid artifact url"},
		{"url ftp", func(p *Plugin) { p.Install.Artifacts[0].URL = "ftp://example.com/x.zip" }, "must use http or https"},
		{"url http", func(p *Plugin) { p.Install.Artifacts[0].URL = "http://example.com/x.zip" }, ""},
		{"url with credentials", func(p *Plugin) { p.Install.Artifacts[0].URL = "https://user:pass@example.com/x.zip" }, "must not contain credentials"},
		{"url with query", func(p *Plugin) { p.Install.Artifacts[0].URL = "https://example.com/x.zip?download=1" }, "must not contain a query or fragment"},
		{"url with empty query", func(p *Plugin) { p.Install.Artifacts[0].URL = "https://example.com/x.zip?" }, "must not contain a query or fragment"},
		{"url with fragment", func(p *Plugin) { p.Install.Artifacts[0].URL = "https://example.com/x.zip#top" }, "must not contain a query or fragment"},
		{"url with empty fragment", func(p *Plugin) { p.Install.Artifacts[0].URL = "https://example.com/x.zip#" }, "must not contain a query or fragment"},
		{"url with escaped query mark", func(p *Plugin) { p.Install.Artifacts[0].URL = "https://example.com/x%3F.zip" }, ""},
		{"short sha256", func(p *Plugin) { p.Install.Artifacts[0].SHA256 = "abc" }, "sha256 must be 64 hex"},
		{"non-hex sha256", func(p *Plugin) { p.Install.Artifacts[0].SHA256 = strings.Repeat("z", 64) }, "sha256 must be 64 hex"},
		{"upper-case sha256", func(p *Plugin) { p.Install.Artifacts[0].SHA256 = strings.ToUpper(sha) }, ""},
		{"negative size", func(p *Plugin) { p.Install.Artifacts[0].Size = -1 }, "invalid size"},
		{"pinned version", func(p *Plugin) {
			p.Versions = []Version{{Version: "v0.9.0", Install: &Install{Artifacts: p.Install.Artifacts}}}
		}, ""},
		{"pinned version invalid", func(p *Plugin) {
			p.Versions = []Version{{Version: "x", Install: &Install{Artifacts: p.Install.Artifacts}}}
		}, "invalid plugin version"},
		{"pinned version duplicate", func(p *Plugin) {
			v := Version{Version: "0.9.0", Install: &Install{Artifacts: p.Install.Artifacts}}
			p.Versions = []Version{v, v}
		}, "duplicate plugin version"},
		{"pinned version type mismatch", func(p *Plugin) {
			p.Versions = []Version{{Version: "0.9.0", Install: &Install{Type: "github-release"}}}
		}, "does not match plugin install type"},
		{"pinned version without artifacts", func(p *Plugin) { p.Versions = []Version{{Version: "0.9.0"}} }, "at least one artifact"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := directPlugin()
			tt.mutate(&p)
			assertErrs(t, checkRegistry(t, Registry{SchemaVersion: 2, Plugins: []Plugin{p}}), tt.wantErr)
		})
	}
}

func TestRegistryRules(t *testing.T) {
	named := func(id string) Plugin { p := basePlugin(); p.ID = id; return p }
	tests := []struct {
		name    string
		reg     Registry
		wantErr string
	}{
		{"schema 2", Registry{SchemaVersion: 2, Plugins: []Plugin{basePlugin()}}, ""},
		{"schema 0", Registry{Plugins: []Plugin{basePlugin()}}, "unsupported schema_version 0"},
		{"schema 3", Registry{SchemaVersion: 3, Plugins: []Plugin{basePlugin()}}, "unsupported schema_version 3"},
		{"sorted", Registry{SchemaVersion: 1, Plugins: []Plugin{named("a"), named("b")}}, ""},
		{"unsorted", Registry{SchemaVersion: 1, Plugins: []Plugin{named("b"), named("a")}}, `plugins[1] (a): entries must be sorted by id`},
		{"duplicate after trim", Registry{SchemaVersion: 1, Plugins: []Plugin{named("a"), named(" a")}}, "plugins[1] (a): duplicate plugin id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertErrs(t, checkRegistry(t, tt.reg), tt.wantErr)
		})
	}
}

func TestDecodeAndFormat(t *testing.T) {
	valid, err := Format(Registry{SchemaVersion: 1, Plugins: []Plugin{basePlugin()}})
	if err != nil {
		t.Fatal(err)
	}
	replace := func(old, new string) string { return strings.Replace(string(valid), old, new, 1) }
	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{"canonical", string(valid), ""},
		{"unknown top-level key", replace(`"plugins"`, `"extra": 1, "plugins"`), `unknown field "extra"`},
		{"unknown entry key", replace(`"id"`, `"stars": 5, "id"`), `unknown field "stars"`},
		{"schema_version as string", replace(`"schema_version": 1`, `"schema_version": "1"`), "decode registry"},
		{"schema_version as float", replace(`"schema_version": 1`, `"schema_version": 1.5`), "decode registry"},
		{"tags as string", replace("[\n        \"Demo\"\n      ]", `"Demo"`), "decode registry"},
		{"auth_required as string", replace(`"license"`, `"auth_required": "yes", "license"`), "decode registry"},
		{"trailing data", string(valid) + "{}", "trailing data"},
		{"extra final newline", string(valid) + "\n", "not canonically formatted"},
		{"missing final newline", strings.TrimSuffix(string(valid), "\n"), "not canonically formatted"},
		{"tab indent", strings.ReplaceAll(string(valid), "  ", "\t"), "not canonically formatted"},
		{"key order", replace(`"id": "demo",`+"\n      "+`"name": "Demo",`, `"name": "Demo",`+"\n      "+`"id": "demo",`), "not canonically formatted"},
		{"ampersand is written as is", replace("A demo plugin.", "a & b"), ""},
		{"escaped ampersand", replace("A demo plugin.", `a \u0026 b`), "not canonically formatted"},
		{"explicit false auth_required", replace(`"license"`, `"auth_required": false,`+"\n      "+`"license"`), "not canonically formatted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errs := Check([]byte(tt.data))
			assertErrs(t, errs, tt.wantErr)
		})
	}
}

func TestFormatErrorShowsExpected(t *testing.T) {
	valid, _ := Format(Registry{SchemaVersion: 1, Plugins: []Plugin{basePlugin()}})
	_, errs := Check([]byte(strings.ReplaceAll(string(valid), "  ", "    ")))
	if len(errs) != 1 || !strings.HasSuffix(errs[0].Error(), string(valid)) {
		t.Fatalf("want one error ending with the canonical file, got %v", errs)
	}
}

func TestRegistryFile(t *testing.T) {
	data, err := os.ReadFile("../../registry.json")
	if err != nil {
		t.Fatal(err)
	}
	_, errs := Check(data)
	assertErrs(t, errs, "")
}

func assertErrs(t *testing.T, errs []error, want string) {
	t.Helper()
	if want == "" {
		if len(errs) > 0 {
			t.Fatalf("want no errors, got %v", errs)
		}
		return
	}
	for _, err := range errs {
		if strings.Contains(err.Error(), want) {
			return
		}
	}
	t.Fatalf("want an error containing %q, got %v", want, errs)
}
