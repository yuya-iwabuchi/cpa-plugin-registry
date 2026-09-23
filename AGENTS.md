# AGENTS.md

This repository is a CLIProxyAPI (CPA) plugin store source: `registry.json`
lists the author's plugins, and `cmd/validate` checks it against the host's
registry and install contract.

## Invariants

- Keep `registry.json` at the repository root on `main`. The host derives each
  source's id from its URL, so moving or renaming the file breaks every
  install that uses it.
- Run `go run ./cmd/validate registry.json` before committing a change to
  `registry.json`. The host rejects the whole file when any entry is invalid,
  which hides every plugin, not just the broken one.
- Keep entries sorted by `id` and formatted exactly as the validator prints on
  failure.
- Set `id` to the plugin's library id, the same key the host config uses for
  the plugin.
- Leave out `version`. For a github-release entry the host always installs the
  latest GitHub release; `version` only labels the entry in the store, and it
  goes stale with every release.

## Adding or updating an entry

1. Confirm the plugin's latest GitHub release has `checksums.txt` and
   `<id>_<version>_<goos>_<goarch>.zip` for darwin/arm64, darwin/amd64,
   linux/amd64, linux/arm64, and windows/amd64. Each zip holds exactly one
   library, at its root, named `<id><ext>` or `<id>-v<version><ext>`, where
   `<ext>` is `.dylib`, `.so`, or `.dll` for the zip's OS. The host rejects a
   zip with any symlink or other non-regular entry, or any backslash,
   absolute or `../` path.
2. Edit `registry.json`, then run `go run ./cmd/validate registry.json`.
3. Run `GITHUB_TOKEN=$(gh auth token) go run ./cmd/validate -live registry.json`
   to download and check every platform's release asset.
4. Add the plugin to the table in `README.md`.

## Commands

```sh
go test ./...
go vet ./...
gofmt -l .
go run ./cmd/validate registry.json
GITHUB_TOKEN=$(gh auth token) go run ./cmd/validate -live registry.json
```

## Commits

Write commit messages as `Type(N/A): <plain sentence>`, for example
`Feature(N/A): List the example plugin.` or `Docs(N/A): Explain the trust model.`
