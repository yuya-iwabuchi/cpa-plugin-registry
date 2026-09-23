# cpa-plugin-registry

A [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) plugin registry
that lists Yuya Iwabuchi's CPA plugins.

## Adding the registry

In the Management Center, open Config Panel → Advanced → Third-party Plugin
Sources, add this URL, and save:

```
https://raw.githubusercontent.com/yuya-iwabuchi/cpa-plugin-registry/main/registry.json
```

Or set it in the host config, with the plugin system switched on (it is off
by default):

```yaml
plugins:
  enabled: true
  store-sources:
    - https://raw.githubusercontent.com/yuya-iwabuchi/cpa-plugin-registry/main/registry.json
```

Then install from the Plugin Store, where this source shows as
`raw.githubusercontent.com`. Each plugin's README names the oldest host version
it supports.

An install records the version under `store:` in the plugin's config block,
and the host loads only that version; at its next start it deletes the
plugin's other library files, including a copy installed by hand. Updates are
never automatic: the Plugin Store marks one as available and you click Update.
It caches each plugin's latest release for up to an hour, so a new release can
take that long to show.

## Plugins

| Plugin | Description | Minimum host |
| --- | --- | --- |
| [Claude Seat Pacer](https://github.com/yuya-iwabuchi/cpa-plugin-claude-seat-pacer) | Uses up each Claude seat's weekly quota before it resets, and keeps every conversation on one seat so its prompt cache keeps working. | 7.2.145 |

## Trust

A plugin is a native library that runs inside the host process with all of the
host's access. Every release is checksummed and carries a build-provenance
attestation you can verify; see each plugin's security notes, for example
[Claude Seat Pacer's SECURITY.md](https://github.com/yuya-iwabuchi/cpa-plugin-claude-seat-pacer/blob/main/SECURITY.md).
The host installs and updates plugins from each plugin's GitHub releases; this
repository only tells it where to look.

## Contributing

This registry lists only the author's own plugins. Report bugs in the
repository of the plugin concerned.

## Licence

[MIT](LICENSE)
