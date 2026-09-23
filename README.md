# cpa-plugin-registry

A [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) plugin registry
that lists Yuya Iwabuchi's CPA plugins.

## Adding the registry

In the Management Center, open Config → Third-party Plugin Sources and add:

```
https://raw.githubusercontent.com/yuya-iwabuchi/cpa-plugin-registry/main/registry.json
```

Or add it to the host config:

```yaml
plugins:
  store-sources:
    - https://raw.githubusercontent.com/yuya-iwabuchi/cpa-plugin-registry/main/registry.json
```

Then install plugins from the Plugin Store, where this source shows as
`raw.githubusercontent.com`. Each plugin's README names the oldest host version
it supports.

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
