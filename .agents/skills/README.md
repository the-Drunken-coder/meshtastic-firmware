# Matt Pocock skills (vendored)

These 33 `matt-*` skills are copied from [the-Drunken-coder/mattpocock-skills-community](https://github.com/the-Drunken-coder/mattpocock-skills-community) at commit `bcc9c7029d3d90013cbe9007adb4ad5053b018ba` (package version `0.3.0+upstream.24fe0ef7`). They include Matt Pocock's [v1.3.1](https://github.com/mattpocock/skills/releases/tag/v1.3.1) at upstream commit `24fe0ef7737efae15c87225755e9f6f5965e4888`, plus in-progress skills. They are MIT-licensed; see [LICENSE.mattpocock-skills](LICENSE.mattpocock-skills).

The community package preserves the `matt-` namespace, normalizes Claude's `disable-model-invocation: true` to `false` for Codex, and adds `kind:spec`, `kind:ticket`, and `kind:map` to new tracker artifacts. Skill contents match that package; project configuration and authorization come from the [workspace instructions](../../../AGENTS.md), [issue tracker](../../../docs/agents/issue-tracker.md), [triage labels](../../../docs/agents/triage-labels.md), and [domain conventions](../../../docs/agents/domain.md).

Codex discovers repository skills in `.agents/skills/`, so they are available in this checkout without installing the Codex plugin. If the `mattpocock-skills-community` plugin is also installed, the skills are identical; prefer one source.

To refresh, verify the community package's upstream commit in `THIRD_PARTY_NOTICES.md`, compare local skill contents with the recorded community revision to preserve user edits, then copy its `skills/` here. Remove skills retired by that package after checking for local changes, and update this provenance. Preserve this README and the license file.

Restart existing agent sessions after an update so discovery reloads skill names and descriptions.

This fork-only setup must not be sent upstream to meshtastic/firmware.
