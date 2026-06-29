# Local TPM agent constraints (machine-specific)

The primary Linux dev machine uses **gitignored** Cursor rules so agents never run
mutating TPM I/O here without explicit permission.

## Gitignored on this repo (never commit)

| Path | Purpose |
|------|---------|
| `.cursor/rules/tpm-dev-machine-no-mutate.mdc` | Always-on Cursor rule |
| `.cursor/skills/tpm-dev-machine-no-mutate/` | Agent skill |
| `.local/THIS_IS_DEV_MACHINE` | Blocks `TPM2_ALLOW_MUTATING` hw tests in Rust |

Recreate after clone: copy this doc's setup or ask an agent to restore the three paths.

## Rust test gates

| Env | Allows |
|-----|--------|
| (none) | Unit tests only — **default** |
| `TPM2_HARDWARE_TEST=1` | Read-only hw smokes (EK cert, PCR read, GetRandom) |
| `+ TPM2_ALLOW_MUTATING=1` | NV define, PCR extend, seal, etc. — **blocked if `.local/THIS_IS_DEV_MACHINE` exists** |

Mutating validation: Windows test laptop only, unless Matt explicitly permits this machine in chat.
