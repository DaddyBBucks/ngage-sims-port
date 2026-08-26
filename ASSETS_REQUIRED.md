# Locally required files

The repository intentionally ships without proprietary runtime inputs.

| Input | CLI option | Handling |
|---|---|---|
| Compatible ARM game binary | `--binary-file` | Supply from your own lawful copy; keep outside Git. |
| Game resource archive | `--archive-file` | Supply locally; keep outside Git. |
| Game save (optional) | `--save-file` | Use a disposable copy because it may be modified. |

The project does not provide downloads, extraction keys, firmware images, or
instructions for acquiring third-party files. Local paths can point anywhere
outside this repository.
