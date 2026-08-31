# Supported disc

Vana360 supports one input profile:
Final Fantasy XI: Ultimate Collection for Xbox 360, USA, Redump disc 63782.

| Property | Required value |
|---|---|
| Profile ID | `ffxi-ultimate-collection-usa-redump-63782` |
| ISO size | `7,838,695,424` bytes |
| SHA-256 | `5fd1258ee10fae4bf27d685868dde79ef753da01722350f86c8291fe5235934f` |
| XGD2 media ID | `1fdb42f7` |
| Xbox title ID | `535107d5` |
| Entrypoint | `GameExecContent0001.xex` |
| Companion modules | `PolCoreContent.xex`, `FFXi.dll`, `FFXiMain.dll`, `patch.xex` |

## Verified module identities

These ordinary-file inputs are the executable set selected by the manifest.

| Runtime path | Bytes | SHA-256 |
|---|---:|---|
| `PlayOnline/GameExecContent0001.xex` | 233,472 | `8eb1d6870a9884b479c2b53b5a0d8fea74b8006ddaf3de7b1e44b97fbc353e83` |
| `PlayOnline/PolCoreContent.xex` | 925,696 | `f5e831f9cb20cbfa4be17d50d8c8b62a15614d1c636b09780a18610ce125cf5c` |
| `0001/FFXi.dll` | 3,121,152 | `406a3c9e2fc1d543e1f76484026fdbff35aa163c749190a74f024fc23c343434` |
| `0001/FFXiMain.dll` | 7,876,608 | `ea25366fed9ce07baaed60934e41411b59ae681163e3d2fd6788dc874ef5c47d` |
| `0001/patch.xex` | 135,168 | `23b498a696faf06faa336faa49d938b6f55fcd281861ee3ded8705a405b1e480` |

## Verified module filetimes

These verified module filetimes are UTC metadata values, distinct from filesystem timestamps.

| Module | Filetime (UTC) |
|---|---|
| `GameExecContent0001.xex` | `2007-08-29 09:19:22 UTC` |
| `PolCoreContent.xex` | `2007-08-29 09:06:40 UTC` |
| `FFXi.dll` | `2009-06-25 14:07:10 UTC` |
| `FFXiMain.dll` | `2009-07-09 14:12:47 UTC` |
| `patch.xex` | `2009-06-25 12:21:36 UTC` |

The executable set combines older launcher modules with the June-July 2009 gameplay modules.
Vana360 therefore identifies it as the selected 2009 Ultimate Collection client,
not as a single whole-disc build date.

Run the verifier before extraction:

```powershell
.\scripts\verify-disc.ps1 -Path <path-to-iso>
```

- Keep your legally owned source ISO on your machine.
  It is provenance evidence and must remain unchanged and untracked.
- Keep the extracted runtime tree private. Restore it in the ignored `game/`
  directory.
- Put generated ReXGlue output only in the ignored `generated/` directory.
- Use only the executable module graph defined by the manifest.
- Treat content under `game/` as runtime input.
  Do not redistribute it as project material.
