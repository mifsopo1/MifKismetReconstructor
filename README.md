# MifKismetReconstructor

**Rebuild editable Blueprint graphs from cooked Kismet bytecode.**

MifKismetReconstructor is an editor-only Unreal Engine 5.3 plugin that takes a **cooked** Blueprint — one shipped in a game, with no editor graphs left in it — and reconstructs its logic back into real, editable K2 nodes. Make an **editable child** or an **uncooked copy** of a cooked Blueprint and actually *see* the events, function calls, delegates, and latent (Delay/Timeline) flow again, instead of empty signature-only stubs.

It reads the raw `UStruct::Script` bytecode of a cooked `BlueprintGeneratedClass`, disassembles it to a statement stream, lifts that into a compiler-mirrored intermediate representation, and emits a connected K2 graph with a live execution spine.

---

## ⚠️ Requirements — read this first

This plugin **does not build against stock Unreal Engine.** It binds an engine-side hook that only exists in a **cooked-editor engine fork**:

- **A cooked-editor UE 5.3.2 engine fork** that provides `CompiledBlueprintReconstructor.h` in the `Kismet` module (the `CreateEditableBlueprintCopy` / "Make Uncooked Blueprint Copy" entry point). On stock UE 5.3 that header does not exist and the plugin will fail to compile. This is the [BrandoCookedEditor-UE5.3.2](https://github.com/631Brando/UnrealEngine/tree/BrandoCookedEditor-UE5.3.2) line of work.
- **Unreal Engine built from source** (editor target). Editor-only, **Win64 only**.
- The plugin connects to the engine hook by a console-variable name at runtime, with **no compile dependency the other way** — so the engine fork works with or without this plugin installed (without it, editable copies are signature-only stubs; with it, the graphs are filled).

If you only need programmatic Blueprint editing (build/wire/compile over HTTP), see the companion **MifBridge** plugin — that one *does* build against a normal source engine.

---

## Install

1. Copy the `MifKismetReconstructor/` folder (the `Source/` folder and the `.uplugin` — **not** any `Binaries/`/`Intermediate/` from another engine) into your project's `Plugins/` directory:
   ```
   <YourProject>/Plugins/MifKismetReconstructor/
   ```
2. The `.uplugin` is `"EnabledByDefault": true`, so no project-file regeneration is required.
3. Build your project's **Editor** target with the editor **closed**, against the cooked-editor engine fork:
   ```
   <EngineFork>\Engine\Build\BatchFiles\Build.bat <YourProject>Editor Win64 Development -Project="<...>.uproject" -WaitMutex
   ```
   This produces `Plugins/MifKismetReconstructor/Binaries/Win64/UnrealEditor-MifKismetReconstructor.dll`.

---

## Usage

### In the editor (the normal path)
Right-click a cooked Blueprint in the Content Browser and choose **Make Uncooked Blueprint Copy** / **Create Editable Child** (this action is provided by the engine fork). With this plugin loaded, the child's function and event graphs come back **filled with reconstructed nodes** instead of empty stubs.

### Console commands (this plugin)
| Command | What it does |
|---|---|
| `mif.kr.ListBP <filter>` | List loaded cooked `BlueprintGeneratedClass`es matching a filter. |
| `mif.kr.FindBP <filter>` | Find Blueprints in the AssetRegistry (cooked + loose) by name. |
| `mif.kr.DumpBP <BP>` | Disassemble a Blueprint's bytecode to a JSON statement stream (per function). |
| `mif.kr.Reconstruct <BP> <Fn>` | Reconstruct a single function into an editable K2 graph (`<Fn>_Recon`). |
| `mif.kr.AnalyzeUbergraph <BP>` | Analyze the shared event ubergraph (per-event slice boundaries). |

### Console variables (defaults shown)
| CVar | Default | Effect |
|---|---|---|
| `mif.kr.Events` | `1` | Reconstruct event bodies by slicing the ubergraph (`0` = events stay bare stubs). |
| `mif.kr.LatentResume` | `1` | Reconstruct latent (Delay/Timeline) resume wiring (`0` = refuse latent bodies). |
| `mif.kr.DriftCensus` | `0` | Append every unclaimed drift edit to `<ProjectSaved>/MifKr/DriftCensus_<ts>.csv` (rule discovery). |
| `mif.kr.ClassifyIntentional` | `0` | Split the drift bucket into intentional shape choices vs. real drift. |
| `mif.kr.DumpFull` | `0` | Dump the full cooked-vs-reconstructed statement stream for every compared function. |

Engine-fork batch/verify commands (`mif.kr.ReconstructAll`, `mif.kr.VerifyFidelity`) live in the engine's `Kismet` module, not this plugin.

### Programmatically
The **MifBridge** plugin exposes a `create_editable_child` HTTP endpoint that drives the same engine entry point; the graphs it produces are filled by this plugin's delegate when both are loaded.

---

## How it works

```
cooked BlueprintGeneratedClass
   │  UStruct::Script (raw bytecode, live pointers)
   ▼
KismetBytecodeDisassemblerJson   → JSON statement stream (per function)
   ▼
KismetBytecodeTransformer        → compiler-mirrored intermediate representation
   ▼
KismetGraphDecompiler            → UK2Node_* nodes + pin wiring + exec spine
   ▼
editable K2 function / event graph  (bound into the engine's editable-copy action)
```

Event bodies are recovered by slicing the shared `ExecuteUbergraph_*` function per event. Data temporaries the cooked compiler spilled to local slots are reconstructed as wires via single-assignment dataflow aliasing, so a partial reconstruction still shows a connected graph rather than a pile of orphaned nodes.

**Status:** verified ~85% event-body reconstruction on a real cooked NPC corpus, with a live execution spine on effectively all non-empty bodies. Editable **children** inherit the parent class cleanly; standalone **siblings/uncooked copies** re-parent to the native super and show more stubs where a reconstructed node's context can't be resolved. This is beta tooling — inspect the result before you rely on it.

---

## License

**GPL-3.0.** This plugin incorporates and adapts source code from
[UEAssetToolkit](https://github.com/Archengius/UEAssetToolkit) and
[UEAssetToolkit-Fixes](https://github.com/Buckminsterfullerene02/UEAssetToolkit-Fixes),
both licensed under GPL-3.0, so this derivative work carries the same license.
See [`LICENSE`](LICENSE) for the full text and [`NOTICE`](NOTICE) for the
attribution and the list of adapted files.

This repository contains **only plugin source** — no Unreal Engine source. The
engine is governed by the Epic Games Unreal Engine EULA; build this plugin
against your own licensed copy of the required engine fork.

*MifKismetReconstructor — by Mif. Editor-only tooling; never cooked into a shipped build.*
