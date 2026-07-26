// MifKismetReconstructor — reconstruct editable K2 graphs from cooked Kismet bytecode.
// Editor-only. Phase 0 = in-editor bytecode disassembler + JSON dumper (no engine hook yet).

using UnrealBuildTool;

public class MifKismetReconstructor : ModuleRules
{
	public MifKismetReconstructor(ReadOnlyTargetRules Target) : base(Target)
	{
		PCHUsage = ModuleRules.PCHUsageMode.UseExplicitOrSharedPCHs;

		PublicDependencyModuleNames.AddRange(new string[]
		{
			"Core",
			"CoreUObject",
			"Engine"          // FEdGraphPinType, FMemberReference, UBlueprintGeneratedClass, UFunction
		});

		PrivateDependencyModuleNames.AddRange(new string[]
		{
			"Json",           // FJsonObject / FJsonSerializer for the disassembler output + dumper
			"AssetRegistry",  // resolve cooked/unloaded Blueprints by name for the Phase-0 dumper
			"BlueprintGraph", // UEdGraphSchema_K2 + UK2Node_* + FEdGraphSchemaAction_K2NewNode (transformer + decompiler)
			"KismetCompiler", // BPTerminal.h (transformer include)
			"UnrealEd",       // FBlueprintEditorUtils / FKismetEditorUtilities (decompiler, Phase 3)
			"Kismet"          // CompiledBlueprintReconstructor.h — bind the F3 "Make Uncooked Blueprint Copy" hook (Phase 4)
		});

		// MifBridge (OPTIONAL). All kr_* HTTP endpoints live in THIS module (coupling model (b),
		// docs/audit/work/K2_reconstructor_pipeline.md §B): the handlers sit next to the Private code
		// they call, so not one reconstructor symbol needs exporting. The dep is guarded so this
		// plugin still builds when MifBridge is not installed — the reconstructor's own value (F3
		// hook, verifier, console tools) does not depend on the bridge.
		// WITH_MIFBRIDGE is ALWAYS defined (1 or 0), never left undefined, so the sources can use a
		// plain #if without an #ifndef guard.
		string MifBridgeModuleDir = System.IO.Path.Combine(PluginDirectory, "..", "MifBridge", "Source", "MifBridge");
		if (System.IO.Directory.Exists(MifBridgeModuleDir))
		{
			PrivateDependencyModuleNames.Add("MifBridge");
			PrivateDefinitions.Add("WITH_MIFBRIDGE=1");
		}
		else
		{
			PrivateDefinitions.Add("WITH_MIFBRIDGE=0");
		}
	}
}
