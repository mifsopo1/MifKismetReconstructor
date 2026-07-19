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
	}
}
