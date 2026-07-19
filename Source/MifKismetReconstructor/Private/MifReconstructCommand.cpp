// Phase-3 driver harness: mint an uncooked Blueprint, add a function graph from a cooked function's
// signature, reconstruct its bytecode into that graph, compile, and open the editor so the graph is
// physically viewable.  Usage:  mif.kr.Reconstruct <BPName> <FuncName>
// DEBUG-gated / throwaway (this becomes the F3 hook in Phase 4).

#include "MifReconstructorDebug.h"
#include "MifReconstructPipeline.h"
#include "Toolkit/KismetBytecodeDisassemblerJson.h"
#include "AssetGeneration/KismetBytecodeTransformer.h"
#include "AssetGeneration/KismetGraphDecompiler.h"
#include "AssetGeneration/KismetIntermediateFormat.h"

#include "Engine/Blueprint.h"
#include "Engine/BlueprintGeneratedClass.h"
#include "Kismet2/KismetEditorUtilities.h"
#include "Kismet2/BlueprintEditorUtils.h"
#include "EdGraphSchema_K2.h"
#include "EdGraph/EdGraph.h"
#include "Editor.h"
#include "Subsystems/AssetEditorSubsystem.h"
#include "HAL/IConsoleManager.h"
#include "Modules/ModuleManager.h"
#include "UObject/Package.h"
#include "UObject/GarbageCollection.h"
#include "Dom/JsonObject.h"
#include "Dom/JsonValue.h"
#include "AssetRegistry/AssetRegistryModule.h"
#include "AssetRegistry/IAssetRegistry.h"
#include "AssetRegistry/ARFilter.h"

// Shared reconstruction pipeline — used by BOTH the mif.kr.Reconstruct console command (below, DEBUG-gated) AND
// the "Make Uncooked Blueprint Copy" (F3) engine hook (bound in the module startup). Compiled in all configs.
bool MifReconstructFunctionIntoGraph(UFunction* SourceFunc, UEdGraph* TargetGraph, UBlueprint* OwnerBP)
{
	if (!SourceFunc || SourceFunc->Script.Num() == 0 || !TargetGraph || !OwnerBP) return false;

	// Hold the GC lock for the whole per-function pipeline. The IR holds RAW, un-rooted UFunction*/UClass* pointers
	// (FunctionToCall + call contexts); a self-call resolves against the new BP's TRANSIENT SkeletonGeneratedClass.
	// A NewObject inside SpawnNode can tick incremental GC mid-reconstruction and collect one of those, leaving a
	// dangling UFunction* → SetFromFunction crashes in FMemberReference::SetGivenSelfScope (owner GetOwnerClass()==null
	// → AV reading 0x120). Locking GC for the scope keeps every referenced object alive until the graph is wired; GC
	// still runs freely BETWEEN functions (the F3 host loops us once per function). Diagnosed on BP_BaseNPC: crash
	// after ~40 functions + an 8s GC stall — a lifetime bug the getter/owner null-guards structurally cannot fix.
	FGCScopeGuard MifReconstructGCLock;

	// MVP defers EVENTS: the ubergraph (ExecuteUbergraph_*) is one giant switch-dispatched function holding every
	// event body — out of scope, and reconstructing it whole is both wrong (events should stay stubs) and the source
	// of a deep, expensive crash on BP_BaseNPC (it's what F3 hits right after the regular functions). Skip it; the
	// per-event graph split is a separate phase.
	if (SourceFunc->HasAnyFunctionFlags(FUNC_UbergraphFunction))
	{
#if MIF_KR_DEBUG
		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[F3] skip ubergraph %s (events deferred)"), *SourceFunc->GetName());
#endif
		return false;
	}

#if MIF_KR_DEBUG
	// BEGIN marker (flushed) so a crash mid-reconstruction names the exact culprit function in the log.
	UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[F3] BEGIN %s (%d bytes)"), *SourceFunc->GetName(), SourceFunc->Script.Num());
	if (GLog) { GLog->Flush(); }
#endif

	// disassemble → JSON statements (drop the trailing EndOfScript marker the transformer doesn't model)
	FKismetBytecodeDisassemblerJson Dis;
	TArray<TSharedPtr<FJsonValue>> Vals = Dis.SerializeFunction(SourceFunc);
	if (Dis.bDisassemblyFailed)
	{
		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("Disassembly of %s aborted at opcode 0x%02X (byte %d)."),
			*SourceFunc->GetName(), Dis.FailedOpcode, Dis.FailedAtIndex);
	}
	TArray<TSharedPtr<FJsonObject>> Stmts;
	for (const TSharedPtr<FJsonValue>& V : Vals)
	{
		TSharedPtr<FJsonObject> O = V->AsObject();
		if (!O.IsValid()) continue;
		if (O->GetStringField(TEXT("Inst")) == TEXT("EndOfScript")) continue;
		Stmts.Add(O);
	}

	// transform JSON → compiled statements
	// SourceClass MUST be the exact expression the disassembler used as its SelfScope (KismetBytecodeDisassemblerJson.cpp:950)
	// so the "<SELF>" tokens it wrote into pin types deserialize back to the SAME class object they were written for.
	FKismetBytecodeTransformer Xform(OwnerBP, SourceFunc->GetTypedOuter<UClass>());
	Xform.SetSourceStatements(SourceFunc->GetName(), Stmts);
	TArray<TSharedPtr<FKismetCompiledStatement>> Compiled = Xform.FinishGeneration();

#if MIF_KR_DEBUG
	if (SourceFunc->GetName() == TEXT("UptadeControllers"))   // scoped IR dump for the one function under review
	{
		auto Fmt = [](const TSharedPtr<FKismetTerminal>& T) -> FString
		{
			if (!T.IsValid()) return TEXT("<null>");
			return T->bIsLiteral
				? FString::Printf(TEXT("LIT('%s' ty=%s)"), *T->StringLiteral, *T->Type.PinCategory.ToString())
				: FString::Printf(TEXT("var'%s'(vt=%d)"), *T->AssociatedVarProperty, (int32) T->VarType);
		};
		TMap<FKismetCompiledStatement*, int32> Idx;
		for (int32 i = 0; i < Compiled.Num(); ++i) if (Compiled[i].IsValid()) Idx.Add(Compiled[i].Get(), i);
		for (int32 i = 0; i < Compiled.Num(); ++i)
		{
			const TSharedPtr<FKismetCompiledStatement>& C = Compiled[i];
			if (!C.IsValid()) continue;
			FString R; for (const TSharedPtr<FKismetTerminal>& T : C->RHS) R += Fmt(T) + TEXT(" ");
			const int32* Tgt = C->TargetLabel.IsValid() ? Idx.Find(C->TargetLabel.Get()) : nullptr;
			UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[ir] %d type=%d fn=%s tgt=%d LHS=%s RHS=[ %s]"),
				i, (int32) C->Type, C->FunctionToCall ? *C->FunctionToCall->GetName() : TEXT("-"),
				Tgt ? *Tgt : -1, *Fmt(C->LHS), *R);
		}
	}
#endif

	// decompile the IR into the target graph (caller compiles the Blueprint afterward)
	FKismetGraphDecompiler Decomp(SourceFunc, TargetGraph);
	return Decomp.Run(SourceFunc, Compiled, TargetGraph, OwnerBP);
}

#if MIF_KR_DEBUG

static UBlueprintGeneratedClass* MifKr_FindBPGCByName(const FString& Name)
{
	FAssetRegistryModule& ARM = FModuleManager::LoadModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));
	FARFilter Filter;
	Filter.ClassPaths.Add(UBlueprintGeneratedClass::StaticClass()->GetClassPathName());
	Filter.ClassPaths.Add(UBlueprint::StaticClass()->GetClassPathName());
	Filter.bRecursiveClasses = true;
	TArray<FAssetData> Assets;
	ARM.Get().GetAssets(Filter, Assets);

	FString Needle = Name; Needle.RemoveFromEnd(TEXT("_C"));
	for (const FAssetData& A : Assets)
	{
		if (!A.AssetName.ToString().Contains(Needle)) continue;
		UObject* Obj = A.GetAsset();
		if (UBlueprintGeneratedClass* C = Cast<UBlueprintGeneratedClass>(Obj)) return C;
		if (UBlueprint* BP = Cast<UBlueprint>(Obj)) return Cast<UBlueprintGeneratedClass>(BP->GeneratedClass);
	}
	return nullptr;
}

static void MifKr_Reconstruct(const TArray<FString>& Args)
{
	if (Args.Num() < 2)
	{
		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("Usage: mif.kr.Reconstruct <BPName> <FuncName>"));
		return;
	}
	const FString BPName = Args[0];
	const FString FuncName = Args[1];

	UBlueprintGeneratedClass* SourceBPGC = MifKr_FindBPGCByName(BPName);
	if (!SourceBPGC)
	{
		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("Source BP '%s' not found in the AssetRegistry."), *BPName);
		return;
	}
	UFunction* SourceFunc = SourceBPGC->FindFunctionByName(FName(*FuncName), EIncludeSuperFlag::ExcludeSuper);
	if (!SourceFunc || SourceFunc->Script.Num() == 0)
	{
		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("Function '%s' not found on %s (or has no bytecode)."), *FuncName, *SourceBPGC->GetName());
		return;
	}

	// 1) mint an uncooked Blueprint parented to the cooked source class (so members resolve)
	FString CleanName = SourceBPGC->GetName();
	CleanName.RemoveFromEnd(TEXT("_C"));
	static int32 GReconCounter = 0;   // unique per run so re-invocation doesn't collide with a prior asset
	const FString ShortName = FString::Printf(TEXT("Recon_%s_%s_%d"), *CleanName, *FuncName, ++GReconCounter);
	const FString PkgPath = FString::Printf(TEXT("/Game/Reconstructed/%s"), *ShortName);
	UPackage* Pkg = CreatePackage(*PkgPath);
	UBlueprint* NewBP = FKismetEditorUtilities::CreateBlueprint(
		SourceBPGC, Pkg, FName(*ShortName), BPTYPE_Normal,
		UBlueprint::StaticClass(), UBlueprintGeneratedClass::StaticClass());
	if (!NewBP)
	{
		UE_LOG(LogMifKismetReconstructor, Error, TEXT("CreateBlueprint failed for %s"), *ShortName);
		return;
	}

	// 2) add a function graph from the source signature (NEW function name to avoid override semantics)
	const FName ReconGraphName(*FString::Printf(TEXT("%s_Recon"), *FuncName));
	UEdGraph* NewGraph = FBlueprintEditorUtils::CreateNewGraph(NewBP, ReconGraphName, UEdGraph::StaticClass(), UEdGraphSchema_K2::StaticClass());
	FBlueprintEditorUtils::AddFunctionGraph<UFunction>(NewBP, NewGraph, /*bIsUserCreated*/ false, SourceFunc);

	// 3) reconstruct SourceFunc's bytecode into the graph (the SHARED pipeline — identical path to the F3 hook)
	const bool bOk = MifReconstructFunctionIntoGraph(SourceFunc, NewGraph, NewBP);

	// 4) compile the Blueprint (the oracle) + open it so the graph is viewable
	FKismetEditorUtilities::CompileBlueprint(NewBP);
	FBlueprintEditorUtils::MarkBlueprintAsStructurallyModified(NewBP);
	Pkg->MarkPackageDirty();
	FAssetRegistryModule::AssetCreated(NewBP);

	UE_LOG(LogMifKismetReconstructor, Display,
		TEXT("mif.kr.Reconstruct %s::%s → ok=%d | graphNodes=%d | asset: %s (function '%s_Recon')"),
		*SourceBPGC->GetName(), *FuncName, bOk, NewGraph->Nodes.Num(), *PkgPath, *FuncName);

	if (GEditor)
	{
		if (UAssetEditorSubsystem* AES = GEditor->GetEditorSubsystem<UAssetEditorSubsystem>())
		{
			AES->OpenEditorForAsset(NewBP);
		}
	}
}

static FAutoConsoleCommand GMifKrReconstruct(
	TEXT("mif.kr.Reconstruct"),
	TEXT("Reconstruct a cooked function's bytecode into an editable Blueprint graph + open it. Usage: mif.kr.Reconstruct <BPName> <FuncName>"),
	FConsoleCommandWithArgsDelegate::CreateStatic(&MifKr_Reconstruct));

#endif // MIF_KR_DEBUG
