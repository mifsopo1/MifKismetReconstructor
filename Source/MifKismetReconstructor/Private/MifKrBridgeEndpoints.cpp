// MifKismetReconstructor — all kr_* MifBridge HTTP endpoints.
//
// Wave 1, complete (8 endpoints, ZERO export promotions — everything reached is either already
// MIFKISMETRECONSTRUCTOR_API or lives in this same module):
//   kr_list_cooked_blueprints  ReadOnly     registry census, loads nothing
//   kr_dump_blueprint          ReadOnly     class structure: functions/properties/events/parent chain
//   kr_disassemble_function    ReadOnly     one function's bytecode as a JSON statement stream
//   kr_list_events             ReadOnly     event thunks + recovered ubergraph entry offsets
//   kr_analyze_ubergraph       ReadOnly     prologue shape, per-event reachability, shared-latent verdict
//   kr_pin_type_from_property  ReadOnly     FProperty -> FEdGraphPinType -> bridge type-grammar string
//   kr_reconstruct_request     SelfManaged  start the ONE job slot (deferred one tick)
//   kr_reconstruct_status      ReadOnly     poll it
// Wave 3, complete (4 endpoints, ONE engine export — RunTransientBlueprintReconstruct, declared in
// CompiledBlueprintReconstructor.h; nothing else in the reconstructor was promoted):
//   kr_verify_fidelity         SelfManaged  throwaway transient CHILD + per-function bytecode diff
//   kr_classify_drift          SelfManaged  the same run, decomposed into per-function verdicts
//   kr_drift_census            SelfManaged  the same run over a filtered corpus, ONE BP PER TICK
//   kr_batch_reconstruct       SelfManaged  pass/fail sweep (sibling by default), ONE BP PER TICK
// All four run through the one-slot job model and are polled by kr_reconstruct_status. See the
// WAVE 3 block below for the design; the export's own header carries the lifetime contract.
//
// Coupling model (b) (docs/audit/work/K2_reconstructor_pipeline.md §B, ratified in K_IMPL_PLAN.md
// §0.2): the handlers live HERE, in the PROVIDER module, next to the Private code they call, so not
// one reconstructor symbol needs exporting and MifBridge gains only the registrar. MifBridge stays
// soft-coupled: it loads and serves its built-ins whether or not this plugin is installed.
//
// ============================ SHIP-SAFETY RULE — READ BEFORE ADDING A HANDLER ====================
// NOTHING in this file may be gated on MIF_KR_DEBUG, and no handler may call a MifKr_* console
// helper. MifBlueprintDumper.cpp:29-352, Analysis/MifUbergraphAnalyzer.cpp:47-397 and
// MifReconstructCommand.cpp:118-212 are ALL inside `#if MIF_KR_DEBUG` (MifReconstructorDebug.h:9-11,
// whose own comment says "Ship OFF (set to 0) before any release") AND file-static — internal
// linkage, so they are not even reachable from this sibling TU, and they disappear entirely the day
// the gate flips. Calling one would make the whole HTTP surface vanish in a shipping build: the
// endpoints would silently stop existing, self_audit's count would drop, and nothing would say why.
// The small amount of resolution/enumeration logic the handlers need is therefore REIMPLEMENTED
// here, ungated. That is deliberate duplication of DATA (a registry filter), not of logic.
// Grep gate for reviews — zero hits required (the -v drops THIS comment block, which necessarily
// names the very symbols it forbids; without it the gate would always fail on its own docs):
//   grep -n "MifKr_ResolveBPGC\|MifKr_RegistryMatches\|MifKr_CoerceToBPGC\|MifKr_FindBPGCByName\|
//            MifKr_AnalyzeUbergraph\|MifKr_DumpBP\|MifKr_OpcodeName" MifKrBridgeEndpoints.cpp \
//     | grep -v "^[0-9]*://"
// ================================================================================================
//
// PARAMETER-DISCIPLINE DUPLICATION (deliberate, K_IMPL_PLAN.md §B.7 option (a)):
// MifBridge::RejectUnknownParams and the JStr/JInt/JBool accessors are declared in
// MifBridge/Private/MifBridgeHandlers.h — a PRIVATE header, unreachable from this module even though
// we link MifBridge. The alternatives were (a) reimplement them here or (b) re-export them through
// the new public registry header. (a) is chosen: MifBridge's brand-new public surface stays at
// exactly two functions (RegisterExternalEndpoint / UnregisterExternalEndpoints) instead of growing
// a JSON-accessor library that would then have to stay ABI-stable for every provider forever. The
// precedent is the helper's own history — RejectUnknownParams was born file-local in
// MifBridgeCooked.cpp and only promoted once a second file needed it. Cost: ~40 lines mirrored
// below; they must track MifBridge's semantics (case-insensitive key matching, "accepted:" list in
// the message). If a third provider plugin ever appears, promote instead of copying a third time.

#include "MifReconstructorDebug.h"   // LogMifKismetReconstructor. NOT for MIF_KR_DEBUG — see above.

#if WITH_MIFBRIDGE

#include "MifBridgeEndpointRegistry.h"   // MifBridge/Public — the ONLY MifBridge header reachable here

// In-module Private headers. Every symbol reached through these was checked for BOTH internal linkage
// and the MIF_KR_DEBUG gate (K_IMPL_PLAN.md §A.3 table): all are ungated with external linkage, which
// is the entire payoff of coupling model (b) — zero export promotions for the whole of Wave 1.
#include "MifKrJobManager.h"                          // one-slot job record (kr_reconstruct_request/status)
#include "MifReconstructPipeline.h"                   // MifReconstructFunctionIntoGraph — ungated, external linkage
#include "Analysis/MifUbergraphSlicer.h"              // namespace MifUber — ungated, external linkage
#include "Toolkit/KismetBytecodeDisassemblerJson.h"   // class is MIFKISMETRECONSTRUCTOR_API
#include "Toolkit/PropertyTypeHelper.h"               // class is MIFKISMETRECONSTRUCTOR_API

#include "CompiledBlueprintReconstructor.h"           // KISMET_API CreateEditableBlueprintCopy (engine fork)

#include "CoreMinimal.h"
#include <initializer_list>              // KrRejectUnknownParams' accepted-key list (mirrors MifBridge)
#include "Dom/JsonObject.h"
#include "Dom/JsonValue.h"
#include "EdGraph/EdGraph.h"
#include "EdGraphSchema_K2.h"            // PC_* pin categories — the bridge type grammar's vocabulary
#include "Editor.h"                      // GEditor — the timer manager behind the one-tick deferral
#include "Engine/Blueprint.h"
#include "Engine/BlueprintGeneratedClass.h"
#include "Engine/LatentActionManager.h"  // FLatentActionInfo::StaticStruct() — the latent-call marker
#include "Kismet2/BlueprintEditorUtils.h"
#include "Kismet2/CompilerResultsLog.h"
#include "Kismet2/KismetEditorUtilities.h"
#include "HAL/FileManager.h"             // IFileManager — the sweep CSV writer and the census-file scan
#include "HAL/IConsoleManager.h"         // IConsoleVariable — scoped mif.kr.* overrides (Wave 3)
#include "Logging/TokenizedMessage.h"    // FTokenizedMessage::ToText for compile messages
#include "Misc/FileHelper.h"             // FFileHelper::LoadFileToString — drift-census CSV row count
#include "Misc/PackageName.h"            // DoesPackageExist — target-path uniquification
#include "Misc/Paths.h"                  // FPaths::ProjectSavedDir — <ProjectSaved>/MifKr report folder
#include "Modules/ModuleManager.h"
#include "Serialization/Archive.h"       // FArchive::Serialize/Flush — per-row-flushed sweep CSV
#include "TimerManager.h"                // SetTimerForNextTick
#include "UObject/Class.h"
#include "UObject/UnrealType.h"          // FProperty::GetCPPType, TFieldIterator<FProperty>
#include "UObject/GarbageCollection.h"   // FGCScopeGuard — raw cooked UFunction*/UStruct* handling
#include "UObject/ObjectMacros.h"        // PKG_Cooked
#include "UObject/Package.h"             // CreatePackage
#include "UObject/UObjectGlobals.h"      // LoadObject
#include "AssetRegistry/AssetRegistryModule.h"
#include "AssetRegistry/IAssetRegistry.h"
#include "AssetRegistry/ARFilter.h"
#include "AssetRegistry/AssetData.h"

namespace MifKr::BridgeEndpoints
{
	static const TCHAR* GProvider = TEXT("MifKismetReconstructor");

	// --- Local mirrors of MifBridge's private handler helpers (see the file header) --------------

	static void KrFail(const TSharedRef<FJsonObject>& Out, const FString& Message)
	{
		Out->SetBoolField(TEXT("ok"), false);
		Out->SetStringField(TEXT("error"), Message);
	}

	/** Mirror of MifBridge::RejectUnknownParams (MifBridgeHandlers.h:65-67). Fails Out (and returns
	 *  true) naming EVERY key in In that is not accepted, and listing the accepted set. An IGNORED
	 *  parameter is worse than a rejected one — the caller gets ok:true and debugs the wrong
	 *  subsystem. Matching is case-INSENSITIVE, exactly as the bridge's JSON accessors find fields,
	 *  so a key that WOULD be honoured is never rejected. KeyNotes explains a specific unknown key
	 *  where "unrecognised" alone would mislead (an unimplemented capability, not a typo). */
	static bool KrRejectUnknownParams(const TSharedRef<FJsonObject>& In, const TSharedRef<FJsonObject>& Out,
		std::initializer_list<const TCHAR*> AcceptedKeys, const TCHAR* AcceptedSummary,
		std::initializer_list<TPair<const TCHAR*, const TCHAR*>> KeyNotes = {})
	{
		TArray<FString> Unrecognised;
		for (const TPair<FString, TSharedPtr<FJsonValue>>& Pair : In->Values)
		{
			// 'op' is the BATCH DISPATCHER's routing key, not a handler parameter: H_batch passes each op
			// object to the handler VERBATIM, 'op' field included. MifBridge tolerates it centrally in
			// its own RejectUnknownParams so no call site has to remember it; this mirror must do the
			// same or every ReadOnly kr_* endpoint fails with "unrecognised parameter 'op'" the moment it
			// is called inside batch — strictness silently breaking composition, the exact regression
			// MifBridge already had and fixed (06_IMPLEMENTED.md, "Batch E + `op` regression").
			if (Pair.Key.Equals(TEXT("op"), ESearchCase::IgnoreCase))
			{
				continue;
			}

			bool bKnown = false;
			for (const TCHAR* Key : AcceptedKeys)
			{
				if (Pair.Key.Equals(Key, ESearchCase::IgnoreCase)) { bKnown = true; break; }
			}
			if (bKnown)
			{
				continue;
			}
			const TCHAR* Note = nullptr;
			for (const TPair<const TCHAR*, const TCHAR*>& KeyNote : KeyNotes)
			{
				if (Pair.Key.Equals(KeyNote.Key, ESearchCase::IgnoreCase)) { Note = KeyNote.Value; break; }
			}
			Unrecognised.Add(Note
				? FString::Printf(TEXT("'%s' (%s)"), *Pair.Key, Note)
				: FString::Printf(TEXT("'%s'"), *Pair.Key));
		}
		if (Unrecognised.Num() == 0)
		{
			return false;
		}
		KrFail(Out, FString::Printf(TEXT("unrecognised parameter%s %s - accepted: %s"),
			Unrecognised.Num() == 1 ? TEXT("") : TEXT("s"),
			*FString::Join(Unrecognised, TEXT(", ")), AcceptedSummary));
		return true;
	}

	/** First non-empty of several accepted spellings (mirror of MifBridge::JStrAny). */
	static FString KrJStrAny(const TSharedRef<FJsonObject>& In, std::initializer_list<const TCHAR*> Fields,
		const FString& Default = FString())
	{
		for (const TCHAR* Field : Fields)
		{
			FString Value;
			if (In->TryGetStringField(Field, Value) && !Value.IsEmpty()) { return Value; }
		}
		return Default;
	}

	static bool KrJBool(const TSharedRef<FJsonObject>& In, const TCHAR* Field, bool Default)
	{
		bool Value = Default;
		return In->TryGetBoolField(Field, Value) ? Value : Default;
	}

	/** First PRESENT of several accepted spellings, for BOOL params with aliases
	 *  (classifyIntentional/classify). "First present", not "first true": a caller who passes
	 *  classify:false must get false, and a value-based fold would silently return the default. */
	static bool KrJBoolAny(const TSharedRef<FJsonObject>& In, std::initializer_list<const TCHAR*> Fields, bool Default)
	{
		for (const TCHAR* Field : Fields)
		{
			bool Value = Default;
			if (In->TryGetBoolField(Field, Value)) { return Value; }
		}
		return Default;
	}

	static int32 KrJInt(const TSharedRef<FJsonObject>& In, const TCHAR* Field, int32 Default)
	{
		int32 Value = Default;
		return In->TryGetNumberField(Field, Value) ? Value : Default;
	}

	/** First present of several accepted spellings, for INT params with aliases (offset/statementOffset). */
	static int32 KrJIntAny(const TSharedRef<FJsonObject>& In, std::initializer_list<const TCHAR*> Fields, int32 Default)
	{
		for (const TCHAR* Field : Fields)
		{
			int32 Value = Default;
			if (In->TryGetNumberField(Field, Value)) { return Value; }
		}
		return Default;
	}

	// --- Shared validation ------------------------------------------------------------------------

	/** Range-check a paging pair. REFUSES rather than clamps: a caller who asked for 5000 rows and
	 *  silently got 2000 would under-report the corpus and never know (the rule already applied by
	 *  kr_list_cooked_blueprints). Returns true and fails Out when the values are unusable. */
	static bool KrRejectPaging(const TSharedRef<FJsonObject>& Out, int32 Offset, int32 Limit, int32 MaxLimit,
		const TCHAR* OffsetName, const TCHAR* LimitName)
	{
		if (Offset < 0)
		{
			KrFail(Out, FString::Printf(TEXT("%s %d is invalid; pass 0 or greater"), OffsetName, Offset));
			return true;
		}
		if (Limit < 1)
		{
			KrFail(Out, FString::Printf(TEXT("%s %d is invalid; pass 1..%d"), LimitName, Limit, MaxLimit));
			return true;
		}
		if (Limit > MaxLimit)
		{
			KrFail(Out, FString::Printf(TEXT("%s %d exceeds maximum %d; page with %s"), LimitName, Limit, MaxLimit, OffsetName));
			return true;
		}
		return false;
	}

	// --- Resolution (reimplemented here, ungated) -------------------------------------------------
	// The dumper's resolver is file-static AND inside the MIF_KR_DEBUG gate (see the SHIP-SAFETY block
	// at the top of this file), so it is unreachable from this sibling TU by construction and would
	// vanish in a shipping build. This reimplementation follows the create_editable_child precedent
	// (MifBridgeReconstruct.cpp:31-39) for the path form, with the _C fallback the dumper uses.
	//
	// ONE DELIBERATE DIVERGENCE from the console-command resolver: a BARE NAME resolves by EXACT match
	// on the _C-stripped asset name, never by substring. The console version returns "the first asset
	// whose name CONTAINS the needle" — a coin flip that is acceptable for a human watching the log and
	// unacceptable for an agent acting on the answer. Ambiguity here is an ERROR listing the candidates.

	// Defined with the registry-enumeration helpers below; declared here because the bare-name
	// resolver dedups with the same "prefer the *_C row" rule kr_list_cooked_blueprints uses.
	static bool IsGeneratedClassAsset(const FAssetData& A);

	static UBlueprintGeneratedClass* KrCoerceBPGC(UObject* Obj)
	{
		if (!Obj) { return nullptr; }
		if (UBlueprintGeneratedClass* C = Cast<UBlueprintGeneratedClass>(Obj)) { return C; }
		if (UBlueprint* BP = Cast<UBlueprint>(Obj)) { return Cast<UBlueprintGeneratedClass>(BP->GeneratedClass); }
		return nullptr;
	}

	/** Resolve an asset argument to a loaded UBlueprintGeneratedClass. Unlike kr_list_cooked_blueprints
	 *  (a pure registry read), this DOES load the package — that is unavoidable: bytecode lives on the
	 *  live UFunction objects. Returns nullptr with OutError filled and actionable. */
	static UBlueprintGeneratedClass* KrResolveBPGC(const FString& Arg, FString& OutError)
	{
		if (Arg.IsEmpty())
		{
			OutError = TEXT("empty asset argument");
			return nullptr;
		}

		if (Arg.Contains(TEXT("/")))
		{
			if (UBlueprintGeneratedClass* C = LoadObject<UBlueprintGeneratedClass>(nullptr, *Arg, nullptr, LOAD_NoWarn | LOAD_Quiet))
			{
				return C;
			}
			const FString WithC = Arg.EndsWith(TEXT("_C")) ? Arg : Arg + TEXT("_C");
			if (WithC != Arg)
			{
				if (UBlueprintGeneratedClass* C = LoadObject<UBlueprintGeneratedClass>(nullptr, *WithC, nullptr, LOAD_NoWarn | LOAD_Quiet))
				{
					return C;
				}
			}
			if (UBlueprint* BP = LoadObject<UBlueprint>(nullptr, *Arg, nullptr, LOAD_NoWarn | LOAD_Quiet))
			{
				if (UBlueprintGeneratedClass* C = Cast<UBlueprintGeneratedClass>(BP->GeneratedClass))
				{
					return C;
				}
				OutError = FString::Printf(
					TEXT("'%s' is a Blueprint asset but its GeneratedClass is not a UBlueprintGeneratedClass (never compiled?)"), *Arg);
				return nullptr;
			}
			OutError = FString::Printf(
				TEXT("asset '%s' not found - pass the objectPath, ideally the .<Name>_C class path (e.g. /Game/Path/BP_Foo.BP_Foo_C); ")
				TEXT("list candidates with kr_list_cooked_blueprints"), *Arg);
			return nullptr;
		}

		// Bare name → EXACT registry match, package-deduped.
		IAssetRegistry& Registry = FModuleManager::LoadModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry")).Get();
		if (Registry.IsLoadingAssets())
		{
			OutError = TEXT("asset registry still scanning; retry after the initial scan completes, or pass a full objectPath (which does not need the registry)");
			return nullptr;
		}

		FARFilter Filter;
		Filter.ClassPaths.Add(UBlueprintGeneratedClass::StaticClass()->GetClassPathName());
		Filter.ClassPaths.Add(UBlueprint::StaticClass()->GetClassPathName());
		Filter.bRecursiveClasses = true;
		TArray<FAssetData> Assets;
		Registry.GetAssets(Filter, Assets);

		FString Needle = Arg;
		Needle.RemoveFromEnd(TEXT("_C"));

		TMap<FName, FAssetData> ByPackage;
		for (const FAssetData& A : Assets)
		{
			if (!A.IsValid()) { continue; }
			FString AssetName = A.AssetName.ToString();
			AssetName.RemoveFromEnd(TEXT("_C"));
			if (!AssetName.Equals(Needle, ESearchCase::IgnoreCase)) { continue; }
			if (FAssetData* Existing = ByPackage.Find(A.PackageName))
			{
				if (!IsGeneratedClassAsset(*Existing) && IsGeneratedClassAsset(A)) { *Existing = A; }
			}
			else
			{
				ByPackage.Add(A.PackageName, A);
			}
		}

		if (ByPackage.Num() == 0)
		{
			OutError = FString::Printf(
				TEXT("no Blueprint asset is named exactly '%s' (matching is EXACT on the _C-stripped name, never a substring) - ")
				TEXT("pass the full objectPath, or search with kr_list_cooked_blueprints"), *Arg);
			return nullptr;
		}
		if (ByPackage.Num() > 1)
		{
			TArray<FString> Candidates;
			for (const TPair<FName, FAssetData>& KV : ByPackage)
			{
				Candidates.Add(KV.Value.GetObjectPathString());
				if (Candidates.Num() >= 10) { break; }
			}
			OutError = FString::Printf(
				TEXT("'%s' is ambiguous - %d packages share that name; pass one of these objectPaths: %s"),
				*Arg, ByPackage.Num(), *FString::Join(Candidates, TEXT(", ")));
			return nullptr;
		}

		for (const TPair<FName, FAssetData>& KV : ByPackage)
		{
			if (UBlueprintGeneratedClass* C = KrCoerceBPGC(KV.Value.GetAsset()))
			{
				return C;
			}
			OutError = FString::Printf(TEXT("'%s' resolved to %s, which is not a BlueprintGeneratedClass"),
				*Arg, *KV.Value.AssetClassPath.ToString());
			return nullptr;
		}
		return nullptr;
	}

	/** Resolve + fail Out in one step. Returns nullptr when it has already written the error. */
	static UBlueprintGeneratedClass* KrResolveBPGCStrict(const TSharedRef<FJsonObject>& In, const TSharedRef<FJsonObject>& Out,
		std::initializer_list<const TCHAR*> Fields, const TCHAR* ParamName)
	{
		const FString Arg = KrJStrAny(In, Fields);
		if (Arg.IsEmpty())
		{
			KrFail(Out, FString::Printf(
				TEXT("%s required (the cooked Blueprint: its objectPath, ideally the .<Name>_C class path, e.g. ")
				TEXT("/Game/Animations/AnimClasses/NPC/PrisonerAnimBP.PrisonerAnimBP_C)"), ParamName));
			return nullptr;
		}
		FString Error;
		UBlueprintGeneratedClass* BPGC = KrResolveBPGC(Arg, Error);
		if (!BPGC) { KrFail(Out, Error); }
		return BPGC;
	}

	// --- Small shared JSON shapes ------------------------------------------------------------------

	static bool KrIsCooked(const UObject* Obj)
	{
		const UPackage* Pkg = Obj ? Obj->GetOutermost() : nullptr;
		return Pkg && Pkg->HasAnyPackageFlags(PKG_Cooked);
	}

	static TArray<TSharedPtr<FJsonValue>> KrFunctionFlagNames(EFunctionFlags Flags)
	{
		const uint32 F = (uint32) Flags;
		TArray<TSharedPtr<FJsonValue>> Names;
		auto Add = [&Names](const TCHAR* N) { Names.Add(MakeShared<FJsonValueString>(N)); };
		if (F & (uint32) FUNC_Final)              { Add(TEXT("Final")); }
		if (F & (uint32) FUNC_Native)             { Add(TEXT("Native")); }
		if (F & (uint32) FUNC_Static)             { Add(TEXT("Static")); }
		if (F & (uint32) FUNC_Event)              { Add(TEXT("Event")); }
		if (F & (uint32) FUNC_BlueprintEvent)     { Add(TEXT("BlueprintEvent")); }
		if (F & (uint32) FUNC_BlueprintCallable)  { Add(TEXT("BlueprintCallable")); }
		if (F & (uint32) FUNC_BlueprintPure)      { Add(TEXT("BlueprintPure")); }
		if (F & (uint32) FUNC_Const)              { Add(TEXT("Const")); }
		if (F & (uint32) FUNC_Net)                { Add(TEXT("Net")); }
		if (F & (uint32) FUNC_NetMulticast)       { Add(TEXT("NetMulticast")); }
		if (F & (uint32) FUNC_NetServer)          { Add(TEXT("NetServer")); }
		if (F & (uint32) FUNC_NetClient)          { Add(TEXT("NetClient")); }
		if (F & (uint32) FUNC_Delegate)           { Add(TEXT("Delegate")); }
		if (F & (uint32) FUNC_MulticastDelegate)  { Add(TEXT("MulticastDelegate")); }
		if (F & (uint32) FUNC_UbergraphFunction)  { Add(TEXT("UbergraphFunction")); }
		if (F & (uint32) FUNC_HasOutParms)        { Add(TEXT("HasOutParms")); }
		if (F & (uint32) FUNC_Private)            { Add(TEXT("Private")); }
		if (F & (uint32) FUNC_Protected)          { Add(TEXT("Protected")); }
		if (F & (uint32) FUNC_Public)             { Add(TEXT("Public")); }
		return Names;
	}

	static TArray<TSharedPtr<FJsonValue>> KrPropertyFlagNames(EPropertyFlags Flags)
	{
		const uint64 F = (uint64) Flags;
		TArray<TSharedPtr<FJsonValue>> Names;
		auto Add = [&Names](const TCHAR* N) { Names.Add(MakeShared<FJsonValueString>(N)); };
		if (F & (uint64) CPF_Edit)                { Add(TEXT("Edit")); }
		if (F & (uint64) CPF_BlueprintVisible)    { Add(TEXT("BlueprintVisible")); }
		if (F & (uint64) CPF_BlueprintReadOnly)   { Add(TEXT("BlueprintReadOnly")); }
		if (F & (uint64) CPF_Net)                 { Add(TEXT("Net")); }
		if (F & (uint64) CPF_RepNotify)           { Add(TEXT("RepNotify")); }
		if (F & (uint64) CPF_Transient)           { Add(TEXT("Transient")); }
		if (F & (uint64) CPF_Config)              { Add(TEXT("Config")); }
		if (F & (uint64) CPF_SaveGame)            { Add(TEXT("SaveGame")); }
		if (F & (uint64) CPF_InstancedReference)  { Add(TEXT("InstancedReference")); }
		if (F & (uint64) CPF_Parm)                { Add(TEXT("Parm")); }
		if (F & (uint64) CPF_ReturnParm)          { Add(TEXT("ReturnParm")); }
		if (F & (uint64) CPF_OutParm)             { Add(TEXT("OutParm")); }
		if (F & (uint64) CPF_DisableEditOnInstance) { Add(TEXT("DisableEditOnInstance")); }
		return Names;
	}

	/** CPF_Parm count excluding the return parm — the same denominator FEventEntry::NumParams uses,
	 *  so kr_dump_blueprint's numParams and kr_list_events' numParams are comparable. */
	static int32 KrCountParams(UFunction* Func)
	{
		int32 N = 0;
		if (!Func) { return 0; }
		for (TFieldIterator<FProperty> It(Func); It; ++It)
		{
			const FProperty* P = *It;
			if (P && P->HasAnyPropertyFlags(CPF_Parm) && !P->HasAnyPropertyFlags(CPF_ReturnParm)) { ++N; }
		}
		return N;
	}

	/** Reduce a disassembled statement to {Inst, StatementIndex} for cheap CFG views (includeRaw:false).
	 *  StatementIndex is a BYTE OFFSET into Script, not an ordinal — pagination is by ARRAY index. */
	static TSharedPtr<FJsonValue> KrThinStatement(const TSharedPtr<FJsonValue>& Value)
	{
		const TSharedPtr<FJsonObject>* Obj = nullptr;
		if (!Value.IsValid() || !Value->TryGetObject(Obj) || !Obj || !Obj->IsValid()) { return Value; }
		TSharedRef<FJsonObject> Thin = MakeShared<FJsonObject>();
		FString Inst;
		if ((*Obj)->TryGetStringField(TEXT("Inst"), Inst)) { Thin->SetStringField(TEXT("Inst"), Inst); }
		int32 Index = 0;
		if ((*Obj)->TryGetNumberField(TEXT("StatementIndex"), Index)) { Thin->SetNumberField(TEXT("StatementIndex"), Index); }
		return MakeShared<FJsonValueObject>(Thin);
	}

	/** Opcode histogram as {"0x1F": n, ...}. Keys are HEX, not opcode names, on purpose: the only
	 *  opcode-name table in this plugin is file-static inside the MIF_KR_DEBUG gate, and duplicating a
	 *  ~100-case switch here would be duplicating LOGIC (the thing the ship-safety rule permits copying
	 *  is small DATA). Every statement's own "Inst" field already carries the human-readable name, so
	 *  nothing is lost: the histogram is for counting, the statement stream is for reading. */
	static TSharedRef<FJsonObject> KrHistogramJson(const TMap<uint8, int32>& Histogram, int32& OutTotal)
	{
		TSharedRef<FJsonObject> Obj = MakeShared<FJsonObject>();
		OutTotal = 0;
		for (const TPair<uint8, int32>& KV : Histogram)
		{
			Obj->SetNumberField(FString::Printf(TEXT("0x%02X"), KV.Key), KV.Value);
			OutTotal += KV.Value;
		}
		return Obj;
	}

	/** Up to MaxNames own function names containing Needle — the "did you mean" list on a lookup miss. */
	static TArray<FString> KrNearMissFunctions(UBlueprintGeneratedClass* BPGC, const FString& Needle, int32 MaxNames)
	{
		TArray<FString> Near;
		if (!BPGC || Needle.IsEmpty()) { return Near; }
		for (TFieldIterator<UFunction> It(BPGC, EFieldIteratorFlags::ExcludeSuper); It && Near.Num() < MaxNames; ++It)
		{
			if (UFunction* F = *It)
			{
				if (F->GetName().Contains(Needle)) { Near.Add(F->GetName()); }
			}
		}
		return Near;
	}

	/** FEdGraphPinType terminal → the BRIDGE type-grammar spelling (docs/02_GOTCHAS.md section 2).
	 *  This is a deliberate translation layer, not a duplicate of MifBridge::MakePinType: that function
	 *  parses the grammar and lives in a Private MifBridge TU; this one EMITS it, and the two must agree
	 *  or kr_pin_type_from_property's whole purpose (hand the string straight to add_variable) fails.
	 *  Emission rules, each chosen to be unambiguous on re-parse:
	 *    - float vs double: in UE5 the category is PC_Real and the WIDTH is the subcategory, so read the
	 *      subcategory rather than assuming (getting this wrong yields a 64-bit pin where a UMG
	 *      TAttribute<float> delegate binding needs 32-bit, and the binding silently will not match).
	 *    - enums are emitted WITH the explicit "enum:" prefix even though a bare enum name also parses:
	 *      the parser tries struct before enum before class, so a bare name is order-dependent.
	 *    - object/class/interface refs are emitted as a full PATH, never a short name — a short name
	 *      resolves through FindFirstObject, which is a coin flip when two classes share a name.
	 *  Returns false with OutWhyNot for pin types the grammar genuinely cannot express. */
	static bool KrBridgeTerminalType(const FName& Category, const FName& SubCategory, UObject* SubObject,
		FString& OutType, FString& OutWhyNot)
	{
		auto ClassRef = [&](const TCHAR* Prefix) -> bool
		{
			if (UClass* C = Cast<UClass>(SubObject))
			{
				OutType = FString::Printf(TEXT("%s:%s"), Prefix, *C->GetPathName());
				return true;
			}
			OutWhyNot = FString::Printf(TEXT("'%s' pin has no class in PinSubCategoryObject"), *Category.ToString());
			return false;
		};

		if (Category == UEdGraphSchema_K2::PC_Boolean) { OutType = TEXT("bool");  return true; }
		if (Category == UEdGraphSchema_K2::PC_Int)     { OutType = TEXT("int");   return true; }
		if (Category == UEdGraphSchema_K2::PC_Int64)   { OutType = TEXT("int64"); return true; }
		if (Category == UEdGraphSchema_K2::PC_String)  { OutType = TEXT("string");return true; }
		if (Category == UEdGraphSchema_K2::PC_Name)    { OutType = TEXT("name");  return true; }
		if (Category == UEdGraphSchema_K2::PC_Text)    { OutType = TEXT("text");  return true; }
		if (Category == UEdGraphSchema_K2::PC_Float)   { OutType = TEXT("float"); return true; }
		if (Category == UEdGraphSchema_K2::PC_Double)  { OutType = TEXT("double");return true; }
		if (Category == UEdGraphSchema_K2::PC_Real)
		{
			OutType = (SubCategory == UEdGraphSchema_K2::PC_Float) ? TEXT("float") : TEXT("double");
			return true;
		}
		if (Category == UEdGraphSchema_K2::PC_Byte || Category == UEdGraphSchema_K2::PC_Enum)
		{
			if (UEnum* E = Cast<UEnum>(SubObject))
			{
				OutType = FString::Printf(TEXT("enum:%s"), *E->GetName());
				return true;
			}
			OutType = TEXT("byte");
			return true;
		}
		if (Category == UEdGraphSchema_K2::PC_Struct)
		{
			if (UScriptStruct* S = Cast<UScriptStruct>(SubObject))
			{
				// UScriptStruct::GetName() drops the F prefix ("Vector"), which is exactly the spelling
				// the bridge's struct resolver takes; it also accepts "FVector", so this is safe either way.
				OutType = S->GetName();
				return true;
			}
			OutWhyNot = TEXT("struct pin has no UScriptStruct in PinSubCategoryObject");
			return false;
		}
		if (Category == UEdGraphSchema_K2::PC_Object)     { return ClassRef(TEXT("object")); }
		if (Category == UEdGraphSchema_K2::PC_Class)      { return ClassRef(TEXT("class")); }
		if (Category == UEdGraphSchema_K2::PC_SoftObject) { return ClassRef(TEXT("softobject")); }
		if (Category == UEdGraphSchema_K2::PC_SoftClass)  { return ClassRef(TEXT("softclass")); }
		if (Category == UEdGraphSchema_K2::PC_Interface)  { return ClassRef(TEXT("interface")); }

		if (Category == UEdGraphSchema_K2::PC_Delegate || Category == UEdGraphSchema_K2::PC_MCDelegate)
		{
			OutWhyNot = TEXT("delegate pins have no type-grammar spelling - author them with add_event_dispatcher, not add_variable");
			return false;
		}
		if (Category == UEdGraphSchema_K2::PC_FieldPath)
		{
			OutWhyNot = TEXT("field-path pins have no type-grammar spelling");
			return false;
		}
		if (Category == UEdGraphSchema_K2::PC_Wildcard)
		{
			OutWhyNot = TEXT("wildcard is not a concrete type");
			return false;
		}
		OutWhyNot = FString::Printf(TEXT("unmapped pin category '%s'"), *Category.ToString());
		return false;
	}

	// --- Registry enumeration (reimplemented, ungated) -------------------------------------------

	/** True for the *GeneratedClass half of a Blueprint package (BlueprintGeneratedClass,
	 *  WidgetBlueprintGeneratedClass, AnimBlueprintGeneratedClass, ...). The asset registry lists
	 *  BOTH the UBlueprint and its generated class for the same package; the generated class is the
	 *  half every downstream kr_* endpoint actually wants (its objectPath is the *_C class path that
	 *  resolution takes), so dedup PREFERS it. Name-suffix test rather than a UClass compare: it
	 *  covers the UMG/Anim subclasses without dragging UMGEditor into this module's dependencies —
	 *  the same reason MifUbergraphAnalyzer.cpp:83 uses bRecursiveClasses instead of naming them. */
	static bool IsGeneratedClassAsset(const FAssetData& A)
	{
		return A.AssetClassPath.GetAssetName().ToString().EndsWith(TEXT("GeneratedClass"));
	}

	/** Widget Blueprints arrive through bRecursiveClasses as WidgetBlueprint /
	 *  WidgetBlueprintGeneratedClass — matched by class NAME for the same no-new-dependency reason. */
	static bool IsWidgetAsset(const FAssetData& A)
	{
		return A.AssetClassPath.GetAssetName().ToString().Contains(TEXT("Widget"));
	}

	// --- kr_list_cooked_blueprints ----------------------------------------------------------------
	//   in:  { pathContains?: "/Game/" (aliases: pathFilter, path; "*" = every mounted root),
	//          cookedOnly?: bool (default true), includeWidgets?: bool (default true),
	//          offset?: int (default 0), limit?: int (default 200, max 2000) }
	//        — any other key is rejected BY NAME, never ignored
	//   out: { total, matched, returned, offset, limit, truncated,
	//          blueprints[{ objectPath, packageName, name, class, cooked, loaded, generatedClass }],
	//          filter{pathContains, cookedOnly, includeWidgets}, note }
	//
	// Registry census of cooked Blueprints — the enumeration the analyzer/batch harness does
	// internally, over HTTP, so an agent can size and page the reconstructable corpus instead of
	// guessing from find_assets. Package-deduped and PKG_Cooked-filtered, mirroring the filter at
	// Analysis/MifUbergraphAnalyzer.cpp:84-102 (that is DATA — an FARFilter shape — not logic; the
	// analyzer's own copy is file-static inside #if MIF_KR_DEBUG and unusable here by design).
	//
	// COOKED CONTENT: this endpoint EXISTS for cooked content. Container-only BPGCs (IoStore .utoc
	// packages the modkit premounts) appear exactly like loose assets because the asset registry
	// indexes both; `cooked` reports PKG_Cooked per package, so a mixed project reads honestly.
	// Cooked Blueprints have NO UBlueprint asset at all — only the generated class — which is why
	// dedup keeps the *_C row. Nothing here LOADS anything: it reads the in-memory registry index
	// and reports `loaded` from FAssetData::IsAssetLoaded(), so the call cannot fault a package in,
	// cannot run a construction script, and is safe to page over the whole project.
	static void H_kr_list_cooked_blueprints(const TSharedRef<FJsonObject>& In, const TSharedRef<FJsonObject>& Out)
	{
		if (KrRejectUnknownParams(In, Out,
			{ TEXT("pathContains"), TEXT("pathFilter"), TEXT("path"), TEXT("cookedOnly"),
			  TEXT("includeWidgets"), TEXT("offset"), TEXT("limit") },
			TEXT("pathContains (aliases: pathFilter, path), cookedOnly, includeWidgets, offset, limit"),
			{{ TEXT("pathPrefix"),
			   TEXT("not a parameter here - pathContains is a SUBSTRING match over the package name, not a prefix; pass \"*\" for every mounted root") },
			 { TEXT("nameContains"),
			   TEXT("not implemented - filter on the package path with pathContains, or use MifBridge's find_assets for name search") }}))
		{
			return;
		}

		const FString PathContains = KrJStrAny(In, { TEXT("pathContains"), TEXT("pathFilter"), TEXT("path") }, TEXT("/Game/"));
		const bool bCookedOnly = KrJBool(In, TEXT("cookedOnly"), true);
		const bool bIncludeWidgets = KrJBool(In, TEXT("includeWidgets"), true);
		const int32 Offset = KrJInt(In, TEXT("offset"), 0);
		const int32 Limit = KrJInt(In, TEXT("limit"), 200);
		const bool bAllPaths = (PathContains == TEXT("*"));

		// Explicit refusals rather than silent clamping: a caller who asked for 5000 rows and got 2000
		// with no page cursor would under-report the corpus and never know.
		if (Limit < 1)
		{
			KrFail(Out, FString::Printf(TEXT("limit %d is invalid; pass 1..2000"), Limit));
			return;
		}
		if (Limit > 2000)
		{
			KrFail(Out, FString::Printf(TEXT("limit %d exceeds maximum 2000; page with offset"), Limit));
			return;
		}
		if (Offset < 0)
		{
			KrFail(Out, FString::Printf(TEXT("offset %d is invalid; pass 0 or greater"), Offset));
			return;
		}

		IAssetRegistry& Registry = FModuleManager::LoadModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry")).Get();
		if (Registry.IsLoadingAssets())
		{
			// A partial index would report a smaller corpus with ok:true — the exact silent-wrong-answer
			// class this bridge refuses. Say so instead (IAssetRegistry.h:719).
			KrFail(Out, TEXT("asset registry still scanning; retry after the initial scan completes"));
			return;
		}

		// Filter shape mirrors MifUbergraphAnalyzer.cpp:85-90. bRecursiveClasses covers
		// WidgetBlueprint(GeneratedClass) and AnimBlueprint(GeneratedClass) without a UMG/Anim dep.
		FARFilter Filter;
		Filter.ClassPaths.Add(UBlueprintGeneratedClass::StaticClass()->GetClassPathName());
		Filter.ClassPaths.Add(UBlueprint::StaticClass()->GetClassPathName());
		Filter.bRecursiveClasses = true;

		TArray<FAssetData> Assets;
		Registry.GetAssets(Filter, Assets);

		// Dedup by PACKAGE (the registry lists both halves of an uncooked Blueprint), preferring the
		// generated-class row. `total` counts every Blueprint package the registry knows about,
		// BEFORE any filter, so the caller can tell "my filter is narrow" from "the corpus is small".
		TMap<FName, FAssetData> ByPackage;
		ByPackage.Reserve(Assets.Num());
		for (const FAssetData& A : Assets)
		{
			if (!A.IsValid())
			{
				continue;
			}
			if (FAssetData* Existing = ByPackage.Find(A.PackageName))
			{
				if (!IsGeneratedClassAsset(*Existing) && IsGeneratedClassAsset(A)) { *Existing = A; }
			}
			else
			{
				ByPackage.Add(A.PackageName, A);
			}
		}

		TArray<FAssetData> Matched;
		Matched.Reserve(ByPackage.Num());
		for (const TPair<FName, FAssetData>& KV : ByPackage)
		{
			const FAssetData& A = KV.Value;
			const bool bCooked = (A.PackageFlags & PKG_Cooked) != 0;
			if (bCookedOnly && !bCooked) { continue; }
			if (!bIncludeWidgets && IsWidgetAsset(A)) { continue; }
			if (!bAllPaths && !A.PackageName.ToString().Contains(PathContains)) { continue; }
			Matched.Add(A);
		}

		// Sorted by package name so paging is STABLE and deterministic: consecutive pages neither
		// overlap nor skip, and their counts sum to `matched` (TMap iteration order is not an order).
		Matched.Sort([](const FAssetData& L, const FAssetData& R)
		{
			return L.PackageName.LexicalLess(R.PackageName);
		});

		TArray<TSharedPtr<FJsonValue>> Rows;
		const int32 First = FMath::Min(Offset, Matched.Num());
		const int32 Last = FMath::Min(First + Limit, Matched.Num());
		for (int32 i = First; i < Last; ++i)
		{
			const FAssetData& A = Matched[i];
			TSharedRef<FJsonObject> Row = MakeShared<FJsonObject>();
			Row->SetStringField(TEXT("objectPath"), A.GetObjectPathString());
			Row->SetStringField(TEXT("packageName"), A.PackageName.ToString());
			Row->SetStringField(TEXT("name"), A.AssetName.ToString());
			Row->SetStringField(TEXT("class"), A.AssetClassPath.ToString());
			Row->SetBoolField(TEXT("cooked"), (A.PackageFlags & PKG_Cooked) != 0);
			Row->SetBoolField(TEXT("loaded"), A.IsAssetLoaded());
			// True when objectPath is already the *_C class path a kr_* resolver takes directly.
			Row->SetBoolField(TEXT("generatedClass"), IsGeneratedClassAsset(A));
			Rows.Add(MakeShared<FJsonValueObject>(Row));
		}

		Out->SetNumberField(TEXT("total"), ByPackage.Num());
		Out->SetNumberField(TEXT("matched"), Matched.Num());
		Out->SetNumberField(TEXT("returned"), Rows.Num());
		Out->SetNumberField(TEXT("offset"), Offset);
		Out->SetNumberField(TEXT("limit"), Limit);
		Out->SetBoolField(TEXT("truncated"), Last < Matched.Num());
		Out->SetArrayField(TEXT("blueprints"), Rows);

		TSharedRef<FJsonObject> FilterEcho = MakeShared<FJsonObject>();
		FilterEcho->SetStringField(TEXT("pathContains"), PathContains);
		FilterEcho->SetBoolField(TEXT("cookedOnly"), bCookedOnly);
		FilterEcho->SetBoolField(TEXT("includeWidgets"), bIncludeWidgets);
		Out->SetObjectField(TEXT("filter"), FilterEcho);

		Out->SetStringField(TEXT("note"),
			TEXT("registry-only census: nothing is loaded, so 'loaded' reports current editor state, not reachability. ")
			TEXT("'total' counts every Blueprint package in the registry before filtering; 'matched' is after. ")
			TEXT("Rows are package-deduped and prefer the *_C generated-class path."));

		if (Matched.Num() == 0)
		{
			Out->SetStringField(TEXT("hint"), FString::Printf(
				TEXT("no Blueprint packages match pathContains '%s'%s - pass \"*\" for every mounted root, or cookedOnly:false to include uncooked assets"),
				*PathContains, bCookedOnly ? TEXT(" with cookedOnly:true") : TEXT("")));
		}
	}

	// --- kr_dump_blueprint -------------------------------------------------------------------------
	//   in:  { asset: "/Game/.../BP_Foo.BP_Foo_C" (aliases: sourceAsset, path)  [REQUIRED],
	//          functionFilter?: substring over function names (alias: function),
	//          includeBytecode?: bool (default false; alias: includeStatements),
	//          maxStatementsPerFunction?: int (default 500, max 5000),
	//          includeHistogram?: bool (default true), includeProperties?: bool (default true),
	//          includeEvents?: bool (default true), offset?: int (0), limit?: int (100, max 500) }
	//   out: { class, className, package, cooked, parentChain[], counts{}, offset, limit,
	//          effectiveLimit, truncated, functions[], properties[], propertiesTruncated, events[],
	//          ubergraph{}, opcodeHistogram{}, opcodeHistogramTotal, filter{}, note }
	//
	// The structure of a cooked BPGC as JSON, returned INLINE — no Saved/ files, no log scraping. This
	// is the console dumper's information without its side effects.
	//
	// OUTPUT-SIZE CONTROL IS THE DESIGN CONSTRAINT, not a nicety. A full statement dump of BP_BaseNPC
	// (113 own functions) is megabytes, and this runs on the GAME THREAD inside an HTTP handler, so the
	// editor is stalled for the whole serialization. Three independent brakes:
	//   1. NOTHING is disassembled unless includeBytecode is true. The default response costs one
	//      TFieldIterator pass and reads Script.Num() — no bytecode walk at all, at any size.
	//   2. Disassembly happens ONLY for the functions on the returned PAGE, never for the whole class.
	//   3. includeBytecode with no functionFilter force-caps limit at 10, and says so in `note` +
	//      `effectiveLimit` (an unannounced cap is a silent wrong answer about how much exists).
	// `maxStatementsPerFunction` then truncates each function's array, always reporting
	// totalStatements alongside so the truncation is visible and the real number is still known.
	//
	// COOKED CONTENT: this is the primary target — a pak-mounted BPGC's UFunctions carry live Script
	// arrays in-process. A LOOSE/uncooked Blueprint also works and is not refused: its compiled
	// GeneratedClass holds the same bytecode, so the dump is identical in shape; `cooked:false` says
	// which kind you got. The one real difference is that an uncooked Blueprint that has never been
	// compiled this session gets compiled by the load, so scriptBytes reflects the CURRENT graphs.
	// Resolution LOADS the package (unlike kr_list_cooked_blueprints, which loads nothing).
	static void H_kr_dump_blueprint(const TSharedRef<FJsonObject>& In, const TSharedRef<FJsonObject>& Out)
	{
		if (KrRejectUnknownParams(In, Out,
			{ TEXT("asset"), TEXT("sourceAsset"), TEXT("path"), TEXT("functionFilter"), TEXT("function"),
			  TEXT("includeBytecode"), TEXT("includeStatements"), TEXT("maxStatementsPerFunction"),
			  TEXT("includeHistogram"), TEXT("includeProperties"), TEXT("includeEvents"),
			  TEXT("offset"), TEXT("limit") },
			TEXT("asset (aliases: sourceAsset, path), functionFilter (alias: function), includeBytecode ")
			TEXT("(alias: includeStatements), maxStatementsPerFunction, includeHistogram, includeProperties, ")
			TEXT("includeEvents, offset, limit"),
			{{ TEXT("includeInherited"),
			   TEXT("not a parameter - this endpoint reports OWN members only (ExcludeSuper); walk parentChain[] and call it again on a parent class") },
			 { TEXT("save"),
			   TEXT("not implemented - the dump is returned inline; nothing is ever written to Saved/") }}))
		{
			return;
		}

		UBlueprintGeneratedClass* BPGC = KrResolveBPGCStrict(In, Out, { TEXT("asset"), TEXT("sourceAsset"), TEXT("path") }, TEXT("asset"));
		if (!BPGC) { return; }

		const FString FunctionFilter = KrJStrAny(In, { TEXT("functionFilter"), TEXT("function") });
		const bool bIncludeBytecode = KrJBool(In, TEXT("includeBytecode"), KrJBool(In, TEXT("includeStatements"), false));
		const int32 MaxStatements = KrJInt(In, TEXT("maxStatementsPerFunction"), 500);
		const bool bIncludeHistogram = KrJBool(In, TEXT("includeHistogram"), true);
		const bool bIncludeProperties = KrJBool(In, TEXT("includeProperties"), true);
		const bool bIncludeEvents = KrJBool(In, TEXT("includeEvents"), true);
		const int32 Offset = KrJInt(In, TEXT("offset"), 0);
		const int32 Limit = KrJInt(In, TEXT("limit"), 100);

		if (KrRejectPaging(Out, Offset, Limit, 500, TEXT("offset"), TEXT("limit"))) { return; }
		if (MaxStatements < 1 || MaxStatements > 5000)
		{
			KrFail(Out, FString::Printf(TEXT("maxStatementsPerFunction %d is invalid; pass 1..5000"), MaxStatements));
			return;
		}

		// Raw cooked UFunction*/UStruct* are read below; hold GC for the whole pass exactly as the
		// analyzer does (nothing is LOADED inside the guard — resolution already happened).
		FGCScopeGuard GcLock;

		UFunction* UberFunc = BPGC->UberGraphFunction;

		// --- enumerate own functions (metadata only; no disassembly here) ---
		struct FFnRow { UFunction* Func = nullptr; FString Name; };
		TArray<FFnRow> AllFns;
		int32 FunctionsWithBytecode = 0;
		for (TFieldIterator<UFunction> It(BPGC, EFieldIteratorFlags::ExcludeSuper); It; ++It)
		{
			UFunction* Func = *It;
			if (!Func) { continue; }
			FFnRow Row;
			Row.Func = Func;
			Row.Name = Func->GetName();
			if (Func->Script.Num() > 0) { ++FunctionsWithBytecode; }
			AllFns.Add(MoveTemp(Row));
		}
		// Sorted by name so paging is stable: consecutive pages neither overlap nor skip.
		AllFns.Sort([](const FFnRow& L, const FFnRow& R) { return L.Name < R.Name; });

		TArray<FFnRow> Matched;
		Matched.Reserve(AllFns.Num());
		for (const FFnRow& Row : AllFns)
		{
			if (!FunctionFilter.IsEmpty() && !Row.Name.Contains(FunctionFilter)) { continue; }
			Matched.Add(Row);
		}

		// Brake 3. Announced, never silent.
		int32 EffectiveLimit = Limit;
		bool bLimitCapped = false;
		if (bIncludeBytecode && FunctionFilter.IsEmpty() && EffectiveLimit > 10)
		{
			EffectiveLimit = 10;
			bLimitCapped = true;
		}

		const int32 First = FMath::Min(Offset, Matched.Num());
		const int32 Last = FMath::Min(First + EffectiveLimit, Matched.Num());

		TMap<uint8, int32> AggHistogram;
		int32 FunctionsDisassembled = 0, FunctionsDisassemblyFailed = 0, StatementsDisassembled = 0;

		TArray<TSharedPtr<FJsonValue>> FnRows;
		for (int32 i = First; i < Last; ++i)
		{
			UFunction* Func = Matched[i].Func;
			TSharedRef<FJsonObject> Row = MakeShared<FJsonObject>();
			Row->SetStringField(TEXT("name"), Matched[i].Name);
			Row->SetNumberField(TEXT("scriptBytes"), Func->Script.Num());
			Row->SetBoolField(TEXT("hasBytecode"), Func->Script.Num() > 0);
			Row->SetNumberField(TEXT("numParams"), KrCountParams(Func));
			Row->SetBoolField(TEXT("isUbergraph"), Func == UberFunc || Func->HasAnyFunctionFlags(FUNC_UbergraphFunction));
			Row->SetBoolField(TEXT("isEvent"), Func->HasAnyFunctionFlags(FUNC_Event));
			Row->SetBoolField(TEXT("isDelegate"), Func->HasAnyFunctionFlags(FUNC_Delegate | FUNC_MulticastDelegate));
			Row->SetStringField(TEXT("flagsHex"), FString::Printf(TEXT("0x%08X"), (uint32) Func->FunctionFlags));
			Row->SetArrayField(TEXT("flags"), KrFunctionFlagNames(Func->FunctionFlags));

			if (bIncludeBytecode)
			{
				if (Func->Script.Num() == 0)
				{
					// Not an error: a stub / interface shell / BlueprintImplementableEvent legitimately
					// has no bytecode. Say so per function rather than failing the whole dump.
					Row->SetNumberField(TEXT("totalStatements"), 0);
					Row->SetBoolField(TEXT("disassemblyFailed"), false);
					Row->SetStringField(TEXT("statementsNote"), TEXT("no bytecode (Script.Num()==0) - stub, interface shell or BlueprintImplementableEvent"));
				}
				else
				{
					FKismetBytecodeDisassemblerJson Dis;
					TArray<TSharedPtr<FJsonValue>> Statements = Dis.SerializeFunction(Func);
					++FunctionsDisassembled;
					StatementsDisassembled += Statements.Num();
					for (const TPair<uint8, int32>& KV : Dis.OpcodeHistogram) { AggHistogram.FindOrAdd(KV.Key) += KV.Value; }

					const int32 TotalStatements = Statements.Num();
					Row->SetNumberField(TEXT("totalStatements"), TotalStatements);
					Row->SetBoolField(TEXT("disassemblyFailed"), Dis.bDisassemblyFailed);
					if (Dis.bDisassemblyFailed)
					{
						++FunctionsDisassemblyFailed;
						Row->SetNumberField(TEXT("failedOpcode"), Dis.FailedOpcode);
						Row->SetStringField(TEXT("failedOpcodeHex"), FString::Printf(TEXT("0x%02X"), Dis.FailedOpcode));
						Row->SetNumberField(TEXT("failedAtIndex"), Dis.FailedAtIndex);
					}

					const int32 Keep = FMath::Min(MaxStatements, TotalStatements);
					if (Keep < TotalStatements) { Statements.SetNum(Keep); }
					Row->SetNumberField(TEXT("returnedStatements"), Statements.Num());
					Row->SetBoolField(TEXT("statementsTruncated"), Keep < TotalStatements);
					Row->SetArrayField(TEXT("statements"), Statements);
				}
			}
			FnRows.Add(MakeShared<FJsonValueObject>(Row));
		}

		// --- parent chain (own class excluded; nearest ancestor first) ---
		TArray<TSharedPtr<FJsonValue>> ParentChain;
		for (UClass* Super = BPGC->GetSuperClass(); Super; Super = Super->GetSuperClass())
		{
			TSharedRef<FJsonObject> Row = MakeShared<FJsonObject>();
			Row->SetStringField(TEXT("class"), Super->GetPathName());
			Row->SetStringField(TEXT("name"), Super->GetName());
			// Cast<>, not IsA: UClass DELIBERATELY hides IsA as private (Class.h:3488-3495 —
			// "calling IsA on a class almost always indicates an error where the caller should use
			// IsChildOf"), so no form of IsA compiles on a UClass*. IsChildOf is NOT the substitute
			// here: it asks whether the class DERIVES from X, whereas this row asks whether the class
			// OBJECT ITSELF is a UBlueprintGeneratedClass (i.e. its metaclass) — a different question
			// that Cast<> answers directly.
			Row->SetBoolField(TEXT("blueprintClass"), Cast<UBlueprintGeneratedClass>(Super) != nullptr);
			Row->SetBoolField(TEXT("cooked"), KrIsCooked(Super));
			ParentChain.Add(MakeShared<FJsonValueObject>(Row));
		}

		// --- own properties ---
		int32 PropertiesOwn = 0;
		TArray<TSharedPtr<FJsonValue>> PropRows;
		bool bPropertiesTruncated = false;
		{
			for (TFieldIterator<FProperty> It(BPGC, EFieldIteratorFlags::ExcludeSuper); It; ++It)
			{
				const FProperty* P = *It;
				if (!P) { continue; }
				++PropertiesOwn;
				if (!bIncludeProperties) { continue; }
				if (PropRows.Num() >= 500) { bPropertiesTruncated = true; continue; }
				TSharedRef<FJsonObject> Row = MakeShared<FJsonObject>();
				Row->SetStringField(TEXT("name"), P->GetName());
				Row->SetStringField(TEXT("cppType"), P->GetCPPType());
				Row->SetStringField(TEXT("propertyClass"), P->GetClass() ? P->GetClass()->GetName() : TEXT("?"));
				Row->SetArrayField(TEXT("flags"), KrPropertyFlagNames(P->GetPropertyFlags()));
				PropRows.Add(MakeShared<FJsonValueObject>(Row));
			}
		}

		// --- event census (flag-based, cheap) ---
		// FUNC_Event on an own function. This is a CHEAP classification, deliberately NOT the
		// authoritative one: proving a thunk really enters the ubergraph requires disassembling it and
		// identity-matching the call, which is exactly what kr_list_events does. Both numbers are
		// reported so a disagreement is visible instead of hidden behind one of them.
		int32 EventsOwn = 0;
		TArray<TSharedPtr<FJsonValue>> EventRows;
		for (const FFnRow& Row : AllFns)
		{
			if (!Row.Func->HasAnyFunctionFlags(FUNC_Event)) { continue; }
			if (Row.Func->HasAnyFunctionFlags(FUNC_UbergraphFunction)) { continue; }
			++EventsOwn;
			if (!bIncludeEvents) { continue; }
			TSharedRef<FJsonObject> E = MakeShared<FJsonObject>();
			E->SetStringField(TEXT("name"), Row.Name);
			E->SetStringField(TEXT("kind"), MifUber::KindName(MifUber::ClassifyEvent(Row.Name)));
			E->SetNumberField(TEXT("numParams"), KrCountParams(Row.Func));
			E->SetNumberField(TEXT("scriptBytes"), Row.Func->Script.Num());
			EventRows.Add(MakeShared<FJsonValueObject>(E));
		}

		Out->SetStringField(TEXT("class"), BPGC->GetPathName());
		Out->SetStringField(TEXT("className"), BPGC->GetName());
		Out->SetStringField(TEXT("package"), BPGC->GetOutermost() ? BPGC->GetOutermost()->GetName() : FString());
		Out->SetBoolField(TEXT("cooked"), KrIsCooked(BPGC));
		Out->SetArrayField(TEXT("parentChain"), ParentChain);

		TSharedRef<FJsonObject> Counts = MakeShared<FJsonObject>();
		Counts->SetNumberField(TEXT("functionsOwn"), AllFns.Num());
		Counts->SetNumberField(TEXT("functionsWithBytecode"), FunctionsWithBytecode);
		Counts->SetNumberField(TEXT("functionsMatched"), Matched.Num());
		Counts->SetNumberField(TEXT("functionsReturned"), FnRows.Num());
		Counts->SetNumberField(TEXT("functionsDisassembled"), FunctionsDisassembled);
		Counts->SetNumberField(TEXT("functionsDisassemblyFailed"), FunctionsDisassemblyFailed);
		Counts->SetNumberField(TEXT("statementsDisassembled"), StatementsDisassembled);
		Counts->SetNumberField(TEXT("propertiesOwn"), PropertiesOwn);
		Counts->SetNumberField(TEXT("propertiesReturned"), PropRows.Num());
		Counts->SetNumberField(TEXT("eventsOwn"), EventsOwn);
		Counts->SetNumberField(TEXT("parentChainDepth"), ParentChain.Num());
		Out->SetObjectField(TEXT("counts"), Counts);

		Out->SetNumberField(TEXT("offset"), Offset);
		Out->SetNumberField(TEXT("limit"), Limit);
		Out->SetNumberField(TEXT("effectiveLimit"), EffectiveLimit);
		Out->SetBoolField(TEXT("truncated"), Last < Matched.Num());
		Out->SetArrayField(TEXT("functions"), FnRows);
		Out->SetArrayField(TEXT("properties"), PropRows);
		Out->SetBoolField(TEXT("propertiesTruncated"), bPropertiesTruncated);
		Out->SetArrayField(TEXT("events"), EventRows);

		TSharedRef<FJsonObject> Uber = MakeShared<FJsonObject>();
		Uber->SetBoolField(TEXT("present"), UberFunc != nullptr);
		if (UberFunc)
		{
			Uber->SetStringField(TEXT("name"), UberFunc->GetName());
			Uber->SetNumberField(TEXT("scriptBytes"), UberFunc->Script.Num());
		}
		Out->SetObjectField(TEXT("ubergraph"), Uber);

		if (bIncludeHistogram)
		{
			int32 HistTotal = 0;
			TSharedRef<FJsonObject> Hist = KrHistogramJson(AggHistogram, HistTotal);
			Out->SetObjectField(TEXT("opcodeHistogram"), Hist);
			Out->SetNumberField(TEXT("opcodeHistogramTotal"), HistTotal);
		}

		TSharedRef<FJsonObject> FilterEcho = MakeShared<FJsonObject>();
		FilterEcho->SetStringField(TEXT("functionFilter"), FunctionFilter);
		FilterEcho->SetBoolField(TEXT("includeBytecode"), bIncludeBytecode);
		FilterEcho->SetNumberField(TEXT("maxStatementsPerFunction"), MaxStatements);
		FilterEcho->SetBoolField(TEXT("includeHistogram"), bIncludeHistogram);
		FilterEcho->SetBoolField(TEXT("includeProperties"), bIncludeProperties);
		FilterEcho->SetBoolField(TEXT("includeEvents"), bIncludeEvents);
		Out->SetObjectField(TEXT("filter"), FilterEcho);

		FString Note =
			TEXT("OWN members only (ExcludeSuper) - inherited members live on the classes in parentChain[]. ")
			TEXT("counts.functionsOwn is the whole class; functionsMatched is after functionFilter; functionsReturned is this page. ")
			TEXT("opcodeHistogram keys are HEX opcodes and it covers ONLY the functions disassembled on this page ")
			TEXT("(zero when includeBytecode is false); each statement's 'Inst' field carries the readable opcode name. ")
			TEXT("events[] is the cheap FUNC_Event classification - kr_list_events is the authoritative one (it disassembles each thunk).");
		if (bLimitCapped)
		{
			Note += FString::Printf(
				TEXT(" LIMIT CAPPED: includeBytecode with no functionFilter caps limit at 10 (requested %d, used %d) - ")
				TEXT("a full statement dump of a large class is megabytes and this call stalls the game thread while it serializes. ")
				TEXT("Pass functionFilter, or page with offset."), Limit, EffectiveLimit);
		}
		Out->SetStringField(TEXT("note"), Note);

		if (Matched.Num() == 0 && !FunctionFilter.IsEmpty())
		{
			TArray<FString> Near = KrNearMissFunctions(BPGC, FunctionFilter.Left(4), 10);
			Out->SetStringField(TEXT("hint"), FString::Printf(
				TEXT("no own function name contains '%s' (%d own functions exist)%s"),
				*FunctionFilter, AllFns.Num(),
				Near.Num() > 0 ? *FString::Printf(TEXT(" - nearest: %s"), *FString::Join(Near, TEXT(", "))) : TEXT("")));
		}
	}

	// --- kr_disassemble_function -------------------------------------------------------------------
	//   in:  { asset [REQUIRED] (aliases: sourceAsset, path), function [REQUIRED] (alias: functionName),
	//          statementOffset?: int (0, alias: offset), statementLimit?: int (2000, max 5000, alias: limit),
	//          includeRaw?: bool (default true) }
	//   out: { class, function, scriptBytes, totalStatements, returned, statementOffset, statementLimit,
	//          truncated, disassemblyFailed, failedOpcode?, failedAtIndex?, opcodeHistogram{},
	//          opcodeHistogramTotal, statements[], note }
	//
	// THE FLAGSHIP. One cooked function's Kismet bytecode as a structured JSON statement stream, over
	// HTTP, in one call. This closes docs/02_GOTCHAS.md section 3, which today tells agents that cooked
	// Blueprint logic is only readable by shelling out to run_console + mif.kr.DumpBP and then scraping
	// files out of Saved/ — a debug-gated console command that will not exist in a shipping build.
	//
	// PAGINATION IS BY ARRAY INDEX, byte offsets are DATA. Each statement's `StatementIndex` field is a
	// BYTE OFFSET into Script (KismetBytecodeDisassemblerJson.cpp:959-961), not an ordinal, and jump
	// targets are expressed in those offsets. statementOffset/statementLimit index the STATEMENT ARRAY.
	// Conflating the two silently produces a stream that starts mid-instruction, so both are named
	// explicitly and totalStatements is always returned, paginated or not.
	//
	// COOKED CONTENT: primary target. A LOOSE/uncooked Blueprint works identically (its compiled class
	// carries the same Script), which makes an authored testbed BP a valid control when a cooked result
	// looks wrong. Resolution LOADS the package.
	static void H_kr_disassemble_function(const TSharedRef<FJsonObject>& In, const TSharedRef<FJsonObject>& Out)
	{
		if (KrRejectUnknownParams(In, Out,
			{ TEXT("asset"), TEXT("sourceAsset"), TEXT("path"), TEXT("function"), TEXT("functionName"),
			  TEXT("statementOffset"), TEXT("offset"), TEXT("statementLimit"), TEXT("limit"), TEXT("includeRaw") },
			TEXT("asset (aliases: sourceAsset, path), function (alias: functionName), statementOffset ")
			TEXT("(alias: offset), statementLimit (alias: limit), includeRaw"),
			{{ TEXT("byteOffset"),
			   TEXT("not a parameter - statementOffset indexes the STATEMENT ARRAY; the byte offsets appear as each statement's StatementIndex field") },
			 { TEXT("includeInherited"),
			   TEXT("not a parameter - lookup is ExcludeSuper; call this endpoint on the parent class named in the error instead") }}))
		{
			return;
		}

		UBlueprintGeneratedClass* BPGC = KrResolveBPGCStrict(In, Out, { TEXT("asset"), TEXT("sourceAsset"), TEXT("path") }, TEXT("asset"));
		if (!BPGC) { return; }

		const FString FunctionName = KrJStrAny(In, { TEXT("function"), TEXT("functionName") });
		if (FunctionName.IsEmpty())
		{
			KrFail(Out, TEXT("function required (exact name of an OWN function on the class; list them with kr_dump_blueprint)"));
			return;
		}

		const int32 StatementOffset = KrJIntAny(In, { TEXT("statementOffset"), TEXT("offset") }, 0);
		const int32 StatementLimit = KrJIntAny(In, { TEXT("statementLimit"), TEXT("limit") }, 2000);
		const bool bIncludeRaw = KrJBool(In, TEXT("includeRaw"), true);
		if (KrRejectPaging(Out, StatementOffset, StatementLimit, 5000, TEXT("statementOffset"), TEXT("statementLimit"))) { return; }

		FGCScopeGuard GcLock;

		UFunction* Func = BPGC->FindFunctionByName(FName(*FunctionName), EIncludeSuperFlag::ExcludeSuper);
		if (!Func)
		{
			// Distinguish "does not exist" from "exists, but on a parent" — they need different fixes.
			UFunction* Inherited = BPGC->FindFunctionByName(FName(*FunctionName), EIncludeSuperFlag::IncludeSuper);
			if (Inherited)
			{
				UClass* Owner = Inherited->GetOwnerClass();
				KrFail(Out, FString::Printf(
					TEXT("function '%s' is INHERITED, not own to %s - its bytecode belongs to %s; call kr_disassemble_function with asset '%s'"),
					*FunctionName, *BPGC->GetName(),
					Owner ? *Owner->GetName() : TEXT("its parent"),
					Owner ? *Owner->GetPathName() : TEXT("<parent class path>")));
				return;
			}
			const TArray<FString> Near = KrNearMissFunctions(BPGC, FunctionName.Left(FMath::Min(5, FunctionName.Len())), 10);
			KrFail(Out, FString::Printf(
				TEXT("function '%s' not found on %s (own functions only)%s - list every own function with kr_dump_blueprint"),
				*FunctionName, *BPGC->GetName(),
				Near.Num() > 0 ? *FString::Printf(TEXT("; nearest own names: %s"), *FString::Join(Near, TEXT(", "))) : TEXT("")));
			return;
		}
		if (Func->Script.Num() == 0)
		{
			KrFail(Out, FString::Printf(
				TEXT("'%s' has no bytecode (Script.Num()==0) - it is a stub, an interface shell or a BlueprintImplementableEvent declaration; there is nothing to disassemble"),
				*FunctionName));
			return;
		}

		FKismetBytecodeDisassemblerJson Dis;
		TArray<TSharedPtr<FJsonValue>> Statements = Dis.SerializeFunction(Func);
		const int32 Total = Statements.Num();

		const int32 First = FMath::Min(StatementOffset, Total);
		const int32 Last = FMath::Min(First + StatementLimit, Total);
		TArray<TSharedPtr<FJsonValue>> Page;
		Page.Reserve(Last - First);
		for (int32 i = First; i < Last; ++i)
		{
			Page.Add(bIncludeRaw ? Statements[i] : KrThinStatement(Statements[i]));
		}

		Out->SetStringField(TEXT("class"), BPGC->GetPathName());
		Out->SetStringField(TEXT("className"), BPGC->GetName());
		Out->SetBoolField(TEXT("cooked"), KrIsCooked(BPGC));
		Out->SetStringField(TEXT("function"), Func->GetName());
		Out->SetNumberField(TEXT("scriptBytes"), Func->Script.Num());
		Out->SetNumberField(TEXT("numParams"), KrCountParams(Func));
		Out->SetArrayField(TEXT("functionFlags"), KrFunctionFlagNames(Func->FunctionFlags));
		Out->SetNumberField(TEXT("totalStatements"), Total);
		Out->SetNumberField(TEXT("returned"), Page.Num());
		Out->SetNumberField(TEXT("statementOffset"), StatementOffset);
		Out->SetNumberField(TEXT("statementLimit"), StatementLimit);
		Out->SetBoolField(TEXT("truncated"), Last < Total);
		Out->SetBoolField(TEXT("includeRaw"), bIncludeRaw);
		Out->SetBoolField(TEXT("disassemblyFailed"), Dis.bDisassemblyFailed);
		if (Dis.bDisassemblyFailed)
		{
			// A DEGRADE, not an endpoint error: every statement decoded before the abort is returned,
			// which is what makes an unknown opcode diagnosable instead of merely fatal.
			Out->SetNumberField(TEXT("failedOpcode"), Dis.FailedOpcode);
			Out->SetStringField(TEXT("failedOpcodeHex"), FString::Printf(TEXT("0x%02X"), Dis.FailedOpcode));
			Out->SetNumberField(TEXT("failedAtIndex"), Dis.FailedAtIndex);
		}
		Out->SetArrayField(TEXT("statements"), Page);

		int32 HistTotal = 0;
		Out->SetObjectField(TEXT("opcodeHistogram"), KrHistogramJson(Dis.OpcodeHistogram, HistTotal));
		Out->SetNumberField(TEXT("opcodeHistogramTotal"), HistTotal);

		Out->SetStringField(TEXT("note"),
			TEXT("statementOffset/statementLimit index the STATEMENT ARRAY; each statement's StatementIndex field is a ")
			TEXT("BYTE OFFSET into Script (that is what jump targets reference). totalStatements is the full count ")
			TEXT("whether or not the response is paginated, so pages concatenate exactly. ")
			TEXT("disassemblyFailed:true means an unknown opcode aborted the walk - every statement before it is still ")
			TEXT("returned and failedAtIndex is the byte where it stopped."));
	}

	// --- shared by kr_list_events and kr_analyze_ubergraph -----------------------------------------
	// The thunk-enumeration rule, in ONE place so the two endpoints can never disagree about what an
	// event is. Mirrors the analyzer's filter: skip the ubergraph itself, skip delegates, skip anything
	// with no bytecode, then RecoverEvent. A thunk whose Status is "no-ubergraph-call" is a REAL
	// FUNCTION, not a failed event — counting it as a failure would manufacture a failure rate out of
	// ordinary functions.
	struct FKrEventScan
	{
		TArray<MifUber::FEventEntry> Events;
		int32 RealFunctions = 0;     // own functions that call no ubergraph
		int32 RawPtrHits = 0;        // memcmp prefilter would have matched but identity did not
		int32 IdentityCalls = 0;
	};

	static void KrScanEvents(UBlueprintGeneratedClass* BPGC, UFunction* UberFunc, FKrEventScan& Out)
	{
		if (!BPGC || !UberFunc) { return; }
		for (TFieldIterator<UFunction> It(BPGC, EFieldIteratorFlags::ExcludeSuper); It; ++It)
		{
			UFunction* Func = *It;
			if (!Func || Func == UberFunc) { continue; }
			if (Func->HasAnyFunctionFlags(FUNC_Delegate | FUNC_UbergraphFunction)) { continue; }
			if (Func->Script.Num() == 0) { continue; }

			MifUber::FEventEntry Info;
			const bool bOk = MifUber::RecoverEvent(Func, UberFunc, Info);
			if (!bOk && Info.Status == TEXT("no-ubergraph-call"))
			{
				++Out.RealFunctions;
				Out.RawPtrHits += Info.RawPtrHits;
				continue;
			}
			Out.RawPtrHits += Info.RawPtrHits;
			Out.IdentityCalls += Info.IdentityCalls;
			Out.Events.Add(MoveTemp(Info));
		}
	}

	/** Accepted `kind` filter values, matching MifUber::EEventKind + "all". */
	static bool KrParseEventKind(const FString& Kind, bool& bOutAll, MifUber::EEventKind& OutKind)
	{
		bOutAll = false;
		if (Kind.IsEmpty() || Kind.Equals(TEXT("all"), ESearchCase::IgnoreCase)) { bOutAll = true; return true; }
		if (Kind.Equals(TEXT("event"), ESearchCase::IgnoreCase))          { OutKind = MifUber::EEventKind::Event; return true; }
		if (Kind.Equals(TEXT("bndEvt"), ESearchCase::IgnoreCase))         { OutKind = MifUber::EEventKind::BndEvt; return true; }
		if (Kind.Equals(TEXT("inpActEvt"), ESearchCase::IgnoreCase))      { OutKind = MifUber::EEventKind::InpActEvt; return true; }
		if (Kind.Equals(TEXT("sequenceEvent"), ESearchCase::IgnoreCase))  { OutKind = MifUber::EEventKind::SequenceEvent; return true; }
		return false;
	}

	static TSharedRef<FJsonObject> KrEventJson(const MifUber::FEventEntry& E, bool bIncludeFrameParamMap)
	{
		TSharedRef<FJsonObject> Row = MakeShared<FJsonObject>();
		Row->SetStringField(TEXT("name"), E.Name);
		Row->SetStringField(TEXT("kind"), MifUber::KindName(E.Kind));
		Row->SetNumberField(TEXT("entryOffset"), E.EntryOffset);
		Row->SetNumberField(TEXT("numParams"), E.NumParams);
		Row->SetNumberField(TEXT("frameLets"), E.FrameLets);
		Row->SetNumberField(TEXT("rawPtrHits"), E.RawPtrHits);
		Row->SetNumberField(TEXT("identityCalls"), E.IdentityCalls);
		Row->SetStringField(TEXT("fastCall"), E.FastCall);
		Row->SetStringField(TEXT("status"), E.Status);
		Row->SetBoolField(TEXT("recovered"), E.bRecovered);
		if (bIncludeFrameParamMap)
		{
			// The AUTHORITATIVE frame→param map, read out of the thunk's own
			// EX_LetValueOnPersistentFrame statements. The generated frame property name is
			// <DescriptiveCompiledName>_<PinName> uniquified with numeric postfixes — it must be READ,
			// never reconstructed, which is exactly why it is surfaced here.
			TArray<TSharedPtr<FJsonValue>> Map;
			for (const TPair<FName, FName>& KV : E.FrameParamMap)
			{
				TSharedRef<FJsonObject> Pair = MakeShared<FJsonObject>();
				Pair->SetStringField(TEXT("frameProperty"), KV.Key.ToString());
				Pair->SetStringField(TEXT("eventPin"), KV.Value.ToString());
				Map.Add(MakeShared<FJsonValueObject>(Pair));
			}
			Row->SetArrayField(TEXT("frameParamMap"), Map);
			Row->SetNumberField(TEXT("frameParamMapped"), E.FrameParamMap.Num());
		}
		return Row;
	}

	// --- kr_list_events ----------------------------------------------------------------------------
	//   in:  { asset [REQUIRED] (aliases: sourceAsset, path),
	//          kind?: all|event|bndEvt|inpActEvt|sequenceEvent (default all),
	//          includeFrameParamMap?: bool (default true) }
	//   out: { class, cooked, status, ubergraph{}, counts{}, byKind{}, events[], filter{}, note }
	//
	// The cooked class's event census: every event thunk with its kind, its RECOVERED ubergraph entry
	// offset, its parameter count, and the authoritative frame→param map — the data needed to reason
	// about event wiring without reconstructing anything.
	//
	// NO UBERGRAPH IS NOT AN ERROR. A Blueprint with functions but no event graph returns ok:true with
	// events:[] and status:"NO_UBERGRAPH" (the analyzer treats this as a normal outcome, not a
	// failure). Same for NO_BYTECODE. Turning either into an HTTP error would make "this BP has no
	// events" indistinguishable from "the call broke".
	//
	// COOKED CONTENT: primary target — on a cooked class the event BODIES exist only as
	// thunk + ubergraph, which is precisely what this reads. A LOOSE/uncooked Blueprint's compiled
	// class has the same shape and works identically; on it the same information is also available
	// through MifBridge's ordinary list_nodes/list_graphs, so this endpoint is redundant there rather
	// than wrong.
	static void H_kr_list_events(const TSharedRef<FJsonObject>& In, const TSharedRef<FJsonObject>& Out)
	{
		if (KrRejectUnknownParams(In, Out,
			{ TEXT("asset"), TEXT("sourceAsset"), TEXT("path"), TEXT("kind"), TEXT("includeFrameParamMap") },
			TEXT("asset (aliases: sourceAsset, path), kind, includeFrameParamMap"),
			{{ TEXT("includeUnrecovered"),
			   TEXT("not a parameter - unrecovered events are ALWAYS listed, with recovered:false and a status reason; hiding them would understate the event count") }}))
		{
			return;
		}

		UBlueprintGeneratedClass* BPGC = KrResolveBPGCStrict(In, Out, { TEXT("asset"), TEXT("sourceAsset"), TEXT("path") }, TEXT("asset"));
		if (!BPGC) { return; }

		const FString KindArg = KrJStrAny(In, { TEXT("kind") }, TEXT("all"));
		bool bAllKinds = true;
		MifUber::EEventKind WantKind = MifUber::EEventKind::Event;
		if (!KrParseEventKind(KindArg, bAllKinds, WantKind))
		{
			KrFail(Out, FString::Printf(
				TEXT("kind '%s' is not recognised; pass one of: all, event, bndEvt, inpActEvt, sequenceEvent"), *KindArg));
			return;
		}
		const bool bIncludeFrameParamMap = KrJBool(In, TEXT("includeFrameParamMap"), true);

		Out->SetStringField(TEXT("class"), BPGC->GetPathName());
		Out->SetStringField(TEXT("className"), BPGC->GetName());
		Out->SetBoolField(TEXT("cooked"), KrIsCooked(BPGC));

		TSharedRef<FJsonObject> FilterEcho = MakeShared<FJsonObject>();
		FilterEcho->SetStringField(TEXT("kind"), bAllKinds ? TEXT("all") : MifUber::KindName(WantKind));
		FilterEcho->SetBoolField(TEXT("includeFrameParamMap"), bIncludeFrameParamMap);
		Out->SetObjectField(TEXT("filter"), FilterEcho);

		FGCScopeGuard GcLock;
		UFunction* UberFunc = BPGC->UberGraphFunction;

		TSharedRef<FJsonObject> Uber = MakeShared<FJsonObject>();
		Uber->SetBoolField(TEXT("present"), UberFunc != nullptr);
		if (UberFunc)
		{
			Uber->SetStringField(TEXT("name"), UberFunc->GetName());
			Uber->SetNumberField(TEXT("scriptBytes"), UberFunc->Script.Num());
		}
		Out->SetObjectField(TEXT("ubergraph"), Uber);

		if (!UberFunc || UberFunc->Script.Num() == 0)
		{
			Out->SetStringField(TEXT("status"), UberFunc ? TEXT("NO_BYTECODE") : TEXT("NO_UBERGRAPH"));
			Out->SetArrayField(TEXT("events"), TArray<TSharedPtr<FJsonValue>>());
			TSharedRef<FJsonObject> Zero = MakeShared<FJsonObject>();
			Zero->SetNumberField(TEXT("events"), 0);
			Zero->SetNumberField(TEXT("returned"), 0);
			Zero->SetNumberField(TEXT("recovered"), 0);
			Zero->SetNumberField(TEXT("failed"), 0);
			Zero->SetNumberField(TEXT("realFunctions"), 0);
			Out->SetObjectField(TEXT("counts"), Zero);
			Out->SetStringField(TEXT("note"), UberFunc
				? TEXT("ok, not an error: the class HAS an UberGraphFunction but it carries no bytecode, so there are no event bodies to enumerate.")
				: TEXT("ok, not an error: this class has NO UberGraphFunction - it has functions only, no event graph. An empty events[] here means 'no events', not 'lookup failed'."));
			return;
		}

		FKrEventScan Scan;
		KrScanEvents(BPGC, UberFunc, Scan);

		int32 Recovered = 0, Failed = 0;
		TMap<FString, int32> ByKind;
		TArray<TSharedPtr<FJsonValue>> Rows;
		for (const MifUber::FEventEntry& E : Scan.Events)
		{
			if (E.bRecovered) { ++Recovered; } else { ++Failed; }
			ByKind.FindOrAdd(MifUber::KindName(E.Kind))++;
			if (!bAllKinds && E.Kind != WantKind) { continue; }
			Rows.Add(MakeShared<FJsonValueObject>(KrEventJson(E, bIncludeFrameParamMap)));
		}

		Out->SetStringField(TEXT("status"), Scan.Events.Num() > 0 ? TEXT("OK") : TEXT("NO_EVENTS"));
		Out->SetArrayField(TEXT("events"), Rows);

		TSharedRef<FJsonObject> Counts = MakeShared<FJsonObject>();
		Counts->SetNumberField(TEXT("events"), Scan.Events.Num());
		Counts->SetNumberField(TEXT("returned"), Rows.Num());
		Counts->SetNumberField(TEXT("recovered"), Recovered);
		Counts->SetNumberField(TEXT("failed"), Failed);
		Counts->SetNumberField(TEXT("realFunctions"), Scan.RealFunctions);
		Counts->SetNumberField(TEXT("rawPointerHits"), Scan.RawPtrHits);
		Counts->SetNumberField(TEXT("identityCalls"), Scan.IdentityCalls);
		Out->SetObjectField(TEXT("counts"), Counts);

		TSharedRef<FJsonObject> KindObj = MakeShared<FJsonObject>();
		for (const TPair<FString, int32>& KV : ByKind) { KindObj->SetNumberField(KV.Key, KV.Value); }
		Out->SetObjectField(TEXT("byKind"), KindObj);

		Out->SetStringField(TEXT("note"),
			TEXT("counts.events is every event on the class; counts.returned is after the kind filter (they are equal when kind=all). ")
			TEXT("counts.realFunctions is own functions that call no ubergraph - ordinary functions, NOT failed events. ")
			TEXT("rawPointerHits counts bytes that merely LOOK like the ubergraph pointer: a sound prefilter but an unsound oracle, ")
			TEXT("so it is reported next to identityCalls (the confirmed calls) rather than folded into the event count. ")
			TEXT("An event with recovered:false keeps its row and carries the reason in status - it is never dropped."));
	}

	// --- kr_analyze_ubergraph ----------------------------------------------------------------------
	//   in:  { asset [REQUIRED] (aliases: sourceAsset, path), includePerEvent?: bool (default true),
	//          includeOffsets?: bool (default false) }
	//   out: { class, cooked, status, prologue{}, ubergraph{}, counts{}, events{}, walkCapHit,
	//          disasmAborted, perEvent[], sharedLatentOffsets[], unreachedOffsets[], invariant, note }
	//
	// The per-Blueprint ubergraph slice analysis: prologue shape, per-event reachability, and the
	// shared/unreached statement counts — the analyzer's measurement for ONE Blueprint, returned as
	// JSON instead of written to a CSV in Saved/. Builds no graphs, mints nothing, compiles nothing.
	//
	// THE NUMBER THAT MATTERS is counts.sharedLatent: a latent node (Delay/timeline) reached by more
	// than one event cannot be split faithfully, because Delay dedupes on (CallbackTarget, UUID) —
	// duplicating it into two event graphs yields two UUIDs and concurrent execution where the cooked
	// original deduped. Everything else here is context for that one figure.
	//
	// INTERNAL CONSISTENCY IS CHECKABLE BY THE CALLER: analysedStmts == reached1 + shared + unreached,
	// echoed in the `invariant` field. The prologue and EX_EndOfScript are structurally outside every
	// event slice and are therefore excluded from analysedStmts — that exclusion is what keeps
	// `unreached` honest (an unreached statement should mean a slicer bug or a missed entry, never
	// "that was the prologue").
	//
	// COOKED CONTENT: primary target. A LOOSE/uncooked Blueprint is accepted too, deliberately (an
	// authored testbed BP is the control case when a cooked result looks wrong) — there is no
	// PKG_Cooked gate here, unlike the corpus sweep, which gates because it is enumerating.
	static void H_kr_analyze_ubergraph(const TSharedRef<FJsonObject>& In, const TSharedRef<FJsonObject>& Out)
	{
		if (KrRejectUnknownParams(In, Out,
			{ TEXT("asset"), TEXT("sourceAsset"), TEXT("path"), TEXT("includePerEvent"), TEXT("includeOffsets") },
			TEXT("asset (aliases: sourceAsset, path), includePerEvent, includeOffsets"),
			{{ TEXT("pathFilter"),
			   TEXT("not a parameter - this endpoint analyses ONE Blueprint; a corpus sweep is a separate (Wave 3) endpoint") },
			 { TEXT("startIndex"),
			   TEXT("not a parameter - that is the console sweep's argument; pass a single asset here") }}))
		{
			return;
		}

		UBlueprintGeneratedClass* BPGC = KrResolveBPGCStrict(In, Out, { TEXT("asset"), TEXT("sourceAsset"), TEXT("path") }, TEXT("asset"));
		if (!BPGC) { return; }

		const bool bIncludePerEvent = KrJBool(In, TEXT("includePerEvent"), true);
		const bool bIncludeOffsets = KrJBool(In, TEXT("includeOffsets"), false);

		Out->SetStringField(TEXT("class"), BPGC->GetPathName());
		Out->SetStringField(TEXT("className"), BPGC->GetName());
		Out->SetBoolField(TEXT("cooked"), KrIsCooked(BPGC));

		FGCScopeGuard GcLock;
		UFunction* UberFunc = BPGC->UberGraphFunction;

		TSharedRef<FJsonObject> Uber = MakeShared<FJsonObject>();
		Uber->SetBoolField(TEXT("present"), UberFunc != nullptr);
		if (UberFunc)
		{
			Uber->SetStringField(TEXT("name"), UberFunc->GetName());
			Uber->SetNumberField(TEXT("scriptBytes"), UberFunc->Script.Num());
		}
		Out->SetObjectField(TEXT("ubergraph"), Uber);

		if (!UberFunc || UberFunc->Script.Num() == 0)
		{
			Out->SetStringField(TEXT("status"), UberFunc ? TEXT("NO_BYTECODE") : TEXT("NO_UBERGRAPH"));
			Out->SetArrayField(TEXT("perEvent"), TArray<TSharedPtr<FJsonValue>>());
			Out->SetStringField(TEXT("note"),
				TEXT("ok, not an error: there is no ubergraph bytecode to analyse. NO_UBERGRAPH / NO_BYTECODE are normal ")
				TEXT("outcomes for a Blueprint that has functions but no event graph."));
			return;
		}

		// Disassemble the ubergraph ONCE. It is the single most expensive function in the asset; a
		// per-event disassembly would multiply that cost by the event count.
		FKismetBytecodeDisassemblerJson UberDis;
		const TArray<TSharedPtr<FJsonValue>> RawStmts = UberDis.SerializeFunction(UberFunc);

		TArray<MifUber::FUberStmt> Stmts;
		TMap<int32, int32> IndexByOffset;
		MifUber::BuildStatements(RawStmts, FLatentActionInfo::StaticStruct()->GetPathName(), UberFunc->GetName(),
			Stmts, IndexByOffset);

		const MifUber::FPrologue Prologue = MifUber::DetectPrologue(Stmts);

		FKrEventScan Scan;
		KrScanEvents(BPGC, UberFunc, Scan);

		// One walk per event, its own stack, its own visited set — nothing carried between events. The
		// offset→events map is assembled HERE, by the measurement, and is never fed back into a walk:
		// a shared region's exit edge is entry-dependent, so a cross-event pop-target cache would be a
		// silent wrong-wiring bug.
		TMap<int32, TSet<int32>> ReachedBy;
		TArray<int32> EventReachedCount;
		EventReachedCount.SetNumZeroed(Scan.Events.Num());
		int32 BadTargets = 0, ComputedHits = 0, EventsRecovered = 0;
		bool bWalkCapHit = false;

		for (int32 e = 0; e < Scan.Events.Num(); ++e)
		{
			if (!Scan.Events[e].bRecovered) { continue; }
			++EventsRecovered;
			TSet<int32> ThisEventReached;
			const MifUber::FWalkResult R =
				MifUber::WalkEvent(Stmts, IndexByOffset, Prologue, Scan.Events[e].EntryOffset, ThisEventReached);
			for (const int32 Off : ThisEventReached) { ReachedBy.FindOrAdd(Off).Add(e); }
			EventReachedCount[e] = R.Reached;
			BadTargets += R.BadTargets;
			ComputedHits += R.ComputedHits;
			bWalkCapHit |= R.bHitGuard;
		}

		int32 Analysed = 0, Reached1 = 0, Shared = 0, Unreached = 0, MaxShare = 0;
		int32 LatentStmts = 0, SharedLatent = 0;
		TArray<TSharedPtr<FJsonValue>> SharedLatentOffsets, UnreachedOffsets;

		for (const MifUber::FUberStmt& S : Stmts)
		{
			if (Prologue.Offsets.Contains(S.Offset)) { continue; }
			if (S.Inst == TEXT("EndOfScript")) { continue; }
			++Analysed;

			const TSet<int32>* E = ReachedBy.Find(S.Offset);
			const int32 Degree = E ? E->Num() : 0;
			MaxShare = FMath::Max(MaxShare, Degree);

			if (Degree == 0)      { ++Unreached; if (bIncludeOffsets) { UnreachedOffsets.Add(MakeShared<FJsonValueNumber>(S.Offset)); } }
			else if (Degree == 1) { ++Reached1; }
			else                  { ++Shared; }

			if (S.bLatent)
			{
				++LatentStmts;
				if (Degree > 1)
				{
					++SharedLatent;
					if (bIncludeOffsets) { SharedLatentOffsets.Add(MakeShared<FJsonValueNumber>(S.Offset)); }
				}
			}
		}

		Out->SetStringField(TEXT("status"), Scan.Events.Num() > 0 ? TEXT("OK") : TEXT("NO_EVENTS"));

		TSharedRef<FJsonObject> ProJson = MakeShared<FJsonObject>();
		ProJson->SetStringField(TEXT("kind"), Prologue.Kind);
		ProJson->SetBoolField(TEXT("sane"), Prologue.bSane);
		ProJson->SetNumberField(TEXT("offsetCount"), Prologue.Offsets.Num());
		ProJson->SetNumberField(TEXT("initialStackDepth"), Prologue.InitialStack.Num());
		Out->SetObjectField(TEXT("prologue"), ProJson);

		TSharedRef<FJsonObject> Counts = MakeShared<FJsonObject>();
		Counts->SetNumberField(TEXT("statements"), Stmts.Num());
		Counts->SetNumberField(TEXT("analysedStmts"), Analysed);
		Counts->SetNumberField(TEXT("reached1"), Reached1);
		Counts->SetNumberField(TEXT("shared"), Shared);
		Counts->SetNumberField(TEXT("unreached"), Unreached);
		Counts->SetNumberField(TEXT("maxShareDegree"), MaxShare);
		Counts->SetNumberField(TEXT("latentStmts"), LatentStmts);
		Counts->SetNumberField(TEXT("sharedLatent"), SharedLatent);
		Counts->SetNumberField(TEXT("badTargets"), BadTargets);
		Counts->SetNumberField(TEXT("computedHits"), ComputedHits);
		Counts->SetNumberField(TEXT("prologueStmts"), Prologue.Offsets.Num());
		Out->SetObjectField(TEXT("counts"), Counts);

		TSharedRef<FJsonObject> Events = MakeShared<FJsonObject>();
		Events->SetNumberField(TEXT("total"), Scan.Events.Num());
		Events->SetNumberField(TEXT("recovered"), EventsRecovered);
		Events->SetNumberField(TEXT("failed"), Scan.Events.Num() - EventsRecovered);
		Events->SetNumberField(TEXT("realFunctions"), Scan.RealFunctions);
		Out->SetObjectField(TEXT("events"), Events);

		Out->SetBoolField(TEXT("walkCapHit"), bWalkCapHit);
		Out->SetBoolField(TEXT("disasmAborted"), UberDis.bDisassemblyFailed);
		if (UberDis.bDisassemblyFailed)
		{
			Out->SetNumberField(TEXT("failedOpcode"), UberDis.FailedOpcode);
			Out->SetStringField(TEXT("failedOpcodeHex"), FString::Printf(TEXT("0x%02X"), UberDis.FailedOpcode));
			Out->SetNumberField(TEXT("failedAtIndex"), UberDis.FailedAtIndex);
		}

		if (bIncludePerEvent)
		{
			TArray<TSharedPtr<FJsonValue>> PerEvent;
			for (int32 e = 0; e < Scan.Events.Num(); ++e)
			{
				TSharedRef<FJsonObject> Row = KrEventJson(Scan.Events[e], /*bIncludeFrameParamMap*/ false);
				Row->SetNumberField(TEXT("reached"), EventReachedCount[e]);
				PerEvent.Add(MakeShared<FJsonValueObject>(Row));
			}
			Out->SetArrayField(TEXT("perEvent"), PerEvent);
		}
		if (bIncludeOffsets)
		{
			Out->SetArrayField(TEXT("sharedLatentOffsets"), SharedLatentOffsets);
			Out->SetArrayField(TEXT("unreachedOffsets"), UnreachedOffsets);
		}

		Out->SetStringField(TEXT("invariant"), FString::Printf(
			TEXT("analysedStmts(%d) == reached1(%d) + shared(%d) + unreached(%d) -> %s"),
			Analysed, Reached1, Shared, Unreached,
			(Analysed == Reached1 + Shared + Unreached) ? TEXT("holds") : TEXT("VIOLATED")));

		FString Note =
			TEXT("READ-ONLY: builds no graphs, mints no Blueprints, compiles nothing. ")
			TEXT("analysedStmts EXCLUDES the prologue statements and EX_EndOfScript, which are structurally outside every ")
			TEXT("event slice - that exclusion is what makes 'unreached' meaningful. ")
			TEXT("sharedLatent is the split-feasibility verdict: a latent statement reached by more than one event cannot be ")
			TEXT("duplicated into per-event graphs faithfully (Delay dedupes on CallbackTarget+UUID).");
		if (bWalkCapHit)
		{
			Note += TEXT(" WALK CAP HIT: at least one event walk tripped the iteration guard, so reached/shared/unreached are a LOWER BOUND, not exact.");
		}
		if (UberDis.bDisassemblyFailed)
		{
			Note += TEXT(" DISASSEMBLY ABORTED on an unknown opcode: every count above is PARTIAL - statements after failedAtIndex were never seen.");
		}
		if (!Prologue.bSane)
		{
			Note += FString::Printf(TEXT(" UNEXPECTED PROLOGUE shape '%s': the entry-seeded stack may be wrong, so treat the reachability numbers as suspect."), *Prologue.Kind);
		}
		Out->SetStringField(TEXT("note"), Note);
	}

	// --- kr_pin_type_from_property -----------------------------------------------------------------
	//   in:  { class [REQUIRED] (aliases: className, asset), property [REQUIRED] (alias: propertyName),
	//          selfScope?: class path (default: the resolved class) }
	//   out: { class, property, propertyClass, cppType, pinType{}, bridgeType, bridgeContainer,
	//          bridgeValueType, bridgeTypeUsable, bridgeTypeNote?, addVariableExample{}, selfScope, note }
	//
	// The translator between the reconstructor's pin-type reflection and the BRIDGE's type grammar
	// (docs/02_GOTCHAS.md section 2). Given any property of a cooked class, it returns the exact
	// `type` (+ `container` / `valueType`) string that add_variable / add_pin / create_function /
	// set_pin_type accept — so an agent mirrors a cooked property instead of guessing category and
	// subcategory spellings, which is where the "unknown type" failures come from.
	//
	// TWO REPRESENTATIONS, ON PURPOSE. `pinType` is FPropertyTypeHelper's own FEdGraphPinType JSON —
	// the reconstructor's internal, lossless form. `bridgeType` is the bridge's short grammar, which is
	// what you can actually pass to another endpoint. They are not redundant: some pin types (delegates,
	// wildcards, field paths) have no bridge spelling at all, and for those bridgeTypeUsable is false
	// with bridgeTypeNote saying why, rather than a plausible-looking string that would be rejected.
	//
	// "<SELF>" is a LOSSY, SIDE-RELATIVE alias, not a type: the serializer emits it whenever an object
	// equals the SelfScope it was given. It therefore means a different class depending on selfScope,
	// which is why selfScope is an explicit parameter and is always echoed. bridgeType never contains
	// "<SELF>" - it always spells the full class path.
	//
	// COOKED CONTENT: works, because FProperty reflection survives cooking intact (it is how
	// describe_class reads cooked assets today). Loose/uncooked classes work identically. Native
	// (C++) classes also resolve, so this doubles as a way to read an engine class's property types.
	static void H_kr_pin_type_from_property(const TSharedRef<FJsonObject>& In, const TSharedRef<FJsonObject>& Out)
	{
		if (KrRejectUnknownParams(In, Out,
			{ TEXT("class"), TEXT("className"), TEXT("asset"), TEXT("property"), TEXT("propertyName"), TEXT("selfScope") },
			TEXT("class (aliases: className, asset), property (alias: propertyName), selfScope"),
			{{ TEXT("function"),
			   TEXT("not supported here - this endpoint reads CLASS properties; a function's parameters are FProperties on the UFunction, which kr_dump_blueprint reports as numParams") }}))
		{
			return;
		}

		const FString ClassArg = KrJStrAny(In, { TEXT("class"), TEXT("className"), TEXT("asset") });
		if (ClassArg.IsEmpty())
		{
			KrFail(Out, TEXT("class required (a _C class path such as /Game/Path/BP_Foo.BP_Foo_C, a plain asset path, or a native class path such as /Script/Engine.Actor)"));
			return;
		}

		FString ResolveError;
		UClass* Target = KrResolveBPGC(ClassArg, ResolveError);
		if (!Target)
		{
			// Not a Blueprint class — try any UClass so native classes work too. This fallback is why
			// the endpoint is useful against /Script/Engine.* as well as /Game/*.
			if (ClassArg.Contains(TEXT("/")) || ClassArg.Contains(TEXT(".")))
			{
				Target = LoadClass<UObject>(nullptr, *ClassArg, nullptr, LOAD_NoWarn | LOAD_Quiet);
			}
			if (!Target)
			{
				Target = FindFirstObject<UClass>(*ClassArg, EFindFirstObjectOptions::None);
			}
		}
		if (!Target)
		{
			KrFail(Out, FString::Printf(
				TEXT("class not found: '%s'. Accepted forms: a Blueprint _C class path (/Game/Path/BP_Foo.BP_Foo_C), ")
				TEXT("a Blueprint asset path, a native class path (/Script/Engine.Actor), or an unambiguous class name. ")
				TEXT("Blueprint resolution reported: %s"), *ClassArg, *ResolveError));
			return;
		}

		const FString PropertyName = KrJStrAny(In, { TEXT("property"), TEXT("propertyName") });
		if (PropertyName.IsEmpty())
		{
			KrFail(Out, TEXT("property required (exact property name on the class; list them with kr_dump_blueprint or MifBridge's describe_class)"));
			return;
		}

		FProperty* Property = Target->FindPropertyByName(FName(*PropertyName));
		if (!Property)
		{
			TArray<FString> Near;
			for (TFieldIterator<FProperty> It(Target); It && Near.Num() < 10; ++It)
			{
				if (*It && (*It)->GetName().Contains(PropertyName.Left(FMath::Min(4, PropertyName.Len())))) { Near.Add((*It)->GetName()); }
			}
			KrFail(Out, FString::Printf(
				TEXT("property '%s' not found on %s (search includes inherited properties)%s - list every property with kr_dump_blueprint, MifBridge's describe_class or list_object_properties"),
				*PropertyName, *Target->GetName(),
				Near.Num() > 0 ? *FString::Printf(TEXT("; nearest: %s"), *FString::Join(Near, TEXT(", "))) : TEXT("")));
			return;
		}

		// selfScope controls when the serializer collapses an object reference to the "<SELF>" token.
		UClass* SelfScope = Target;
		const FString SelfScopeArg = KrJStrAny(In, { TEXT("selfScope") });
		if (!SelfScopeArg.IsEmpty())
		{
			UClass* Scope = LoadClass<UObject>(nullptr, *SelfScopeArg, nullptr, LOAD_NoWarn | LOAD_Quiet);
			if (!Scope) { Scope = FindFirstObject<UClass>(*SelfScopeArg, EFindFirstObjectOptions::None); }
			if (!Scope)
			{
				KrFail(Out, FString::Printf(TEXT("selfScope class not found: '%s' (pass a class path, or omit it to use the resolved class)"), *SelfScopeArg));
				return;
			}
			SelfScope = Scope;
		}

		FEdGraphPinType PinType;
		if (!FPropertyTypeHelper::ConvertPropertyToPinType(Property, PinType))
		{
			KrFail(Out, FString::Printf(
				TEXT("property '%s' (%s) has no Blueprint pin type - it is a C++-only property shape that Blueprint cannot represent"),
				*PropertyName, Property->GetClass() ? *Property->GetClass()->GetName() : TEXT("?")));
			return;
		}

		Out->SetStringField(TEXT("class"), Target->GetPathName());
		Out->SetStringField(TEXT("className"), Target->GetName());
		// See the note at the parent-chain site: Cast<>, because UClass makes IsA private.
		Out->SetBoolField(TEXT("blueprintClass"), Cast<UBlueprintGeneratedClass>(Target) != nullptr);
		Out->SetBoolField(TEXT("cooked"), KrIsCooked(Target));
		Out->SetStringField(TEXT("property"), Property->GetName());
		Out->SetStringField(TEXT("propertyClass"), Property->GetClass() ? Property->GetClass()->GetName() : TEXT("?"));
		Out->SetStringField(TEXT("cppType"), Property->GetCPPType());
		Out->SetArrayField(TEXT("propertyFlags"), KrPropertyFlagNames(Property->GetPropertyFlags()));
		Out->SetObjectField(TEXT("pinType"), FPropertyTypeHelper::SerializeGraphPinType(PinType, SelfScope));
		Out->SetStringField(TEXT("selfScope"), SelfScope->GetPathName());

		FString BridgeType, BridgeValueType, WhyNot;
		const bool bTerminalOk = KrBridgeTerminalType(PinType.PinCategory, PinType.PinSubCategory,
			PinType.PinSubCategoryObject.Get(), BridgeType, WhyNot);

		FString BridgeContainer;
		bool bUsable = bTerminalOk;
		switch (PinType.ContainerType)
		{
		case EPinContainerType::Array: BridgeContainer = TEXT("array"); break;
		case EPinContainerType::Set:   BridgeContainer = TEXT("set");   break;
		case EPinContainerType::Map:
			BridgeContainer = TEXT("map");
			// Only probed when the KEY type mapped: otherwise WhyNot already names the key's problem
			// and overwriting it with the value's would hide the first failure.
			if (bTerminalOk)
			{
				FString ValueWhyNot;
				if (!KrBridgeTerminalType(PinType.PinValueType.TerminalCategory, PinType.PinValueType.TerminalSubCategory,
					PinType.PinValueType.TerminalSubCategoryObject.Get(), BridgeValueType, ValueWhyNot))
				{
					bUsable = false;
					WhyNot = FString::Printf(TEXT("map value type: %s"), *ValueWhyNot);
				}
			}
			break;
		default: break;
		}

		Out->SetBoolField(TEXT("bridgeTypeUsable"), bUsable);
		if (bUsable)
		{
			Out->SetStringField(TEXT("bridgeType"), BridgeType);
			if (!BridgeContainer.IsEmpty()) { Out->SetStringField(TEXT("bridgeContainer"), BridgeContainer); }
			if (!BridgeValueType.IsEmpty()) { Out->SetStringField(TEXT("bridgeValueType"), BridgeValueType); }

			// Ready to paste into add_variable / add_pin — the reason this endpoint exists.
			TSharedRef<FJsonObject> Example = MakeShared<FJsonObject>();
			Example->SetStringField(TEXT("name"), Property->GetName());
			Example->SetStringField(TEXT("type"), BridgeType);
			if (!BridgeContainer.IsEmpty()) { Example->SetStringField(TEXT("container"), BridgeContainer); }
			if (!BridgeValueType.IsEmpty()) { Example->SetStringField(TEXT("valueType"), BridgeValueType); }
			Out->SetObjectField(TEXT("addVariableExample"), Example);
		}
		else
		{
			Out->SetStringField(TEXT("bridgeTypeNote"), FString::Printf(
				TEXT("no bridge type grammar spelling for this pin: %s. The pinType object above is still exact - ")
				TEXT("it just cannot be expressed as an add_variable 'type' string."), *WhyNot));
		}

		Out->SetStringField(TEXT("note"),
			TEXT("pinType is FPropertyTypeHelper's lossless FEdGraphPinType JSON (the reconstructor's internal form); ")
			TEXT("bridgeType is the short grammar that add_variable / add_pin / create_function / set_pin_type accept. ")
			TEXT("The container never appears inside bridgeType - it is a separate 'container' field, and a map's value ")
			TEXT("type is a separate 'valueType' field. The \"<SELF>\" token can appear in pinType (it means 'this object ")
			TEXT("IS selfScope' and is therefore side-relative); bridgeType always spells the full class path instead."));
	}

	// --- kr_reconstruct_request / kr_reconstruct_status --------------------------------------------
	//
	// WHY THIS PAIR IS SHAPED THE WAY IT IS (the load-bearing constraint, verified):
	// FHttpServerModule is a game-thread ticker. While a synchronous reconstruct runs, no HTTP request
	// is even read off the socket. Mid-job progress polling is therefore PHYSICALLY IMPOSSIBLE, not
	// merely unimplemented. So a single-Blueprint job is ATOMIC: the request validates, reserves the
	// one job slot, defers the work by exactly one tick and returns immediately with a jobId; the work
	// then runs to completion inside that tick; the status endpoint reports queued/running/done/failed
	// plus the result. What this buys is real and worth the machinery — the caller never holds an HTTP
	// connection open across a multi-second editor stall (the bridge's read timeout would otherwise
	// fire and report a failure that did not happen), the result survives a client reconnect, and the
	// jobId names the culprit in the log if the editor dies mid-reconstruct. What it does NOT buy is
	// progress, and the status payload says so in every response rather than implying otherwise.
	//
	// The one-tick deferral is the same precedent new_level/save_level_as use
	// (MifBridgeWorld.cpp:144): scheduling for the next tick lets the CURRENT tick — the one this HTTP
	// handler is running inside — unwind before heavy engine surgery begins.

	struct FKrReconstructPlan
	{
		FString JobId;
		FString SourceClassPath;   // re-resolved after the tick; never a captured raw pointer
		FString Mode;              // "copy" | "function"
		FString Variant;
		FString TargetPath;
		FString FunctionName;
		bool    bAsChild = false;
		bool    bFullParent = false;
	};

	/** Count nodes across a Blueprint's function graphs + ubergraph pages — the node tally reported as
	 *  nodesCreated for copy mode. Graph Nodes.Num() deltas, deliberately NOT decompiler counters: the
	 *  per-event decompiler instances are not aggregated anywhere, so summing them was never verified. */
	static int32 KrCountBlueprintNodes(UBlueprint* BP)
	{
		int32 N = 0;
		if (!BP) { return 0; }
		for (UEdGraph* Graph : BP->FunctionGraphs)   { if (Graph) { N += Graph->Nodes.Num(); } }
		for (UEdGraph* Graph : BP->UbergraphPages)   { if (Graph) { N += Graph->Nodes.Num(); } }
		return N;
	}

	static void KrRecordCompileResults(const FCompilerResultsLog& Results)
	{
		MifKr::Jobs::FJobRecord& Job = MifKr::Jobs::Mutable();
		Job.bCompileMeasured = true;
		Job.CompileErrors = Results.NumErrors;
		Job.CompileWarnings = Results.NumWarnings;
		for (const TSharedRef<FTokenizedMessage>& Message : Results.Messages)
		{
			if (Message->GetSeverity() == EMessageSeverity::Error)
			{
				Job.FirstError = Message->ToText().ToString();
				break;
			}
		}
	}

	/** The deferred slice. Runs ONE tick after the request returned, on the game thread. */
	static void KrRunReconstructJob(FKrReconstructPlan Plan)
	{
		using namespace MifKr::Jobs;

		if (!HasRecord() || Get().JobId != Plan.JobId)
		{
			// Cannot happen with one slot and no cancellation, but a stale timer firing against a
			// different job would corrupt that job's counters — so it is checked, not assumed.
			return;
		}

		MarkRunning(TEXT("resolving"));

		// Re-resolve by PATH. One tick has passed since the request handler resolved it, and holding a
		// raw UObject* across that gap is precisely the un-rooted-pointer lifetime bug the pipeline's
		// own FGCScopeGuard exists to prevent. The package is already loaded, so this is a lookup.
		FString ResolveError;
		UBlueprintGeneratedClass* BPGC = KrResolveBPGC(Plan.SourceClassPath, ResolveError);
		if (!BPGC)
		{
			Finish(false, FString::Printf(TEXT("source class disappeared between request and execution: %s"), *ResolveError));
			return;
		}

		FJobRecord& Job = Mutable();
		TSharedRef<FJsonObject> Result = MakeShared<FJsonObject>();
		Result->SetStringField(TEXT("sourceClass"), BPGC->GetPathName());
		Result->SetBoolField(TEXT("sourceCooked"), KrIsCooked(BPGC));

		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[kr job] %s BEGIN mode=%s source=%s target=%s"),
			*Plan.JobId, *Plan.Mode, *BPGC->GetPathName(), *Plan.TargetPath);
		if (GLog) { GLog->Flush(); }   // flushed BEGIN marker: a hard crash names the culprit

		if (Plan.Mode == TEXT("copy"))
		{
			SetPhase(TEXT("minting"));
			FText Error;
			// The engine's headless editable-copy export: mint + populate (which drives the two
			// reconstruction delegates this module bound, feeding FunctionsDone/EventsDone) + compile
			// + SAVE. Same call create_editable_child makes; the difference is that this one runs
			// deferred, under a job record, and reports the reconstruction tallies.
			UBlueprint* NewBP = CreateEditableBlueprintCopy(BPGC, Plan.TargetPath, Plan.bAsChild, &Error, Plan.bFullParent);
			if (!NewBP)
			{
				Finish(false, FString::Printf(TEXT("editable copy failed: %s"), *Error.ToString()));
				return;
			}
			Job.NodesCreated = KrCountBlueprintNodes(NewBP);

			Result->SetStringField(TEXT("blueprintId"), NewBP->GetPathName());
			Result->SetStringField(TEXT("assetPath"), Plan.TargetPath);
			Result->SetBoolField(TEXT("asChild"), Plan.bAsChild);
			Result->SetBoolField(TEXT("fullParent"), Plan.bFullParent);
			Result->SetNumberField(TEXT("functionGraphs"), NewBP->FunctionGraphs.Num());
			Result->SetNumberField(TEXT("ubergraphPages"), NewBP->UbergraphPages.Num());
			Result->SetNumberField(TEXT("graphNodes"), Job.NodesCreated);
			if (NewBP->GeneratedClass) { Result->SetStringField(TEXT("class"), NewBP->GeneratedClass->GetPathName()); }
			Result->SetBoolField(TEXT("saved"), true);
			Result->SetStringField(TEXT("resultNote"),
				TEXT("copy mode SAVES the asset (the engine export does), and compiles it internally - so compile.measured is ")
				TEXT("false here: this endpoint does not own that FCompilerResultsLog and will not invent errors:0 for it. ")
				TEXT("For authoritative compile numbers call MifBridge's validate (or compile) on blueprintId."));
			Job.Result = Result;
			Finish(true, FString());
			return;
		}

		// --- mode == "function" ---
		SetPhase(TEXT("resolving"));
		UFunction* SourceFunc = BPGC->FindFunctionByName(FName(*Plan.FunctionName), EIncludeSuperFlag::ExcludeSuper);
		if (!SourceFunc || SourceFunc->Script.Num() == 0)
		{
			Finish(false, FString::Printf(
				TEXT("function '%s' is no longer resolvable on %s (or has no bytecode) - it was present when the job was queued"),
				*Plan.FunctionName, *BPGC->GetName()));
			return;
		}

		SetPhase(TEXT("minting"));
		UPackage* Package = CreatePackage(*Plan.TargetPath);
		if (!Package)
		{
			Finish(false, FString::Printf(TEXT("CreatePackage failed for '%s' - is it a valid long package path?"), *Plan.TargetPath));
			return;
		}
		const FString ShortName = FPackageName::GetShortName(Plan.TargetPath);
		// Parented to the COOKED source class so member references resolve during decompilation.
		UBlueprint* NewBP = FKismetEditorUtilities::CreateBlueprint(
			BPGC, Package, FName(*ShortName), BPTYPE_Normal,
			UBlueprint::StaticClass(), UBlueprintGeneratedClass::StaticClass());
		if (!NewBP)
		{
			Finish(false, FString::Printf(TEXT("CreateBlueprint failed for '%s' (target '%s')"), *ShortName, *Plan.TargetPath));
			return;
		}

		// A NEW function name (<Fn>_Recon), not an override of the cooked one: an override would inherit
		// the parent's signature semantics and hide whether the decompiled body is what compiled.
		const FName GraphName(*FString::Printf(TEXT("%s_Recon"), *Plan.FunctionName));
		UEdGraph* NewGraph = FBlueprintEditorUtils::CreateNewGraph(
			NewBP, GraphName, UEdGraph::StaticClass(), UEdGraphSchema_K2::StaticClass());
		FBlueprintEditorUtils::AddFunctionGraph<UFunction>(NewBP, NewGraph, /*bIsUserCreated*/ false, SourceFunc);
		const int32 StubNodes = NewGraph ? NewGraph->Nodes.Num() : 0;

		SetPhase(TEXT("reconstructing"));
		// The SHARED pipeline — byte-for-byte the same entry point the F3 hook and the console command
		// use. Called DIRECTLY (not through the engine delegate), so the delegate counters do not fire
		// and cannot double-count: function mode's tallies are set explicitly here.
		const bool bClean = MifReconstructFunctionIntoGraph(SourceFunc, NewGraph, NewBP);
		Job.FunctionsDone = 1;
		Job.FunctionsReconstructed = bClean ? 1 : 0;
		Job.NodesCreated = NewGraph ? FMath::Max(0, NewGraph->Nodes.Num() - StubNodes) : 0;

		SetPhase(TEXT("compiling"));
		FCompilerResultsLog Results;
		Results.SetSourcePath(NewBP->GetPathName());
		FKismetEditorUtilities::CompileBlueprint(NewBP, EBlueprintCompileOptions::None, &Results);
		KrRecordCompileResults(Results);

		FBlueprintEditorUtils::MarkBlueprintAsStructurallyModified(NewBP);
		Package->MarkPackageDirty();
		FAssetRegistryModule::AssetCreated(NewBP);

		Result->SetStringField(TEXT("blueprintId"), NewBP->GetPathName());
		Result->SetStringField(TEXT("assetPath"), Plan.TargetPath);
		Result->SetStringField(TEXT("sourceFunction"), SourceFunc->GetName());
		Result->SetNumberField(TEXT("sourceScriptBytes"), SourceFunc->Script.Num());
		Result->SetStringField(TEXT("graph"), GraphName.ToString());
		Result->SetNumberField(TEXT("graphNodes"), NewGraph ? NewGraph->Nodes.Num() : 0);
		Result->SetNumberField(TEXT("stubNodes"), StubNodes);
		Result->SetNumberField(TEXT("nodesAdded"), Job.NodesCreated);
		// clean:false is a RESULT, not an error: the decompiler degraded and left a partial graph, which
		// is still the most useful thing that could be returned. Read the number, do not read ok.
		Result->SetBoolField(TEXT("clean"), bClean);
		Result->SetBoolField(TEXT("saved"), false);
		Result->SetStringField(TEXT("resultNote"),
			TEXT("function mode does NOT save: the new asset is dirty in memory. Persist it with MifBridge's ")
			TEXT("save_dirty_packages, or discard it by restarting. Inspect the graph with list_nodes ")
			TEXT("{blueprintId, graph} - its node count must equal result.graphNodes."));
		Job.Result = Result;
		Finish(true, FString());
	}

	// --- kr_reconstruct_request --------------------------------------------------------------------
	//   in:  { sourceAsset [REQUIRED] (aliases: blueprint, bpName, path),
	//          mode?: "copy" | "function" (default copy),
	//          variant?: child|sibling|uncooked|sibling_full|full (copy mode ONLY, default child),
	//          function?: string (function mode ONLY, REQUIRED there; alias functionName, func),
	//          targetPath?: long package path (aliases childPath, outPath) }
	//   out: { jobId, state:"queued", kind, mode, variant?, function?, sourceAsset, sourceClassPath,
	//          bpName, targetPath, functionsTotalEstimate, deferred:true, note }
	//
	// Bucket SELF-MANAGED: the deferred slice runs a full FKismetEditorUtilities::CompileBlueprint (and
	// in copy mode a package save). A full compile inside a blanket undo transaction means reinstancing
	// captured by an undo step, which means a dead CDO and a crash — the exact reason
	// create_editable_child is self-managed for the same call. The REQUEST handler itself mutates
	// nothing; it validates and enqueues.
	//
	// COOKED CONTENT: this endpoint's whole reason to exist — it turns pak-mounted bytecode into
	// editable K2 graphs. A LOOSE/uncooked source is accepted rather than refused (there is no
	// PKG_Cooked gate) but it is pointless: an uncooked Blueprint already HAS its graphs, so the copy
	// is a slower duplicate. The response says so via sourceCooked in the job result.
	static void H_kr_reconstruct_request(const TSharedRef<FJsonObject>& In, const TSharedRef<FJsonObject>& Out)
	{
		if (KrRejectUnknownParams(In, Out,
			{ TEXT("sourceAsset"), TEXT("blueprint"), TEXT("bpName"), TEXT("path"), TEXT("mode"),
			  TEXT("variant"), TEXT("copyVariant"), TEXT("function"), TEXT("functionName"), TEXT("func"),
			  TEXT("targetPath"), TEXT("childPath"), TEXT("outPath") },
			TEXT("sourceAsset (aliases: blueprint, bpName, path), mode, variant (alias: copyVariant), ")
			TEXT("function (aliases: functionName, func), targetPath (aliases: childPath, outPath)"),
			{{ TEXT("open"),
			   TEXT("not implemented deliberately - an unattended agent must not be made to open editor tabs; inspect the result with list_nodes instead") },
			 { TEXT("save"),
			   TEXT("not a parameter - copy mode always saves (the engine export does); function mode never does, leaving the asset dirty for save_dirty_packages") },
			 { TEXT("compile"),
			   TEXT("not a parameter - the reconstructed Blueprint is always compiled; the compile is the oracle that says whether the decompiled graph is real") },
			 { TEXT("wait"),
			   TEXT("not implemented - the job is deferred one tick and cannot be waited on inside this request; poll kr_reconstruct_status") }}))
		{
			return;
		}

		// Cheap refusal first: a caller whose slot is busy learns that without paying for a package load.
		if (MifKr::Jobs::IsBusy())
		{
			const MifKr::Jobs::FJobRecord& Running = MifKr::Jobs::Get();
			KrFail(Out, MifKr::Jobs::BusyMessage());
			Out->SetStringField(TEXT("runningJobId"), Running.JobId);
			Out->SetStringField(TEXT("runningKind"), Running.Kind);
			Out->SetStringField(TEXT("runningState"), MifKr::Jobs::StateName(Running.State));
			return;
		}

		if (!GEditor)
		{
			KrFail(Out, TEXT("no GEditor - kr_reconstruct_request defers its work through the editor timer manager and cannot run in a commandlet"));
			return;
		}

		const FString SourceArg = KrJStrAny(In, { TEXT("sourceAsset"), TEXT("blueprint"), TEXT("bpName"), TEXT("path") });
		if (SourceArg.IsEmpty())
		{
			KrFail(Out, TEXT("sourceAsset required (the cooked Blueprint: its .<Name>_C class path, its asset path, or its exact name)"));
			return;
		}

		FString Mode = KrJStrAny(In, { TEXT("mode") }, TEXT("copy")).ToLower();
		if (Mode != TEXT("copy") && Mode != TEXT("function"))
		{
			KrFail(Out, FString::Printf(TEXT("mode '%s' is not recognised; pass 'copy' (whole editable Blueprint) or 'function' (one function into a scratch Blueprint)"), *Mode));
			return;
		}

		const FString VariantArg = KrJStrAny(In, { TEXT("variant"), TEXT("copyVariant") });
		const FString FunctionArg = KrJStrAny(In, { TEXT("function"), TEXT("functionName"), TEXT("func") });

		// Cross-parameter rules stated as errors, not silently ignored: a 'variant' quietly dropped in
		// function mode would leave the caller believing they controlled something they did not.
		if (Mode == TEXT("function") && !VariantArg.IsEmpty())
		{
			KrFail(Out, TEXT("variant applies to mode 'copy' only - function mode always mints a scratch Blueprint parented to the cooked source class; drop variant or switch to mode 'copy'"));
			return;
		}
		if (Mode == TEXT("copy") && !FunctionArg.IsEmpty())
		{
			KrFail(Out, TEXT("function applies to mode 'function' only - copy mode reconstructs EVERY function of the class; drop function or switch to mode 'function'"));
			return;
		}
		if (Mode == TEXT("function") && FunctionArg.IsEmpty())
		{
			KrFail(Out, TEXT("function required when mode='function' (exact name of an OWN function on the class; list them with kr_dump_blueprint)"));
			return;
		}

		FString Variant = VariantArg.IsEmpty() ? TEXT("child") : VariantArg.ToLower();
		bool bAsChild = false, bFullParent = false;
		if (Mode == TEXT("copy"))
		{
			if (Variant == TEXT("child"))                                     { bAsChild = true; }
			else if (Variant == TEXT("sibling") || Variant == TEXT("uncooked")) { bAsChild = false; }
			else if (Variant == TEXT("sibling_full") || Variant == TEXT("full")) { bAsChild = false; bFullParent = true; }
			else
			{
				KrFail(Out, FString::Printf(
					TEXT("variant '%s' is not recognised; pass child (IS-A the source), sibling or uncooked (parent-class copy), or sibling_full/full (sibling whose Blueprint parent chain is also reconstructed)"),
					*Variant));
				return;
			}
		}
		else
		{
			Variant.Empty();
		}

		FString ResolveError;
		UBlueprintGeneratedClass* BPGC = KrResolveBPGC(SourceArg, ResolveError);
		if (!BPGC)
		{
			KrFail(Out, ResolveError);
			return;
		}

		FString BaseName = BPGC->GetName();
		BaseName.RemoveFromEnd(TEXT("_C"));

		// functionsTotalEstimate: own functions with bytecode that are not the ubergraph. Named
		// "Estimate" because the authoritative per-function gate is engine-static and unlinkable from
		// here — the DONE counts are authoritative, the total is advisory.
		int32 FunctionsTotalEstimate = 0;
		for (TFieldIterator<UFunction> It(BPGC, EFieldIteratorFlags::ExcludeSuper); It; ++It)
		{
			UFunction* Func = *It;
			if (!Func || Func->Script.Num() == 0) { continue; }
			if (Func->HasAnyFunctionFlags(FUNC_UbergraphFunction)) { continue; }
			++FunctionsTotalEstimate;
		}

		if (Mode == TEXT("function"))
		{
			UFunction* SourceFunc = BPGC->FindFunctionByName(FName(*FunctionArg), EIncludeSuperFlag::ExcludeSuper);
			if (!SourceFunc)
			{
				UFunction* Inherited = BPGC->FindFunctionByName(FName(*FunctionArg), EIncludeSuperFlag::IncludeSuper);
				const TArray<FString> Near = KrNearMissFunctions(BPGC, FunctionArg.Left(FMath::Min(5, FunctionArg.Len())), 10);
				KrFail(Out, FString::Printf(
					TEXT("function '%s' not found on %s (own functions only)%s%s"),
					*FunctionArg, *BPGC->GetName(),
					Inherited ? TEXT(" - it is INHERITED; reconstruct it from the class that owns it") : TEXT(""),
					Near.Num() > 0 ? *FString::Printf(TEXT("; nearest own names: %s"), *FString::Join(Near, TEXT(", "))) : TEXT("")));
				return;
			}
			if (SourceFunc->HasAnyFunctionFlags(FUNC_UbergraphFunction))
			{
				// The pipeline itself refuses this by design; refusing here too means the caller gets
				// the REASON instead of a job that "succeeded" with an empty graph.
				KrFail(Out, FString::Printf(
					TEXT("'%s' is the ubergraph (FUNC_UbergraphFunction) - it is one switch-dispatched function holding EVERY event body, ")
					TEXT("and reconstructing it whole is both wrong and the source of a deep crash. Use mode:'copy', where events are sliced ")
					TEXT("per-event by the event delegate; inspect its structure first with kr_analyze_ubergraph."),
					*FunctionArg));
				return;
			}
			if (SourceFunc->Script.Num() == 0)
			{
				KrFail(Out, FString::Printf(
					TEXT("function '%s' has no bytecode (Script.Num()==0) - it is a stub, an interface shell or a BlueprintImplementableEvent declaration; there is nothing to reconstruct"),
					*FunctionArg));
				return;
			}
			FunctionsTotalEstimate = 1;
		}

		// --- target path ---
		FString TargetPath = KrJStrAny(In, { TEXT("targetPath"), TEXT("childPath"), TEXT("outPath") });
		const bool bDefaultedPath = TargetPath.IsEmpty();
		if (bDefaultedPath)
		{
			if (Mode == TEXT("copy"))
			{
				TargetPath = FString::Printf(TEXT("/Game/Mif/%s_%s"), *BaseName, bAsChild ? TEXT("Child") : TEXT("Editable"));
			}
			else
			{
				// Uniquified so a re-run does not collide with the previous scratch asset. Bounded:
				// an unbounded search here would hang the game thread inside an HTTP handler.
				static int32 GReconCounter = 0;
				const FString Base = FString::Printf(TEXT("/Game/Reconstructed/Recon_%s_%s"), *BaseName, *FunctionArg);
				for (int32 Attempt = 0; Attempt < 1000; ++Attempt)
				{
					const FString Candidate = FString::Printf(TEXT("%s_%d"), *Base, ++GReconCounter);
					if (!FPackageName::DoesPackageExist(Candidate) && !FindObject<UPackage>(nullptr, *Candidate))
					{
						TargetPath = Candidate;
						break;
					}
				}
				if (TargetPath.IsEmpty())
				{
					KrFail(Out, FString::Printf(TEXT("could not find a free package name under '%s_<n>' after 1000 tries - pass targetPath explicitly"), *Base));
					return;
				}
			}
		}
		else if (!FPackageName::IsValidLongPackageName(TargetPath))
		{
			KrFail(Out, FString::Printf(
				TEXT("targetPath '%s' is not a valid long package name - pass something like /Game/Mif/%s_Child (no file extension, no trailing asset name after a dot)"),
				*TargetPath, *BaseName));
			return;
		}

		// --- reserve the slot and defer ---
		FString JobId, BeginError;
		if (!MifKr::Jobs::TryBegin(TEXT("reconstruct"), JobId, BeginError))
		{
			KrFail(Out, BeginError);
			return;
		}

		{
			MifKr::Jobs::FJobRecord& Job = MifKr::Jobs::Mutable();
			Job.SourceAsset = SourceArg;
			Job.SourceClassPath = BPGC->GetPathName();
			Job.BpName = BaseName;
			Job.Mode = Mode;
			Job.Variant = Variant;
			Job.TargetPath = TargetPath;
			Job.FunctionName = (Mode == TEXT("function")) ? FunctionArg : FString();
			Job.FunctionsTotalEstimate = FunctionsTotalEstimate;
		}

		FKrReconstructPlan Plan;
		Plan.JobId = JobId;
		Plan.SourceClassPath = BPGC->GetPathName();
		Plan.Mode = Mode;
		Plan.Variant = Variant;
		Plan.TargetPath = TargetPath;
		Plan.FunctionName = (Mode == TEXT("function")) ? FunctionArg : FString();
		Plan.bAsChild = bAsChild;
		Plan.bFullParent = bFullParent;

		GEditor->GetTimerManager()->SetTimerForNextTick(FTimerDelegate::CreateLambda([Plan]()
		{
			KrRunReconstructJob(Plan);
		}));

		Out->SetStringField(TEXT("jobId"), JobId);
		Out->SetStringField(TEXT("kind"), TEXT("reconstruct"));
		Out->SetStringField(TEXT("state"), TEXT("queued"));
		Out->SetStringField(TEXT("mode"), Mode);
		if (!Variant.IsEmpty()) { Out->SetStringField(TEXT("variant"), Variant); }
		if (Mode == TEXT("function")) { Out->SetStringField(TEXT("function"), FunctionArg); }
		Out->SetStringField(TEXT("sourceAsset"), SourceArg);
		Out->SetStringField(TEXT("sourceClassPath"), BPGC->GetPathName());
		Out->SetBoolField(TEXT("sourceCooked"), KrIsCooked(BPGC));
		Out->SetStringField(TEXT("bpName"), BaseName);
		Out->SetStringField(TEXT("targetPath"), TargetPath);
		Out->SetBoolField(TEXT("targetPathDefaulted"), bDefaultedPath);
		Out->SetNumberField(TEXT("functionsTotalEstimate"), FunctionsTotalEstimate);
		Out->SetBoolField(TEXT("deferred"), true);
		Out->SetStringField(TEXT("note"),
			TEXT("DEFERRED one tick - this call did NOT do the work and did NOT block. Poll kr_reconstruct_status. ")
			TEXT("The job is ATOMIC: it runs to completion inside a single tick, during which the HTTP listener (a ")
			TEXT("game-thread ticker) is stalled, so a poll issued mid-job is not read until the job ends. ")
			TEXT("There is ONE job slot and no queue - a second request while this one runs is REFUSED, naming this jobId. ")
			TEXT("functionsTotalEstimate is advisory (the authoritative per-function gate lives in the engine); ")
			TEXT("functionsDone/functionsReconstructed in the status are authoritative."));
	}

	// --- kr_reconstruct_status ---------------------------------------------------------------------
	//   in:  { jobId?: string (alias id; default = the retained job) }
	//   out: { found, jobId, kind, state, phase, mode, variant?, function?, sourceAsset,
	//          sourceClassPath, bpName, targetPath, queuedAtUtc, elapsedMs, functionsTotalEstimate,
	//          functionsDone, functionsReconstructed, functionsDegraded, eventsDone,
	//          eventsReconstructed, nodesCreated, compile{measured,errors,warnings,firstError},
	//          result{}, error?, note }
	//
	// The poll half, for every job kind. Bucket READ-ONLY: it is a pure query of a POD record, and a
	// transacted poll would push an empty undo entry per call — the exact transaction pollution the
	// read-only bucket exists to prevent, made worse here because polling is by definition repeated.
	//
	// ONLY ONE RECORD IS RETAINED (the running job, or the last completed one), so poll-after-done
	// always works but poll-after-the-NEXT-request does not. An unknown jobId answers found:false and
	// names the id that IS retained rather than reporting a bare failure.
	//
	// COOKED CONTENT: n/a - this endpoint reads no assets at all.
	static void H_kr_reconstruct_status(const TSharedRef<FJsonObject>& In, const TSharedRef<FJsonObject>& Out)
	{
		if (KrRejectUnknownParams(In, Out,
			{ TEXT("jobId"), TEXT("id") },
			TEXT("jobId (alias: id)"),
			{{ TEXT("wait"),
			   TEXT("not implemented - a blocking wait would hold the game thread that runs the job, deadlocking it; poll instead") },
			 { TEXT("history"),
			   TEXT("not implemented - exactly ONE job record is retained (the running job, or the last completed one)") }}))
		{
			return;
		}

		const FString WantId = KrJStrAny(In, { TEXT("jobId"), TEXT("id") });

		// The honesty field. Present on EVERY response, including found:false — the constraint it
		// describes is a property of the HTTP server, not of any particular job.
		const TCHAR* HonestyNote =
			TEXT("single-Blueprint jobs (reconstruct, verify, classify) are ATOMIC: the HTTP listener is a game-thread ")
			TEXT("ticker, so while the job runs no request is read off the socket at all - their progress counters advance ")
			TEXT("on completion, never mid-job. The SLICED kinds (census, batch) are the exception and the reason: they ")
			TEXT("process ONE Blueprint per tick, so the ticker pumps HTTP between Blueprints and result.bpDone genuinely ")
			TEXT("advances across polls. Job records are in-memory only: after an editor restart this answers found:false. ")
			TEXT("Exactly one record is retained, so poll after done works but is lost once the next request is accepted.");

		if (!MifKr::Jobs::HasRecord())
		{
			Out->SetBoolField(TEXT("found"), false);
			Out->SetStringField(TEXT("reason"), TEXT("no kr job has been requested in this editor session"));
			Out->SetStringField(TEXT("note"), HonestyNote);
			return;
		}

		const MifKr::Jobs::FJobRecord& Job = MifKr::Jobs::Get();
		if (!WantId.IsEmpty() && WantId != Job.JobId)
		{
			Out->SetBoolField(TEXT("found"), false);
			Out->SetStringField(TEXT("requestedJobId"), WantId);
			Out->SetStringField(TEXT("retainedJobId"), Job.JobId);
			Out->SetStringField(TEXT("reason"), FString::Printf(
				TEXT("job '%s' is not retained; only the latest record is kept and it is '%s' (%s)"),
				*WantId, *Job.JobId, MifKr::Jobs::StateName(Job.State)));
			Out->SetStringField(TEXT("note"), HonestyNote);
			return;
		}

		Out->SetBoolField(TEXT("found"), true);
		Out->SetStringField(TEXT("jobId"), Job.JobId);
		Out->SetStringField(TEXT("kind"), Job.Kind);
		// Whether a mid-job poll of THIS kind can observe progress at all. Stated per record rather than
		// left to the general note: polling an atomic kind in a loop is not wrong, but the caller must
		// know the counters CANNOT move until the job ends, so an unchanged poll is not a hung job.
		Out->SetBoolField(TEXT("progressObservable"),
			Job.Kind == TEXT("census") || Job.Kind == TEXT("batch"));
		Out->SetStringField(TEXT("state"), MifKr::Jobs::StateName(Job.State));
		Out->SetStringField(TEXT("phase"), Job.Phase);
		Out->SetStringField(TEXT("mode"), Job.Mode);
		if (!Job.Variant.IsEmpty())      { Out->SetStringField(TEXT("variant"), Job.Variant); }
		if (!Job.FunctionName.IsEmpty()) { Out->SetStringField(TEXT("function"), Job.FunctionName); }
		Out->SetStringField(TEXT("sourceAsset"), Job.SourceAsset);
		Out->SetStringField(TEXT("sourceClassPath"), Job.SourceClassPath);
		Out->SetStringField(TEXT("bpName"), Job.BpName);
		Out->SetStringField(TEXT("targetPath"), Job.TargetPath);
		Out->SetStringField(TEXT("queuedAtUtc"), Job.QueuedAtUtc.ToIso8601());
		Out->SetNumberField(TEXT("elapsedMs"), MifKr::Jobs::ElapsedMs(Job));

		Out->SetNumberField(TEXT("functionsTotalEstimate"), Job.FunctionsTotalEstimate);
		Out->SetNumberField(TEXT("functionsDone"), Job.FunctionsDone);
		Out->SetNumberField(TEXT("functionsReconstructed"), Job.FunctionsReconstructed);
		Out->SetNumberField(TEXT("functionsDegraded"), FMath::Max(0, Job.FunctionsDone - Job.FunctionsReconstructed));
		Out->SetNumberField(TEXT("eventsDone"), Job.EventsDone);
		Out->SetNumberField(TEXT("eventsReconstructed"), Job.EventsReconstructed);
		Out->SetNumberField(TEXT("nodesCreated"), Job.NodesCreated);

		TSharedRef<FJsonObject> Compile = MakeShared<FJsonObject>();
		Compile->SetBoolField(TEXT("measured"), Job.bCompileMeasured);
		Compile->SetNumberField(TEXT("errors"), Job.CompileErrors);
		Compile->SetNumberField(TEXT("warnings"), Job.CompileWarnings);
		if (!Job.FirstError.IsEmpty()) { Compile->SetStringField(TEXT("firstError"), Job.FirstError); }
		if (!Job.bCompileMeasured)
		{
			Compile->SetStringField(TEXT("note"),
				TEXT("errors/warnings are 0 because nothing measured them, NOT because the compile was clean - ")
				TEXT("copy mode compiles inside the engine export. Call validate on result.blueprintId for real numbers."));
		}
		Out->SetObjectField(TEXT("compile"), Compile);

		if (Job.Result.IsValid()) { Out->SetObjectField(TEXT("result"), Job.Result); }
		if (!Job.Error.IsEmpty())  { Out->SetStringField(TEXT("error"), Job.Error); }
		Out->SetStringField(TEXT("note"), HonestyNote);
	}

	// ============================== WAVE 3 — THE VERIFY FAMILY ======================================
	//
	// kr_verify_fidelity, kr_classify_drift, kr_drift_census, kr_batch_reconstruct.
	//
	// ALL FOUR ARE ONE ENGINE CALL. RunTransientBlueprintReconstruct (CompiledBlueprintReconstructor.h,
	// KISMET_API) mints a copy of the cooked class into GetTransientPackage(), runs the SAME
	// PopulateUncookedCopy pipeline F3 and mif.kr.ReconstructAll run, compiles it silently into an
	// FCompilerResultsLog, hands the live UBlueprint to a callback, and then unroots it and marks it
	// RF_Transient ITSELF. Nothing is saved, registered with the AssetRegistry, opened, or dialogged.
	// The four endpoints differ only in what their callback does and how many Blueprints they feed it.
	//
	// THE POINTER RULE, and why it is the first thing in this block: the UBlueprint* handed to the
	// callback is torn down the instant the callback returns, and OutStats.AttemptedFunctions holds raw
	// UFunction* into the COOKED class that are only guaranteed live for the same window. Every callback
	// below therefore copies out ints and FStrings ONLY. Retaining either pointer is a use-after-collect
	// that a census would reproduce 1256 times.
	//
	// WHY NOT REUSE CreateEditableBlueprintCopy (the Wave-1 copy-mode call): it is a persistent asset
	// factory — it calls AssetCreated + MarkPackageDirty + SavePackage unconditionally, and compiles
	// with neither a results log nor bSilentMode. Over a census that is one .uasset write, one registry
	// add and one delete per Blueprint, with compile errors unreportable. See the export's own header.
	//
	// SHIP SAFETY (the block at the top of this file, extended to engine statics): nothing here calls a
	// MIF_KR_DEBUG-gated helper or a symbol with internal linkage in another TU. The engine's
	// IsCompiledBlueprintAsset / ResolveBlueprintClass / RunReconstructOnce are all file-static inside
	// namespace CompiledBlueprintCopyAction and are REIMPLEMENTED here, ungated, from public API.
	//
	// PROGRESS HONESTY. Single-BP jobs (verify, classify) are ATOMIC — the HTTP listener is a
	// game-thread ticker, so nothing is read off the socket while they run. The census and batch sweeps
	// are the exception and the reason the job model exists: they process ONE Blueprint per tick, so
	// between Blueprints the ticker pumps HTTP and a poll genuinely observes progress. Both write their
	// running totals into the job record's result payload on every slice, so kr_reconstruct_status shows
	// live counters with no new status endpoint and no new record fields.

	/** Scoped in-process override of an int CVar, restored on destruction. Used for
	 *  mif.kr.ClassifyIntentional (MifDriftClassifier.cpp:57-62) and mif.kr.DriftCensus (:66-71).
	 *  RAII rather than set-then-set-back at the end of the handler because a census spans MANY ticks
	 *  and any early return in between would otherwise leave the editor permanently in census mode —
	 *  a diagnostic CSV silently growing for the rest of the session. */
	struct FKrScopedCVarInt
	{
		FKrScopedCVarInt(const TCHAR* Name, int32 NewValue)
			: VarName(Name)
		{
			Var = IConsoleManager::Get().FindConsoleVariable(Name);
			if (!Var) { return; }
			Prev = Var->GetInt();
			if (Prev == NewValue) { bApplied = true; return; }

			// A CVar Set is REFUSED, silently and with no return value, when the caller's priority is
			// below the one that last wrote it - and ECVF_SetByConsole (a human typing the CVar into the
			// console) outranks ECVF_SetByCode. Without the read-back below, a caller who asked for
			// classifyIntentional:false would get a run with it ON and no way to tell: exactly the
			// silent-wrong-answer class this bridge refuses. So: try as code, verify, escalate to the
			// console priority only if the polite attempt lost, and remember which one won so the restore
			// uses the same priority (a restore at a lower priority would be refused too).
			Var->Set(NewValue, ECVF_SetByCode);
			if (Var->GetInt() != NewValue)
			{
				SetBy = ECVF_SetByConsole;
				Var->Set(NewValue, SetBy);
			}
			bApplied = (Var->GetInt() == NewValue);
			bChanged = bApplied;
		}
		~FKrScopedCVarInt()
		{
			if (Var && bChanged) { Var->Set(Prev, SetBy); bChanged = false; }
		}
		FKrScopedCVarInt(const FKrScopedCVarInt&) = delete;
		FKrScopedCVarInt& operator=(const FKrScopedCVarInt&) = delete;

		bool Found() const { return Var != nullptr; }
		/** True iff the CVar actually reads back the requested value. False => the request did NOT take
		 *  effect and the caller must be told, never left to assume. */
		bool Applied() const { return Var != nullptr && bApplied; }

		FString VarName;
		IConsoleVariable* Var = nullptr;
		int32 Prev = 0;
		bool  bChanged = false;
		bool  bApplied = false;
		EConsoleVariableFlags SetBy = ECVF_SetByCode;
	};

	/** True for a UAnimBlueprintGeneratedClass (or any subclass of one).
	 *
	 *  THE ANIM TRAP, and why every verify-family endpoint has to know about it: the engine's
	 *  GetBlueprintClassTypesForSource (CompiledBlueprintCopyAction.cpp:216-225) special-cases ONLY
	 *  Widget Blueprints, so an anim source is minted as a PLAIN UBlueprint — which is not a
	 *  UAnimBlueprint, has no AnimGraph, and never routes through the anim compiler. The copy therefore
	 *  loses the entire state-machine/AnimGraph half of the asset and any fidelity number measured on it
	 *  describes a degraded copy, not the decompiler. The engine's own enumeration gate
	 *  (IsCompiledBlueprintAsset:102-119) excludes anim BPGCs by exact class-path equality for exactly
	 *  this reason, so census and batch never see one; the single-BP endpoints have no such gate and
	 *  must refuse (or be forced past this, loudly flagged) instead of returning a meaningless score.
	 *
	 *  Matched by walking the CLASS-OF chain by name rather than Cast<UAnimBlueprintGeneratedClass>:
	 *  naming that type would add an AnimGraphRuntime/Engine-anim include for one predicate, the same
	 *  no-new-dependency reasoning IsWidgetAsset above already applies. */
	static bool KrIsAnimBlueprintClass(const UObject* Obj)
	{
		static const FName AnimBPGCName(TEXT("AnimBlueprintGeneratedClass"));
		for (const UClass* C = Obj ? Obj->GetClass() : nullptr; C; C = C->GetSuperClass())
		{
			if (C->GetFName() == AnimBPGCName) { return true; }
		}
		return false;
	}

	/** Every FBlueprintFidelityReport field, verbatim, plus the three derived numbers.
	 *
	 *  score/adjustedScore are JSON **null** when HasScore() is false — never 1.0 and never the -1.0f
	 *  NoScore sentinel. The report header (CompiledBlueprintReconstructor.h) is explicit that callers
	 *  MUST branch: a Blueprint with zero comparable functions has NO fidelity, and 735 of 1250 corpus
	 *  Blueprints are exactly that (all-event BPs). Emitting 1.000 for them is the flattering lie the
	 *  whole metric exists to avoid. `compared` and `scored` ride alongside every percentage so a
	 *  caller can always see the denominator. */
	static TSharedRef<FJsonObject> KrFidelityJson(const FBlueprintFidelityReport& R)
	{
		TSharedRef<FJsonObject> J = MakeShared<FJsonObject>();
		J->SetNumberField(TEXT("compared"), R.Compared);
		J->SetNumberField(TEXT("identical"), R.Identical);
		J->SetNumberField(TEXT("equivalent"), R.Equivalent);
		J->SetNumberField(TEXT("intentional"), R.Intentional);
		J->SetNumberField(TEXT("drift"), R.Drift);
		J->SetNumberField(TEXT("missing"), R.Missing);
		J->SetNumberField(TEXT("uncomparable"), R.Uncomparable);
		J->SetNumberField(TEXT("scored"), R.Scored());
		if (R.HasScore())
		{
			J->SetNumberField(TEXT("score"), R.Score());
			J->SetNumberField(TEXT("adjustedScore"), R.AdjustedScore());
		}
		else
		{
			J->SetField(TEXT("score"), MakeShared<FJsonValueNull>());
			J->SetField(TEXT("adjustedScore"), MakeShared<FJsonValueNull>());
			J->SetStringField(TEXT("scoreNote"),
				TEXT("null, NOT 1.000: nothing was scored (an all-event Blueprint has no own-class function bytecode to diff). ")
				TEXT("735 of 1250 corpus Blueprints are in this state - treating them as perfect would inflate every aggregate."));
		}
		if (!R.FirstDrift.IsEmpty())       { J->SetStringField(TEXT("firstDrift"), R.FirstDrift); }
		if (!R.IntentTally.IsEmpty())      { J->SetStringField(TEXT("intentTally"), R.IntentTally); }
		if (!R.FirstIntentional.IsEmpty()) { J->SetStringField(TEXT("firstIntentional"), R.FirstIntentional); }
		return J;
	}

	/** One function's verdict, derived from a SINGLE-FUNCTION fidelity report (see KrRunTransientVerify). */
	struct FKrFunctionVerdict
	{
		FString Name;
		FString Verdict;            // identical | equivalent | intentional | drift | missing | uncomparable | not-scored
		TArray<FString> Reasons;    // classifier claim reasons, from the report's IntentTally
		FString Detail;             // the engine-formatted root/audit line, verbatim - never re-parsed
	};

	/** Map a one-element fidelity report onto a verdict. Exactly one counter can be non-zero, because
	 *  VerifyBlueprint's loop forms exactly one verdict per function (MifFidelityVerifier.cpp:460-593);
	 *  ALL-zero means the verifier skipped it (`Script.Num() == 0`), which is reported as its own
	 *  verdict rather than omitted - a silently dropped row is indistinguishable from a function that
	 *  was never attempted. */
	static FKrFunctionVerdict KrVerdictFromSingle(const FString& FnName, const FBlueprintFidelityReport& R)
	{
		FKrFunctionVerdict V;
		V.Name = FnName;
		if      (R.Identical    > 0) { V.Verdict = TEXT("identical"); }
		else if (R.Equivalent   > 0) { V.Verdict = TEXT("equivalent"); }
		else if (R.Intentional  > 0) { V.Verdict = TEXT("intentional"); V.Detail = R.FirstIntentional; }
		else if (R.Drift        > 0) { V.Verdict = TEXT("drift");        V.Detail = R.FirstDrift; }
		else if (R.Missing      > 0) { V.Verdict = TEXT("missing");      V.Detail = R.FirstDrift; }
		else if (R.Uncomparable > 0) { V.Verdict = TEXT("uncomparable");
			V.Detail = TEXT("disassembly aborted, an <unresolved> pointer, or the pair resolved to the same UFunction - excluded from BOTH numerator and denominator on purpose"); }
		else                         { V.Verdict = TEXT("not-scored");
			V.Detail = TEXT("the verifier skipped this function: the cooked side has no bytecode (Script.Num()==0)"); }

		// "flowstack=1;outparam=1" -> ["flowstack","outparam"]. Reading the reasons off the report's own
		// tally rather than off FVerdict: FVerdict never crosses the verifier boundary (it is built and
		// consumed inside MifFidelityVerifier.cpp), and widening that boundary is the lockstep hazard the
		// codebase refuses on principle (CompiledBlueprintReconstructor.h's delegate-arity note).
		TArray<FString> Pairs;
		R.IntentTally.ParseIntoArray(Pairs, TEXT(";"), /*CullEmpty*/ true);
		for (const FString& P : Pairs)
		{
			FString Key, Val;
			if (P.Split(TEXT("="), &Key, &Val)) { V.Reasons.Add(Key); }
		}

		// The classifier's decline-to-REAL contract, made visible. When it produces a root the drift line
		// carries "ROOT:" (MifFidelityVerifier.cpp:568); when it declined on a cap (>2000 statements /
		// LCS cell cap / sim cap, MifDriftClassifier.cpp:81-83) or was switched off, the line falls back
		// to the raw first-diff format with no ROOT. That text difference is the only signal available
		// outside the verifier, and it is reported as such rather than guessed at.
		if (V.Verdict == TEXT("drift") && !V.Detail.Contains(TEXT("ROOT:")))
		{
			V.Reasons.Add(TEXT("classifier-declined-or-off"));
		}
		return V;
	}

	static TSharedRef<FJsonObject> KrVerdictJson(const FKrFunctionVerdict& V)
	{
		TSharedRef<FJsonObject> J = MakeShared<FJsonObject>();
		J->SetStringField(TEXT("name"), V.Name);
		J->SetStringField(TEXT("verdict"), V.Verdict);
		TArray<TSharedPtr<FJsonValue>> Reasons;
		for (const FString& R : V.Reasons) { Reasons.Add(MakeShared<FJsonValueString>(R)); }
		J->SetArrayField(TEXT("reasons"), Reasons);
		if (!V.Detail.IsEmpty()) { J->SetStringField(TEXT("detail"), V.Detail); }
		return J;
	}

	/** Everything one transient reconstruct produced. Pointers deliberately absent - see THE POINTER
	 *  RULE at the top of this block. */
	struct FKrVerifyOutcome
	{
		// "" | "resolve" | "parent" | "mint" - the engine's THREE-WAY skip taxonomy, kept distinct on
		// purpose (CompiledBlueprintCopyAction.cpp:1084-1087). Collapsing them into one "failed" loses
		// the diagnosis: a missing asset, an unparentable class and a failed mint have different fixes.
		FString Skip;
		bool bMinted   = false;
		bool bCompiled = false;      // minted AND compiled clean - the export refuses to score anything else
		bool bVerified = false;      // the bound fidelity delegate actually ran and returned true
		FBlueprintFidelityReport Report;
		int32 FunctionsAttempted = 0, FunctionsReconstructed = 0;
		int32 EventsAttempted = 0, EventsReconstructed = 0;
		int32 CompileErrors = 0, CompileWarnings = 0;
		FString FirstError;
		FString ParentClass;
		TArray<FKrFunctionVerdict> Functions;   // populated only when bPerFunction
		int32 ElapsedMs = 0;
	};

	/** THE shared primitive behind all four endpoints: one mint -> populate -> compile -> (verify).
	 *
	 *  bAsChild=false (the batch sweep's default) mints a SIBLING, which copies the component tree into
	 *  the transient package, so every component reference differs by object path and reports systematic
	 *  FALSE drift. bVerify is therefore only ever passed true together with bAsChild - the callers
	 *  enforce it, the export deliberately does not.
	 *
	 *  bPerFunction re-runs the SAME bound verifier once per attempted function with a ONE-ELEMENT
	 *  denominator. That is how kr_classify_drift gets per-function verdicts with ZERO changes to
	 *  MifFidelityVerifier.cpp: its loop is independent per function, so a single-element call yields
	 *  exactly that function's verdict in the report's own counters. The alternative - a module-static
	 *  capture sink inside the verifier - would put a second, forkable copy of the verdict logic in the
	 *  tree and add a global that must be armed/disarmed correctly on every early return. Cost of this
	 *  choice: the drift path's disassembly + classification runs twice for the classify endpoint only
	 *  (once for the aggregate, once per function), which is what buys the cross-check the response
	 *  reports as `consistent`. */
	static void KrRunTransientVerify(UBlueprintGeneratedClass* SourceBPGC, bool bAsChild, bool bVerify,
		bool bPerFunction, FKrVerifyOutcome& Out)
	{
		const double T0 = FPlatformTime::Seconds();
		if (!SourceBPGC) { Out.Skip = TEXT("resolve"); return; }

		// CHILD parents to the cooked class ITSELF, so the copy IS-A <SourceClass> and INHERITS its
		// components instead of copying them - the only mode fidelity is measurable in. This check lives
		// HERE and not inside the export so SKIP_PARENT keeps its own outcome (:1084-1087).
		UClass* ParentClass = bAsChild ? static_cast<UClass*>(SourceBPGC) : SourceBPGC->GetSuperClass();
		if (!ParentClass || !FKismetEditorUtilities::CanCreateBlueprintOfClass(ParentClass))
		{
			Out.Skip = TEXT("parent");
			if (ParentClass) { Out.ParentClass = ParentClass->GetPathName(); }
			Out.ElapsedMs = (int32)((FPlatformTime::Seconds() - T0) * 1000.0);
			return;
		}
		Out.ParentClass = ParentClass->GetPathName();

		FUncookedCopyStats Stats;
		FCompilerResultsLog Results;
		bool bVerifierRan = false;

		const bool bScored = RunTransientBlueprintReconstruct(SourceBPGC, ParentClass, bAsChild, Stats, Results,
			[&](UBlueprint* ReconBP)
			{
				// THE POINTER RULE: ReconBP is unrooted and RF_Transient'd by the engine the moment this
				// returns, and Stats.AttemptedFunctions holds raw cooked UFunction*. Nothing but ints and
				// FStrings leaves this lambda.
				if (!bVerify || !ReconBP) { return; }
				FOnVerifyBlueprintFidelity& Verifier = GetBlueprintFidelityVerifier();
				if (!Verifier.IsBound())
				{
					// Cannot happen while this endpoint exists (it is registered by the same module that
					// binds the verifier at startup), but checked rather than assumed: an unbound verifier
					// would otherwise leave an all-zero report that reads exactly like a perfect all-event
					// Blueprint. Belt-and-braces, mirroring the engine console command's own check.
					return;
				}
				bVerifierRan = Verifier.Execute(SourceBPGC, ReconBP, Stats.AttemptedFunctions, Out.Report);

				if (!bPerFunction) { return; }
				for (UFunction* Func : Stats.AttemptedFunctions)
				{
					if (!Func) { continue; }
					TArray<UFunction*> OneFunction;
					OneFunction.Add(Func);
					FBlueprintFidelityReport Single;
					Verifier.Execute(SourceBPGC, ReconBP, OneFunction, Single);
					Out.Functions.Add(KrVerdictFromSingle(Func->GetName(), Single));
				}
			});

		// The export returns false for BOTH "the mint failed" and "it compiled with errors", and its
		// contract does not separate them - but the skip taxonomy needs them separated. Discriminate on
		// evidence that the pipeline actually RAN: a failed mint returns before PopulateUncookedCopy and
		// before the compile, leaving both the stats block and the results log pristine. bSilentMode is
		// the sharpest signal (RunReconstructOnce sets it immediately before CompileBlueprint, and
		// FCompilerResultsLog defaults it to false); the rest are corroboration so this degrades to
		// "compile failed" rather than to a wrong skip class if that ever changes.
		Out.bMinted = Results.bSilentMode
			|| Results.Messages.Num() > 0
			|| Stats.AttemptedFunctions.Num() > 0
			|| Stats.FunctionsAttempted > 0
			|| Stats.EventsAttempted > 0;
		Out.bCompiled = bScored;
		Out.bVerified = bVerifierRan;
		Out.FunctionsAttempted     = Stats.FunctionsAttempted;
		Out.FunctionsReconstructed = Stats.FunctionsReconstructed;
		Out.EventsAttempted        = Stats.EventsAttempted;
		Out.EventsReconstructed    = Stats.EventsReconstructed;
		Out.CompileErrors   = Results.NumErrors;
		Out.CompileWarnings = Results.NumWarnings;
		for (const TSharedRef<FTokenizedMessage>& Message : Results.Messages)
		{
			if (Message->GetSeverity() == EMessageSeverity::Error)
			{
				Out.FirstError = Message->ToText().ToString();
				break;
			}
		}
		if (!Out.bMinted) { Out.Skip = TEXT("mint"); }
		Out.ElapsedMs = (int32)((FPlatformTime::Seconds() - T0) * 1000.0);
	}

	/** Stats + compile block, shared by all four result payloads. Events stay in their OWN fields and
	 *  never fold into the function counters: an event body comes from slicing the ubergraph, so it has
	 *  no own-class UFunction to diff and has no place in the fidelity denominator. Folding them would
	 *  silently corrupt the published 54.65% number, whose denominator is AttemptedFunctions. */
	static void KrAddStatsAndCompile(const TSharedRef<FJsonObject>& Into, const FKrVerifyOutcome& O)
	{
		TSharedRef<FJsonObject> Stats = MakeShared<FJsonObject>();
		Stats->SetNumberField(TEXT("functionsAttempted"), O.FunctionsAttempted);
		Stats->SetNumberField(TEXT("functionsReconstructed"), O.FunctionsReconstructed);
		Stats->SetNumberField(TEXT("eventsAttempted"), O.EventsAttempted);
		Stats->SetNumberField(TEXT("eventsReconstructed"), O.EventsReconstructed);
		// Reported because it can be switched off: with mif.kr.Events 0 the engine still invokes the event
		// delegate (so eventsAttempted stays honest) but every body stays a bare stub and
		// eventsReconstructed collapses to 0. Without this field that reads like a decompiler regression.
		if (IConsoleVariable* EventsCVar = IConsoleManager::Get().FindConsoleVariable(TEXT("mif.kr.Events")))
		{
			Stats->SetBoolField(TEXT("eventsEnabled"), EventsCVar->GetInt() != 0);
		}
		Into->SetObjectField(TEXT("stats"), Stats);

		TSharedRef<FJsonObject> Compile = MakeShared<FJsonObject>();
		Compile->SetBoolField(TEXT("measured"), true);   // unlike copy mode, this pipeline owns its results log
		Compile->SetNumberField(TEXT("errors"), O.CompileErrors);
		Compile->SetNumberField(TEXT("warnings"), O.CompileWarnings);
		if (!O.FirstError.IsEmpty()) { Compile->SetStringField(TEXT("firstError"), O.FirstError); }
		Into->SetObjectField(TEXT("compile"), Compile);
	}

	// --- Corpus enumeration (mirror of the engine gate, ungated) -----------------------------------

	/** Mirror of the engine's IsCompiledBlueprintAsset (CompiledBlueprintCopyAction.cpp:102-119) - the
	 *  ONE predicate that decides what F3 and mif.kr.ReconstructAll operate on, and therefore the only
	 *  honest target set for a census or a batch sweep. Reimplemented because that predicate is
	 *  file-static in the engine TU (the SHIP-SAFETY block at the top of this file, applied to engine
	 *  statics). SYNC CONTRACT: if the engine predicate gains a class, this must gain it too.
	 *
	 *  EXACT class-path equality, deliberately NOT the bRecursiveClasses shape kr_list_cooked_blueprints
	 *  uses - and the difference is load-bearing, not an oversight. It is exactly what EXCLUDES
	 *  UAnimBlueprintGeneratedClass (see KrIsAnimBlueprintClass): an anim source mints a plain UBlueprint
	 *  and loses its AnimGraph, so censusing one would feed a degraded copy's score into the corpus
	 *  number this endpoint publishes. Diverging here would corrupt the metric.
	 *
	 *  The two Widget class paths are matched by class NAME rather than by StaticClass()->GetClassPathName()
	 *  for the same no-new-dependency reason IsWidgetAsset gives above: naming UWidgetBlueprint would drag
	 *  UMGEditor into this module's Build.cs for one comparison. */
	static bool KrIsCompiledBlueprintAsset(const FAssetData& A)
	{
		if (!A.IsValid() || (A.PackageFlags & PKG_Cooked) == 0) { return false; }
		if (A.AssetClassPath == UBlueprint::StaticClass()->GetClassPathName()) { return true; }
		if (A.AssetClassPath == UBlueprintGeneratedClass::StaticClass()->GetClassPathName()) { return true; }
		const FString ClassName = A.AssetClassPath.GetAssetName().ToString();
		return ClassName.Equals(TEXT("WidgetBlueprint"), ESearchCase::CaseSensitive)
			|| ClassName.Equals(TEXT("WidgetBlueprintGeneratedClass"), ESearchCase::CaseSensitive);
	}

	struct FKrSweepTarget
	{
		FString ObjectPath;    // re-resolved every slice - never a raw pointer held across ticks
		FString PackageName;
	};

	/** The census/batch target set: cooked, gate-passing, package-deduped, sorted by package name.
	 *  Mirrors the engine batch harness's enumeration (:1149-1169) so a census result is comparable to a
	 *  mif.kr.ReconstructAll run over the same filter. Anim Blueprints are counted as they are excluded
	 *  (OutAnimExcluded) instead of vanishing: a silent exclusion is indistinguishable from an asset that
	 *  was never there, and the anim gap is a known, deliberate limitation that a caller must be able to
	 *  see the size of. */
	static bool KrEnumerateSweepTargets(const FString& PathFilter, TArray<FKrSweepTarget>& OutTargets,
		int32& OutAnimExcluded, int32& OutCorpusTotal, FString& OutError)
	{
		IAssetRegistry& Registry = FModuleManager::LoadModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry")).Get();
		if (Registry.IsLoadingAssets())
		{
			// A partial index would report a SMALLER corpus with ok:true - the silent-wrong-answer class
			// this bridge refuses, and here it would understate a published fidelity number.
			OutError = TEXT("asset registry still scanning; retry after the initial scan completes");
			return false;
		}

		FARFilter Filter;
		Filter.ClassPaths.Add(UBlueprintGeneratedClass::StaticClass()->GetClassPathName());
		Filter.ClassPaths.Add(UBlueprint::StaticClass()->GetClassPathName());
		Filter.bRecursiveClasses = true;   // SEE the anim/widget subclasses, then judge them by the exact gate
		TArray<FAssetData> Assets;
		Registry.GetAssets(Filter, Assets);

		const bool bAllPaths = (PathFilter == TEXT("*"));
		TSet<FName> SeenPackages;
		TSet<FName> AnimPackages;
		TSet<FName> CorpusPackages;
		for (const FAssetData& A : Assets)
		{
			if (!A.IsValid()) { continue; }
			if ((A.PackageFlags & PKG_Cooked) != 0) { CorpusPackages.Add(A.PackageName); }
			// Path filter FIRST so the anim-exclusion count describes the requested set, not the project.
			if (!bAllPaths && !A.PackageName.ToString().Contains(PathFilter)) { continue; }
			if (!KrIsCompiledBlueprintAsset(A))
			{
				if ((A.PackageFlags & PKG_Cooked) != 0
					&& A.AssetClassPath.GetAssetName().ToString().StartsWith(TEXT("AnimBlueprint")))
				{
					AnimPackages.Add(A.PackageName);
				}
				continue;
			}
			if (SeenPackages.Contains(A.PackageName)) { continue; }
			SeenPackages.Add(A.PackageName);
			FKrSweepTarget T;
			T.ObjectPath  = A.GetObjectPathString();
			T.PackageName = A.PackageName.ToString();
			OutTargets.Add(T);
		}

		// Deterministic order: a startIndex resume cursor is meaningless unless the same filter enumerates
		// the same Blueprints in the same order across runs (TSet/TMap iteration order is not an order).
		OutTargets.Sort([](const FKrSweepTarget& L, const FKrSweepTarget& R)
		{
			return L.PackageName < R.PackageName;
		});
		OutAnimExcluded = AnimPackages.Num();
		OutCorpusTotal  = CorpusPackages.Num();
		return true;
	}

	// --- kr_verify_fidelity / kr_classify_drift: the single-BP deferred job ------------------------

	struct FKrVerifyPlan
	{
		FString JobId;
		FString Kind;                 // "verify" | "classify"
		FString SourceClassPath;      // re-resolved after the tick; never a captured raw pointer
		FString SourceAsset;
		FString BpName;
		bool    bClassifyIntentional = true;
		bool    bPerFunction = false;
		bool    bAnimAllowed = false;
		FString FunctionFilter;
	};

	static void KrRunVerifyJob(FKrVerifyPlan Plan)
	{
		using namespace MifKr::Jobs;

		if (!HasRecord() || Get().JobId != Plan.JobId)
		{
			// A stale timer firing against a different job would corrupt that job's counters. Checked,
			// not assumed - the same guard KrRunReconstructJob carries.
			return;
		}

		MarkRunning(TEXT("resolving"));

		FString ResolveError;
		UBlueprintGeneratedClass* BPGC = KrResolveBPGC(Plan.SourceClassPath, ResolveError);
		if (!BPGC)
		{
			Finish(false, FString::Printf(TEXT("source class disappeared between request and execution: %s"), *ResolveError));
			return;
		}

		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[kr job] %s BEGIN kind=%s source=%s classify=%d perFunction=%d"),
			*Plan.JobId, *Plan.Kind, *BPGC->GetPathName(), Plan.bClassifyIntentional ? 1 : 0, Plan.bPerFunction ? 1 : 0);
		if (GLog) { GLog->Flush(); }   // flushed BEGIN marker: a hard crash names the culprit

		// Scoped for THIS job only, restored before the record reports done - so a caller who asks for
		// the pre-classifier audit baseline does not silently leave the editor in that state.
		FKrScopedCVarInt ClassifyScope(TEXT("mif.kr.ClassifyIntentional"), Plan.bClassifyIntentional ? 1 : 0);

		SetPhase(TEXT("reconstructing"));
		FKrVerifyOutcome Outcome;
		KrRunTransientVerify(BPGC, /*bAsChild*/ true, /*bVerify*/ true, Plan.bPerFunction, Outcome);
		SetPhase(TEXT("verifying"));

		FJobRecord& Job = Mutable();
		Job.bCompileMeasured = true;
		Job.CompileErrors = Outcome.CompileErrors;
		Job.CompileWarnings = Outcome.CompileWarnings;
		Job.FirstError = Outcome.FirstError;

		TSharedRef<FJsonObject> Result = MakeShared<FJsonObject>();
		Result->SetStringField(TEXT("sourceAsset"), Plan.SourceAsset);
		Result->SetStringField(TEXT("sourceClass"), BPGC->GetPathName());
		Result->SetBoolField(TEXT("sourceCooked"), KrIsCooked(BPGC));
		Result->SetStringField(TEXT("bpName"), Plan.BpName);
		Result->SetStringField(TEXT("mode"), TEXT("child"));
		Result->SetStringField(TEXT("parentClass"), Outcome.ParentClass);
		Result->SetBoolField(TEXT("classifyIntentional"), Plan.bClassifyIntentional);
		Result->SetBoolField(TEXT("classifyIntentionalApplied"), ClassifyScope.Applied());
		if (!ClassifyScope.Applied())
		{
			Result->SetStringField(TEXT("classifyIntentionalNote"), ClassifyScope.Found()
				? TEXT("mif.kr.ClassifyIntentional could NOT be overridden for this job (something set it at a higher priority) - the numbers below were produced with its CURRENT value, not the requested one")
				: TEXT("mif.kr.ClassifyIntentional is not registered - the classifier is not present in this build, so intentional is structurally 0"));
		}
		Result->SetNumberField(TEXT("elapsedMs"), Outcome.ElapsedMs);
		if (KrIsAnimBlueprintClass(BPGC))
		{
			// Forced past the refusal with allowAnim:true. The numbers are real measurements of a
			// DEGRADED copy - say so in the payload, not only in the request that allowed it.
			Result->SetBoolField(TEXT("animBlueprint"), true);
			Result->SetBoolField(TEXT("allowAnim"), Plan.bAnimAllowed);
			Result->SetBoolField(TEXT("degraded"), true);
			Result->SetStringField(TEXT("degradedReason"),
				TEXT("this is an Animation Blueprint and the engine mints anim sources as a PLAIN UBlueprint ")
				TEXT("(GetBlueprintClassTypesForSource special-cases only Widget), so the copy has no AnimGraph at all. ")
				TEXT("Every number below describes that degraded copy, NOT the decompiler. Do not compare it to the corpus."));
		}

		if (!Outcome.Skip.IsEmpty())
		{
			Job.Result = Result;
			const TCHAR* Why =
				Outcome.Skip == TEXT("parent")
					? TEXT("cannot create a Blueprint parented to this class (FKismetEditorUtilities::CanCreateBlueprintOfClass refused it)")
					: TEXT("could not mint a transient copy (CreateBlueprint failed) - nothing was populated and nothing compiled");
			Result->SetStringField(TEXT("skip"), Outcome.Skip);
			Finish(false, FString::Printf(TEXT("%s: %s"), *Plan.BpName, Why));
			return;
		}

		Result->SetBoolField(TEXT("minted"), Outcome.bMinted);
		Result->SetBoolField(TEXT("compiled"), Outcome.bCompiled);
		KrAddStatsAndCompile(Result, Outcome);

		if (!Outcome.bCompiled)
		{
			// The honesty rule, enforced by the engine export itself: a failed compile leaves the
			// GeneratedClass bytecode absent or stale, so the verifier is never invoked and NO fidelity
			// number can leak. The job is `done` (the work ran and produced a truthful answer), the
			// fidelity block is absent, and the reason is stated - not ok:true with a silent 0/0.
			Result->SetBoolField(TEXT("fidelityMeasured"), false);
			Result->SetStringField(TEXT("error"), FString::Printf(
				TEXT("%s failed to compile (%d errors) - fidelity not measured. A failed compile leaves no trustworthy ")
				TEXT("bytecode to diff, so scoring it would be a lie."), *Plan.BpName, Outcome.CompileErrors));
			Job.Result = Result;
			Finish(true, FString());
			return;
		}

		Result->SetBoolField(TEXT("fidelityMeasured"), Outcome.bVerified);
		Result->SetObjectField(TEXT("fidelity"), KrFidelityJson(Outcome.Report));

		// Numerically checkable invariants, computed here so a caller does not have to trust the prose.
		// scored == identical+equivalent+intentional+drift+missing is the report's own definition, and
		// adjustedScore >= score holds because the adjusted numerator adds intentional to the same
		// denominator. If either is ever false the report is internally inconsistent and the number
		// must not be used - which is exactly why they are reported rather than assumed.
		{
			const FBlueprintFidelityReport& R = Outcome.Report;
			TSharedRef<FJsonObject> Inv = MakeShared<FJsonObject>();
			Inv->SetBoolField(TEXT("scoredEqualsSum"),
				R.Scored() == (R.Identical + R.Equivalent + R.Intentional + R.Drift + R.Missing));
			Inv->SetBoolField(TEXT("adjustedGeScore"), !R.HasScore() || (R.AdjustedScore() >= R.Score()));
			Inv->SetBoolField(TEXT("comparedEqualsScoredMinusMissing"), R.Compared == (R.Scored() - R.Missing));
			Result->SetObjectField(TEXT("invariants"), Inv);
		}

		if (Plan.bPerFunction)
		{
			TArray<TSharedPtr<FJsonValue>> Rows;
			TMap<FString, int32> ByVerdict;
			TMap<FString, int32> ReasonTally;
			bool bFilterFound = Plan.FunctionFilter.IsEmpty();
			TArray<FString> AllNames;
			for (const FKrFunctionVerdict& V : Outcome.Functions)
			{
				AllNames.Add(V.Name);
				++ByVerdict.FindOrAdd(V.Verdict);
				for (const FString& R : V.Reasons) { ++ReasonTally.FindOrAdd(R); }
				if (!Plan.FunctionFilter.IsEmpty())
				{
					if (!V.Name.Equals(Plan.FunctionFilter, ESearchCase::IgnoreCase)) { continue; }
					bFilterFound = true;
				}
				Rows.Add(MakeShared<FJsonValueObject>(KrVerdictJson(V)));
			}
			Result->SetArrayField(TEXT("functions"), Rows);
			Result->SetNumberField(TEXT("functionsReported"), Rows.Num());
			Result->SetNumberField(TEXT("functionsAttemptedRows"), Outcome.Functions.Num());

			TSharedRef<FJsonObject> Counts = MakeShared<FJsonObject>();
			for (const TPair<FString, int32>& KV : ByVerdict) { Counts->SetNumberField(KV.Key, KV.Value); }
			Result->SetObjectField(TEXT("verdictCounts"), Counts);

			// THE cross-check the two-pass design buys: the per-function decomposition and the whole-BP
			// aggregate are produced by two INDEPENDENT verifier runs, so agreement is evidence, not a
			// tautology. A false here means the decomposition is not faithful and the rows must not be
			// trusted - reported as a number rather than asserted away.
			auto CountOf = [&ByVerdict](const TCHAR* Key) { const int32* P = ByVerdict.Find(Key); return P ? *P : 0; };
			const FBlueprintFidelityReport& R = Outcome.Report;
			const bool bConsistent =
				CountOf(TEXT("identical"))    == R.Identical &&
				CountOf(TEXT("equivalent"))   == R.Equivalent &&
				CountOf(TEXT("intentional"))  == R.Intentional &&
				CountOf(TEXT("drift"))        == R.Drift &&
				CountOf(TEXT("missing"))      == R.Missing &&
				CountOf(TEXT("uncomparable")) == R.Uncomparable;
			Result->SetBoolField(TEXT("consistent"), bConsistent);
			if (!bConsistent)
			{
				Result->SetStringField(TEXT("consistentNote"),
					TEXT("the per-function rows do NOT sum to the aggregate report - the decomposition is unfaithful and ")
					TEXT("the rows must not be used. The aggregate (one whole-BP verifier run) is the trustworthy half."));
			}

			TArray<FString> ReasonKeys;
			ReasonTally.GetKeys(ReasonKeys);
			ReasonKeys.Sort();
			TArray<FString> ReasonParts;
			for (const FString& K : ReasonKeys) { ReasonParts.Add(FString::Printf(TEXT("%s=%d"), *K, ReasonTally[K])); }
			Result->SetStringField(TEXT("reasonTally"), FString::Join(ReasonParts, TEXT(";")));

			if (!Plan.FunctionFilter.IsEmpty())
			{
				Result->SetStringField(TEXT("functionFilter"), Plan.FunctionFilter);
				Result->SetBoolField(TEXT("functionFound"), bFilterFound);
				if (!bFilterFound)
				{
					// Never a silent empty array: name what WAS attempted so the caller can correct the
					// spelling instead of concluding the function has no drift.
					TArray<TSharedPtr<FJsonValue>> Names;
					for (const FString& N : AllNames) { Names.Add(MakeShared<FJsonValueString>(N)); }
					Result->SetArrayField(TEXT("attemptedFunctions"), Names);
					Result->SetStringField(TEXT("functionNote"), FString::Printf(
						TEXT("'%s' was never attempted on %s - the decompiler delegate was not invoked on it (it is inherited, ")
						TEXT("has no bytecode, or is the ubergraph). attemptedFunctions lists what WAS attempted."),
						*Plan.FunctionFilter, *Plan.BpName));
				}
			}
			Result->SetStringField(TEXT("perFunctionNote"),
				TEXT("verdicts come from re-running the SAME bound verifier once per attempted function with a one-element ")
				TEXT("denominator, so each row is that function's own verdict. `detail` is the verifier's own root/audit line, ")
				TEXT("verbatim: 'ROOT:' present means the classifier attributed the root cause; absent means it declined ")
				TEXT("(a cap) or is off, and reasons then carry classifier-declined-or-off."));
		}

		Job.Result = Result;
		Finish(true, FString());
	}

	// --- kr_drift_census / kr_batch_reconstruct: the sliced sweep ----------------------------------

	/** Sweep state, alive across ticks. ONE instance, because there is ONE job slot: a second sweep
	 *  cannot exist without the job model first refusing the request. Holds package/object PATHS, never
	 *  UObject pointers - a raw pointer held across a tick boundary (with a CollectGarbage every 25
	 *  Blueprints in between) is precisely the lifetime bug the pipeline's own FGCScopeGuard exists for. */
	struct FKrSweepState
	{
		FString JobId;
		FString Kind;                    // "census" | "batch"
		TArray<FKrSweepTarget> Targets;
		int32 StartIndex = 0;
		int32 Index = 0;                 // absolute index into Targets
		int32 EndIndex = 0;              // exclusive
		bool  bAsChild = true;
		bool  bVerify = true;
		bool  bClassifyIntentional = true;
		FString PathFilter;
		int32 AnimExcluded = 0;
		int32 CorpusTotal = 0;

		int32 Pass = 0, Fail = 0, Skip = 0;
		int32 SkipResolve = 0, SkipParent = 0, SkipMint = 0;
		int32 Identical = 0, Equivalent = 0, Intentional = 0, Drift = 0, Missing = 0, Uncomparable = 0;
		int32 FunctionsAttempted = 0, FunctionsReconstructed = 0;
		int32 EventsAttempted = 0, EventsReconstructed = 0;
		TMap<FString, int32> IntentTally;

		int32 GcRuns = 0;
		int32 LastBpMs = 0, MaxBpMs = 0;
		FString MaxBpName;
		FString CurrentPackage;

		TUniquePtr<FArchive> Csv;
		FString CsvPath;
		int32 CsvRows = 0;

		TUniquePtr<FKrScopedCVarInt> ClassifyScope;
		TUniquePtr<FKrScopedCVarInt> CensusScope;
	};

	static TUniquePtr<FKrSweepState> GSweep;

	static void KrSweepWriteCsvLine(FKrSweepState& S, const FString& Line)
	{
		if (!S.Csv) { return; }
		const FString L = Line + LINE_TERMINATOR;
		FTCHARToUTF8 Conv(*L);
		S.Csv->Serialize((void*)Conv.Get(), Conv.Length());
		S.Csv->Flush();   // per row: a hard engine assert must preserve partial results AND name the culprit
	}

	static FString KrCsvCell(const FString& S)
	{
		return S.Replace(TEXT(","), TEXT(";")).Replace(TEXT("\n"), TEXT(" ")).Replace(TEXT("\r"), TEXT(" "));
	}

	/** The running/final payload, rebuilt every slice so a mid-sweep poll sees live numbers. */
	static TSharedRef<FJsonObject> KrSweepResultJson(const FKrSweepState& S, bool bFinal)
	{
		TSharedRef<FJsonObject> R = MakeShared<FJsonObject>();

		TSharedRef<FJsonObject> FilterEcho = MakeShared<FJsonObject>();
		FilterEcho->SetStringField(TEXT("pathFilter"), S.PathFilter);
		FilterEcho->SetNumberField(TEXT("startIndex"), S.StartIndex);
		FilterEcho->SetStringField(TEXT("mode"), S.bAsChild ? TEXT("child") : TEXT("sibling"));
		FilterEcho->SetBoolField(TEXT("verify"), S.bVerify);
		FilterEcho->SetBoolField(TEXT("classifyIntentional"), S.bClassifyIntentional);
		// Reported, not assumed: a CVar Set is refused silently when something wrote it at a higher
		// priority, and a census whose instrument never turned on must say so rather than return an
		// empty CSV that reads like "no unclaimed drift".
		FilterEcho->SetBoolField(TEXT("classifyIntentionalApplied"), S.ClassifyScope.IsValid() && S.ClassifyScope->Applied());
		if (S.CensusScope.IsValid())
		{
			FilterEcho->SetBoolField(TEXT("driftCensusApplied"), S.CensusScope->Applied());
		}
		FilterEcho->SetBoolField(TEXT("cookedOnly"), true);
		R->SetObjectField(TEXT("filter"), FilterEcho);

		const int32 Done = S.Index - S.StartIndex;
		R->SetNumberField(TEXT("bpTotal"), S.EndIndex - S.StartIndex);
		R->SetNumberField(TEXT("bpDone"), Done);
		R->SetNumberField(TEXT("bpIndexAbsolute"), S.Index);
		R->SetNumberField(TEXT("corpusPackages"), S.CorpusTotal);
		R->SetNumberField(TEXT("pass"), S.Pass);
		R->SetNumberField(TEXT("fail"), S.Fail);
		R->SetNumberField(TEXT("skip"), S.Skip);
		R->SetBoolField(TEXT("complete"), bFinal);
		if (!S.CurrentPackage.IsEmpty() && !bFinal) { R->SetStringField(TEXT("currentPackage"), S.CurrentPackage); }

		TSharedRef<FJsonObject> Tax = MakeShared<FJsonObject>();
		Tax->SetNumberField(TEXT("resolve"), S.SkipResolve);
		Tax->SetNumberField(TEXT("parent"), S.SkipParent);
		Tax->SetNumberField(TEXT("mint"), S.SkipMint);
		R->SetObjectField(TEXT("skipTaxonomy"), Tax);

		TSharedRef<FJsonObject> Stats = MakeShared<FJsonObject>();
		Stats->SetNumberField(TEXT("functionsAttempted"), S.FunctionsAttempted);
		Stats->SetNumberField(TEXT("functionsReconstructed"), S.FunctionsReconstructed);
		Stats->SetNumberField(TEXT("eventsAttempted"), S.EventsAttempted);
		Stats->SetNumberField(TEXT("eventsReconstructed"), S.EventsReconstructed);
		if (IConsoleVariable* EventsCVar = IConsoleManager::Get().FindConsoleVariable(TEXT("mif.kr.Events")))
		{
			Stats->SetBoolField(TEXT("eventsEnabled"), EventsCVar->GetInt() != 0);   // see KrAddStatsAndCompile
		}
		R->SetObjectField(TEXT("stats"), Stats);

		if (S.bVerify)
		{
			const int32 Scored = S.Identical + S.Equivalent + S.Intentional + S.Drift + S.Missing;
			TSharedRef<FJsonObject> Totals = MakeShared<FJsonObject>();
			Totals->SetNumberField(TEXT("identical"), S.Identical);
			Totals->SetNumberField(TEXT("equivalent"), S.Equivalent);
			Totals->SetNumberField(TEXT("intentional"), S.Intentional);
			Totals->SetNumberField(TEXT("drift"), S.Drift);
			Totals->SetNumberField(TEXT("missing"), S.Missing);
			Totals->SetNumberField(TEXT("uncomparable"), S.Uncomparable);
			Totals->SetNumberField(TEXT("compared"), Scored);
			R->SetObjectField(TEXT("totals"), Totals);

			// RAW AND ADJUSTED, ALWAYS TOGETHER. An adjusted number quoted without its raw twin is how a
			// metric starts lying; and neither describes the all-event Blueprints, which score nothing at
			// all. Both are null when nothing was scored - never 1.000, never a sentinel.
			if (Scored > 0)
			{
				R->SetNumberField(TEXT("corpusFidelity"), float(S.Identical + S.Equivalent) / float(Scored));
				R->SetNumberField(TEXT("corpusAdjusted"), float(S.Identical + S.Equivalent + S.Intentional) / float(Scored));
			}
			else
			{
				R->SetField(TEXT("corpusFidelity"), MakeShared<FJsonValueNull>());
				R->SetField(TEXT("corpusAdjusted"), MakeShared<FJsonValueNull>());
			}

			TArray<FString> Keys;
			S.IntentTally.GetKeys(Keys);
			Keys.Sort();
			TArray<FString> Parts;
			for (const FString& K : Keys) { Parts.Add(FString::Printf(TEXT("%s=%d"), *K, S.IntentTally[K])); }
			R->SetStringField(TEXT("intentTally"), FString::Join(Parts, TEXT(";")));
		}

		R->SetNumberField(TEXT("animExcluded"), S.AnimExcluded);
		R->SetStringField(TEXT("animNote"),
			TEXT("Animation Blueprints are EXCLUDED from the target set by the same exact-class-path gate F3 uses: an anim ")
			TEXT("source mints a plain UBlueprint and loses its AnimGraph, so its score would describe the mint, not the ")
			TEXT("decompiler. Counted here so the exclusion is visible, never silent."));

		R->SetNumberField(TEXT("lastBpMs"), S.LastBpMs);
		R->SetNumberField(TEXT("maxBpMs"), S.MaxBpMs);
		if (!S.MaxBpName.IsEmpty()) { R->SetStringField(TEXT("maxBpName"), S.MaxBpName); }
		R->SetNumberField(TEXT("gcRuns"), S.GcRuns);
		R->SetNumberField(TEXT("resumeHint"), S.Index);
		R->SetStringField(TEXT("resumeNote"),
			TEXT("if the editor dies mid-sweep, re-issue the SAME call with startIndex = resumeHint; the target order is ")
			TEXT("sorted by package name, so the enumeration is stable across runs."));

		if (!S.CsvPath.IsEmpty())
		{
			R->SetStringField(TEXT("csvPath"), S.CsvPath);
			R->SetNumberField(TEXT("csvRows"), S.CsvRows);
		}
		else
		{
			R->SetField(TEXT("csvPath"), MakeShared<FJsonValueNull>());
			R->SetStringField(TEXT("csvNote"),
				TEXT("the per-Blueprint CSV could not be opened; the counters above are unaffected (the CSV is the forensic copy, not the answer)"));
		}
		return R;
	}

	/** Corpus reference numbers the reconstructor has already recorded, echoed so a census result is
	 *  comparable to them without a human going to look them up. These are the published baseline; a
	 *  census over the SAME filter that lands far from them is a decompiler regression, not noise. */
	static void KrAddCorpusBaseline(const TSharedRef<FJsonObject>& Into)
	{
		TSharedRef<FJsonObject> B = MakeShared<FJsonObject>();
		B->SetNumberField(TEXT("cookedBlueprintPackagesAnalysed"), 1277);
		B->SetNumberField(TEXT("batchBlueprints"), 1256);
		B->SetNumberField(TEXT("batchPass"), 1228);
		B->SetNumberField(TEXT("rawFidelityPct"), 54.65);
		B->SetNumberField(TEXT("eventsReconstructedPct"), 85.9);
		B->SetNumberField(TEXT("allEventBlueprintsScoringNothing"), 735);
		B->SetNumberField(TEXT("allEventBlueprintsOf"), 1250);
		B->SetStringField(TEXT("note"),
			TEXT("published corpus baseline for comparison ONLY - it is not this run's data. A run over a narrower ")
			TEXT("pathFilter is not comparable to it; only a whole-corpus run is."));
		Into->SetObjectField(TEXT("corpusBaseline"), B);
	}

	/** Newest <ProjectSaved>/MifKr/DriftCensus_*.csv, plus its size and row count.
	 *
	 *  Discovered by SCANNING rather than reported by the classifier: the classifier opens that file
	 *  lazily on the first unclaimed edit, keeps it in a file-static TUniquePtr for the rest of the
	 *  session, and exposes no accessor - and it is inside another TU, so nothing here may reach in.
	 *  Reporting the scan honestly (with censusCsvDiscovered) beats either inventing a path or
	 *  returning nothing. */
	static void KrAttachCensusCsv(const TSharedRef<FJsonObject>& Into)
	{
		const FString Dir = FPaths::ProjectSavedDir() / TEXT("MifKr");
		TArray<FString> Files;
		IFileManager::Get().FindFiles(Files, *(Dir / TEXT("DriftCensus_*.csv")), /*Files*/ true, /*Directories*/ false);
		FString BestPath;
		FDateTime BestStamp = FDateTime::MinValue();
		for (const FString& F : Files)
		{
			const FString Full = Dir / F;
			const FDateTime Stamp = IFileManager::Get().GetTimeStamp(*Full);
			if (Stamp > BestStamp) { BestStamp = Stamp; BestPath = Full; }
		}
		if (BestPath.IsEmpty())
		{
			Into->SetField(TEXT("censusCsvPath"), MakeShared<FJsonValueNull>());
			Into->SetStringField(TEXT("censusCsvNote"),
				TEXT("no DriftCensus_*.csv exists under <ProjectSaved>/MifKr - the census file is written only when an ")
				TEXT("UNCLAIMED drift edit occurs, so zero rows means zero unclaimed edits. Verdicts are unaffected either ")
				TEXT("way (the census is diagnostic only)."));
			return;
		}
		Into->SetStringField(TEXT("censusCsvPath"), BestPath);
		Into->SetNumberField(TEXT("censusCsvBytes"), (double)IFileManager::Get().FileSize(*BestPath));
		Into->SetStringField(TEXT("censusCsvModifiedUtc"), BestStamp.ToIso8601());

		// Row count so the caller can check it against the drift totals. Capped: reading an unbounded
		// diagnostic file into memory inside a game-thread handler is not worth a nicer number.
		const int64 Size = IFileManager::Get().FileSize(*BestPath);
		if (Size >= 0 && Size <= 4 * 1024 * 1024)
		{
			FString Text;
			if (FFileHelper::LoadFileToString(Text, *BestPath))
			{
				int32 Lines = 0;
				for (int32 i = 0; i < Text.Len(); ++i) { if (Text[i] == TEXT('\n')) { ++Lines; } }
				Into->SetNumberField(TEXT("censusCsvRows"), FMath::Max(0, Lines - 1));   // minus the header
			}
		}
		else
		{
			Into->SetStringField(TEXT("censusCsvRowsNote"),
				TEXT("row count not computed: the file exceeds the 4 MB read cap for a game-thread handler"));
		}
		Into->SetStringField(TEXT("censusCsvNote"),
			TEXT("DISCOVERED BY SCANNING <ProjectSaved>/MifKr for the newest DriftCensus_*.csv - the classifier opens that ")
			TEXT("file lazily and exposes no path accessor. It is opened ONCE per editor session, so a second census in the ")
			TEXT("same session APPENDS to the same file: compare censusCsvRows across runs, not in absolute terms."));
	}

	static void KrSweepTick();

	static void KrSweepFinish(FKrSweepState& S, bool bOk, const FString& Error)
	{
		using namespace MifKr::Jobs;

		// Mirrors the engine batch harness's closing collect (:1306). Between-Blueprint only, never
		// inside one: the decompiler holds raw UFunction*/UClass* while a Blueprint is in flight.
		CollectGarbage(GARBAGE_COLLECTION_KEEPFLAGS);
		++S.GcRuns;

		if (S.Csv)
		{
			const int32 Scored = S.Identical + S.Equivalent + S.Intentional + S.Drift + S.Missing;
			KrSweepWriteCsvLine(S, FString::Printf(
				TEXT("# TOTAL pass=%d fail=%d skip=%d of %d | ident=%d equiv=%d intentional=%d drift=%d missing=%d uncomparable=%d compared=%d"),
				S.Pass, S.Fail, S.Skip, S.EndIndex - S.StartIndex,
				S.Identical, S.Equivalent, S.Intentional, S.Drift, S.Missing, S.Uncomparable, Scored));
			S.Csv->Flush();
			S.Csv.Reset();
		}

		TSharedRef<FJsonObject> Result = KrSweepResultJson(S, /*bFinal*/ true);
		if (S.Kind == TEXT("census"))
		{
			KrAttachCensusCsv(Result);
			KrAddCorpusBaseline(Result);
		}
		Result->SetStringField(TEXT("note"),
			TEXT("sliced ONE Blueprint per tick, so bpDone advanced across polls - this is the only kr job kind with real ")
			TEXT("mid-job progress. pass+fail+skip == bpDone, and skipTaxonomy sums to skip. Every throwaway copy was minted ")
			TEXT("into the transient package and torn down by the engine: nothing was saved, registered or opened."));

		FJobRecord& Job = Mutable();
		Job.Result = Result;
		Job.bCompileMeasured = true;

		// The CVar overrides are released HERE, before the record reports done - so a caller that polls
		// `done` and immediately runs a console verify is not silently in census mode.
		S.CensusScope.Reset();
		S.ClassifyScope.Reset();

		Finish(bOk, Error);
		GSweep.Reset();
	}

	/** ONE Blueprint, then re-arm. The whole point: between slices the game-thread ticker pumps HTTP, so
	 *  a poll is actually read and answered. A synchronous loop here would stall the listener for the
	 *  entire sweep and make progress physically unobservable. */
	static void KrSweepTick()
	{
		using namespace MifKr::Jobs;

		if (!GSweep) { return; }
		FKrSweepState& S = *GSweep;

		if (!HasRecord() || Get().JobId != S.JobId)
		{
			// The slot was taken by another job - abandon quietly rather than corrupt its counters.
			GSweep.Reset();
			return;
		}
		if (!GEditor)
		{
			KrSweepFinish(S, false, TEXT("GEditor disappeared mid-sweep - the remaining Blueprints were not processed"));
			return;
		}

		MarkRunning(TEXT("sweeping"));

		if (S.Index >= S.EndIndex)
		{
			KrSweepFinish(S, true, FString());
			return;
		}

		const FKrSweepTarget Target = S.Targets[S.Index];
		S.CurrentPackage = Target.PackageName;

		// Flushed BEGIN marker, mirroring the engine harness (:1222-1224): if a Blueprint hard-asserts
		// mid-sweep the last line in the log names the exact culprit, and resumeHint names where to resume.
		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[kr %s] %s %d/%d BEGIN %s"),
			*S.Kind, *S.JobId, S.Index, S.EndIndex - 1, *Target.PackageName);
		if (GLog) { GLog->Flush(); }

		FString ResolveError;
		UBlueprintGeneratedClass* BPGC = KrResolveBPGC(Target.ObjectPath, ResolveError);

		FKrVerifyOutcome Outcome;
		if (!BPGC)
		{
			Outcome.Skip = TEXT("resolve");
		}
		else
		{
			KrRunTransientVerify(BPGC, S.bAsChild, S.bVerify, /*bPerFunction*/ false, Outcome);
		}

		const FString BpName = BPGC ? BPGC->GetName() : FString();
		S.LastBpMs = Outcome.ElapsedMs;
		if (Outcome.ElapsedMs > S.MaxBpMs) { S.MaxBpMs = Outcome.ElapsedMs; S.MaxBpName = Target.PackageName; }

		if (!Outcome.Skip.IsEmpty())
		{
			++S.Skip;
			if      (Outcome.Skip == TEXT("resolve")) { ++S.SkipResolve; }
			else if (Outcome.Skip == TEXT("parent"))  { ++S.SkipParent; }
			else                                      { ++S.SkipMint; }
			// Skip rows carry the base 9 fields and are padded out so they still line up under the
			// 17-column verify header - the engine harness's own convention.
			const FString Row = FString::Printf(TEXT("%d,%s,%s,,,SKIP_%s,,,"),
				S.Index, *KrCsvCell(Target.PackageName), *KrCsvCell(BpName), *Outcome.Skip.ToUpper());
			KrSweepWriteCsvLine(S, Row + (S.bVerify ? FString::ChrN(8, TEXT(',')) : FString()));
			++S.CsvRows;
		}
		else
		{
			const bool bFail = !Outcome.bCompiled;
			if (bFail) { ++S.Fail; } else { ++S.Pass; }

			S.FunctionsAttempted     += Outcome.FunctionsAttempted;
			S.FunctionsReconstructed += Outcome.FunctionsReconstructed;
			S.EventsAttempted        += Outcome.EventsAttempted;
			S.EventsReconstructed    += Outcome.EventsReconstructed;

			const FBlueprintFidelityReport& F = Outcome.Report;
			if (S.bVerify)
			{
				S.Identical += F.Identical; S.Equivalent += F.Equivalent; S.Intentional += F.Intentional;
				S.Drift     += F.Drift;     S.Missing    += F.Missing;    S.Uncomparable += F.Uncomparable;
				TArray<FString> Pairs;
				F.IntentTally.ParseIntoArray(Pairs, TEXT(";"), /*CullEmpty*/ true);
				for (const FString& P : Pairs)
				{
					FString Key, Val;
					if (P.Split(TEXT("="), &Key, &Val)) { S.IntentTally.FindOrAdd(Key) += FCString::Atoi(*Val); }
				}
			}

			if (S.bVerify)
			{
				// EMPTY fidelity cells when nothing was scored - a 0-function BP must never write a 1.000
				// row into a file someone will average.
				const FString FidCell = F.HasScore() ? FString::Printf(TEXT("%.3f"), F.Score()) : FString();
				const FString AdjCell = F.HasScore() ? FString::Printf(TEXT("%.3f"), F.AdjustedScore()) : FString();
				KrSweepWriteCsvLine(S, FString::Printf(TEXT("%d,%s,%s,%d,%d,%s,%d,%d,%d,%d,%d,%d,%s,%s,%s,%s,%s"),
					S.Index, *KrCsvCell(Target.PackageName), *KrCsvCell(BpName),
					Outcome.FunctionsAttempted, Outcome.FunctionsReconstructed,
					bFail ? TEXT("FAIL") : TEXT("PASS"), Outcome.CompileErrors, Outcome.CompileWarnings,
					F.Identical, F.Equivalent, F.Intentional, F.Drift, *FidCell, *AdjCell,
					*KrCsvCell(F.IntentTally), *KrCsvCell(F.FirstDrift), *KrCsvCell(Outcome.FirstError)));
			}
			else
			{
				KrSweepWriteCsvLine(S, FString::Printf(TEXT("%d,%s,%s,%d,%d,%s,%d,%d,%s"),
					S.Index, *KrCsvCell(Target.PackageName), *KrCsvCell(BpName),
					Outcome.FunctionsAttempted, Outcome.FunctionsReconstructed,
					bFail ? TEXT("FAIL") : TEXT("PASS"), Outcome.CompileErrors, Outcome.CompileWarnings,
					*KrCsvCell(Outcome.FirstError)));
			}
			++S.CsvRows;
		}

		++S.Index;

		// GC cadence copied from the engine harness (:1303): every 25 Blueprints, counted from the
		// resume cursor, BETWEEN Blueprints. Never inside one - the throwaway copy is already torn down
		// by the export at this point, but the decompiler's IR holds raw pointers while a BP is in flight.
		if (((S.Index - S.StartIndex) % 25) == 0)
		{
			CollectGarbage(GARBAGE_COLLECTION_KEEPFLAGS);
			++S.GcRuns;
		}

		Mutable().Result = KrSweepResultJson(S, /*bFinal*/ false);
		SetPhase(*FString::Printf(TEXT("sweeping %d/%d"), S.Index - S.StartIndex, S.EndIndex - S.StartIndex));

		if (S.Index >= S.EndIndex)
		{
			KrSweepFinish(S, true, FString());
			return;
		}
		GEditor->GetTimerManager()->SetTimerForNextTick(FTimerDelegate::CreateLambda([]() { KrSweepTick(); }));
	}

	/** Shared front half of kr_drift_census and kr_batch_reconstruct: enumerate, take the slot, open the
	 *  CSV, scope the CVars, arm the first tick. Writes the queued response into Out. */
	static void KrStartSweep(const TSharedRef<FJsonObject>& Out, const TCHAR* Kind, const FString& PathFilter,
		int32 StartIndex, int32 MaxCount, bool bAsChild, bool bVerify, bool bClassifyIntentional, bool bCensusCvar)
	{
		if (!GEditor)
		{
			KrFail(Out, FString::Printf(
				TEXT("no GEditor - %s slices its work through the editor timer manager and cannot run in a commandlet"), Kind));
			return;
		}

		TArray<FKrSweepTarget> Targets;
		int32 AnimExcluded = 0, CorpusTotal = 0;
		FString EnumError;
		if (!KrEnumerateSweepTargets(PathFilter, Targets, AnimExcluded, CorpusTotal, EnumError))
		{
			KrFail(Out, EnumError);
			return;
		}

		if (StartIndex > Targets.Num())
		{
			KrFail(Out, FString::Printf(
				TEXT("startIndex %d is past the end of the target set (%d cooked Blueprints match pathFilter '%s')"),
				StartIndex, Targets.Num(), *PathFilter));
			return;
		}

		const int32 EndIndex = (MaxCount <= 0)
			? Targets.Num()
			: FMath::Min(Targets.Num(), StartIndex + MaxCount);

		FString JobId, BeginError;
		if (!MifKr::Jobs::TryBegin(Kind, JobId, BeginError))
		{
			KrFail(Out, BeginError);
			return;
		}

		TUniquePtr<FKrSweepState> S = MakeUnique<FKrSweepState>();
		S->JobId = JobId;
		S->Kind = Kind;
		S->Targets = MoveTemp(Targets);
		S->StartIndex = StartIndex;
		S->Index = StartIndex;
		S->EndIndex = EndIndex;
		S->bAsChild = bAsChild;
		S->bVerify = bVerify;
		S->bClassifyIntentional = bClassifyIntentional;
		S->PathFilter = PathFilter;
		S->AnimExcluded = AnimExcluded;
		S->CorpusTotal = CorpusTotal;

		// One CSV per JOB, named with the jobId: a partial HTTP sweep and a full console
		// mif.kr.ReconstructAll run must never be mistaken for one another when someone finds two files
		// in that folder a week later. Column set is the engine harness's, exactly (9 without verify,
		// 17 with), so the two are diffable.
		const FString ReportDir = FPaths::ProjectSavedDir() / TEXT("MifKr");
		IFileManager::Get().MakeDirectory(*ReportDir, /*Tree*/ true);
		S->CsvPath = ReportDir / FString::Printf(TEXT("%s_%s_%s_%s.csv"),
			(S->Kind == TEXT("census")) ? TEXT("KrCensus") : TEXT("KrBatch"),
			bAsChild ? TEXT("child") : TEXT("sibling"),
			*FDateTime::Now().ToString(TEXT("%Y%m%d_%H%M%S")), *JobId);
		S->Csv.Reset(IFileManager::Get().CreateFileWriter(*S->CsvPath, FILEWRITE_AllowRead));
		if (!S->Csv)
		{
			// Not fatal: the counters are the answer, the CSV is the forensic copy. Say so rather than
			// failing a multi-minute job over a file handle.
			S->CsvPath.Empty();
		}
		else
		{
			KrSweepWriteCsvLine(*S, bVerify
				? TEXT("Index,Package,Blueprint,RealFuncs,Reconstructed,Status,Errors,Warnings,Ident,Equiv,Intent,Drift,Fidelity,AdjFidelity,IntentTally,FirstDrift,FirstError")
				: TEXT("Index,Package,Blueprint,RealFuncs,Reconstructed,Status,Errors,Warnings,FirstError"));
		}

		S->ClassifyScope = MakeUnique<FKrScopedCVarInt>(TEXT("mif.kr.ClassifyIntentional"), bClassifyIntentional ? 1 : 0);
		if (bCensusCvar)
		{
			S->CensusScope = MakeUnique<FKrScopedCVarInt>(TEXT("mif.kr.DriftCensus"), 1);
		}

		{
			MifKr::Jobs::FJobRecord& Job = MifKr::Jobs::Mutable();
			Job.SourceAsset = PathFilter;
			Job.BpName = FString::Printf(TEXT("%d blueprint(s)"), EndIndex - StartIndex);
			Job.Mode = bAsChild ? TEXT("child") : TEXT("sibling");
			Job.TargetPath = S->CsvPath;
			Job.FunctionsTotalEstimate = 0;   // unknowable up front across N Blueprints; the DONE counts are authoritative
			Job.Result = KrSweepResultJson(*S, /*bFinal*/ false);
		}

		const int32 BpTotal = EndIndex - StartIndex;
		const bool bEmpty = (BpTotal <= 0);
		GSweep = MoveTemp(S);

		Out->SetStringField(TEXT("jobId"), JobId);
		Out->SetStringField(TEXT("kind"), Kind);
		Out->SetStringField(TEXT("state"), TEXT("queued"));
		Out->SetStringField(TEXT("pathFilter"), PathFilter);
		Out->SetStringField(TEXT("mode"), bAsChild ? TEXT("child") : TEXT("sibling"));
		Out->SetBoolField(TEXT("verify"), bVerify);
		Out->SetBoolField(TEXT("classifyIntentional"), bClassifyIntentional);
		Out->SetNumberField(TEXT("startIndex"), StartIndex);
		Out->SetNumberField(TEXT("bpTotal"), BpTotal);
		Out->SetNumberField(TEXT("matched"), GSweep->Targets.Num());
		Out->SetNumberField(TEXT("animExcluded"), AnimExcluded);
		Out->SetNumberField(TEXT("corpusPackages"), CorpusTotal);
		if (!GSweep->CsvPath.IsEmpty()) { Out->SetStringField(TEXT("csvPath"), GSweep->CsvPath); }
		Out->SetBoolField(TEXT("deferred"), true);
		Out->SetStringField(TEXT("note"),
			TEXT("DEFERRED and SLICED: this call did NOT do the work. One Blueprint is processed per editor tick, so ")
			TEXT("kr_reconstruct_status genuinely advances mid-job (bpDone) - unlike the single-Blueprint kinds, which are ")
			TEXT("atomic. There is ONE job slot and no queue. Poll kr_reconstruct_status; result.resumeHint is the ")
			TEXT("startIndex to pass if the editor dies mid-sweep."));

		if (bEmpty)
		{
			Out->SetStringField(TEXT("hint"), FString::Printf(
				TEXT("zero cooked Blueprints match pathFilter '%s' at startIndex %d - pass \"*\" for every mounted root, or ")
				TEXT("size the corpus first with kr_list_cooked_blueprints"), *PathFilter, StartIndex));
		}

		// Armed even when empty: the job must reach `done` with bpTotal:0 rather than sit queued forever.
		GEditor->GetTimerManager()->SetTimerForNextTick(FTimerDelegate::CreateLambda([]() { KrSweepTick(); }));
	}

	// --- kr_verify_fidelity ------------------------------------------------------------------------
	//   in:  { sourceAsset [REQUIRED] (aliases: blueprint, bpName, path),
	//          classifyIntentional?: bool (default true; alias classify),
	//          allowAnim?: bool (default false) }
	//   out: { jobId, kind:"verify", state:"queued", sourceAsset, sourceClassPath, sourceCooked,
	//          bpName, mode:"child", classifyIntentional, functionsTotalEstimate, deferred:true, note }
	//   result (via kr_reconstruct_status): { fidelity{...}, stats{...}, compile{...}, invariants{...} }
	//
	// Reconstruct a THROWAWAY transient CHILD of the cooked class, compile it, and diff every
	// reconstructed function's recompiled bytecode against the cooked original. Turns "it compiled" into
	// "it provably behaves like the original", with the exact function and statement where it does not.
	//
	// NO `variant`/`mode` PARAMETER EXISTS, ON PURPOSE: fidelity is CHILD-ONLY. A sibling is minted into
	// the transient package and COPIES the component tree, so every component reference differs by object
	// path and reports systematic FALSE drift - a number that measures the mode, not the decompiler.
	//
	// Bucket SELF-MANAGED: the deferred slice runs a full FKismetEditorUtilities::CompileBlueprint. A full
	// compile inside a blanket undo transaction means reinstancing captured by an undo step, i.e. a dead
	// CDO. SelfManaged also makes the endpoint compile-heavy, fencing it out of batch's open transaction.
	//
	// COOKED CONTENT: cooked is the target, but a loose/authored Blueprint is deliberately ACCEPTED - that
	// is the ground-truth loop (author a BP with the bridge, reconstruct it, diff against what you built).
	static void H_kr_verify_fidelity(const TSharedRef<FJsonObject>& In, const TSharedRef<FJsonObject>& Out)
	{
		if (KrRejectUnknownParams(In, Out,
			{ TEXT("sourceAsset"), TEXT("blueprint"), TEXT("bpName"), TEXT("path"),
			  TEXT("classifyIntentional"), TEXT("classify"), TEXT("allowAnim") },
			TEXT("sourceAsset (aliases: blueprint, bpName, path), classifyIntentional (alias: classify), allowAnim"),
			{{ TEXT("variant"),
			   TEXT("does not exist here - fidelity is CHILD-ONLY: a sibling copy mints its components into the transient package, so every component reference differs by object path and reports systematic FALSE drift") },
			 { TEXT("mode"),
			   TEXT("does not exist here - this endpoint always mints a transient CHILD; use kr_batch_reconstruct for a sibling sweep") },
			 { TEXT("function"),
			   TEXT("not a filter here - kr_verify_fidelity reports the whole-Blueprint aggregate; use kr_classify_drift for per-function verdicts") },
			 { TEXT("targetPath"),
			   TEXT("not a parameter - nothing is saved: the copy is minted into the transient package and torn down by the engine") },
			 { TEXT("wait"),
			   TEXT("not implemented - the job is deferred one tick and cannot be waited on inside this request; poll kr_reconstruct_status") }}))
		{
			return;
		}

		if (MifKr::Jobs::IsBusy())
		{
			const MifKr::Jobs::FJobRecord& Running = MifKr::Jobs::Get();
			KrFail(Out, MifKr::Jobs::BusyMessage());
			Out->SetStringField(TEXT("runningJobId"), Running.JobId);
			Out->SetStringField(TEXT("runningKind"), Running.Kind);
			Out->SetStringField(TEXT("runningState"), MifKr::Jobs::StateName(Running.State));
			return;
		}
		if (!GEditor)
		{
			KrFail(Out, TEXT("no GEditor - kr_verify_fidelity defers its work through the editor timer manager and cannot run in a commandlet"));
			return;
		}

		const FString SourceArg = KrJStrAny(In, { TEXT("sourceAsset"), TEXT("blueprint"), TEXT("bpName"), TEXT("path") });
		if (SourceArg.IsEmpty())
		{
			KrFail(Out, TEXT("sourceAsset required (the cooked Blueprint: its .<Name>_C class path, its asset path, or its exact name)"));
			return;
		}

		FString ResolveError;
		UBlueprintGeneratedClass* BPGC = KrResolveBPGC(SourceArg, ResolveError);
		if (!BPGC) { KrFail(Out, ResolveError); return; }

		const bool bAllowAnim = KrJBool(In, TEXT("allowAnim"), false);
		if (KrIsAnimBlueprintClass(BPGC) && !bAllowAnim)
		{
			KrFail(Out, FString::Printf(
				TEXT("'%s' is an Animation Blueprint and reconstruction of anim graphs is NOT implemented: the engine mints an ")
				TEXT("anim source as a PLAIN UBlueprint (only Widget Blueprints get their own class pair), so the copy has no ")
				TEXT("AnimGraph and every fidelity number would describe that degraded copy rather than the decompiler. ")
				TEXT("Anim Blueprints are excluded from kr_drift_census and kr_batch_reconstruct by the same rule. ")
				TEXT("Pass allowAnim:true to measure it anyway - the result is then flagged degraded:true."),
				*BPGC->GetPathName()));
			Out->SetBoolField(TEXT("animBlueprint"), true);
			Out->SetStringField(TEXT("sourceClassPath"), BPGC->GetPathName());
			return;
		}

		const bool bClassify = KrJBoolAny(In, { TEXT("classifyIntentional"), TEXT("classify") }, true);

		FString BaseName = BPGC->GetName();
		BaseName.RemoveFromEnd(TEXT("_C"));

		int32 FunctionsTotalEstimate = 0;
		for (TFieldIterator<UFunction> It(BPGC, EFieldIteratorFlags::ExcludeSuper); It; ++It)
		{
			UFunction* Func = *It;
			if (!Func || Func->Script.Num() == 0) { continue; }
			if (Func->HasAnyFunctionFlags(FUNC_UbergraphFunction)) { continue; }
			++FunctionsTotalEstimate;
		}

		FString JobId, BeginError;
		if (!MifKr::Jobs::TryBegin(TEXT("verify"), JobId, BeginError)) { KrFail(Out, BeginError); return; }

		{
			MifKr::Jobs::FJobRecord& Job = MifKr::Jobs::Mutable();
			Job.SourceAsset = SourceArg;
			Job.SourceClassPath = BPGC->GetPathName();
			Job.BpName = BaseName;
			Job.Mode = TEXT("child");
			Job.FunctionsTotalEstimate = FunctionsTotalEstimate;
		}

		FKrVerifyPlan Plan;
		Plan.JobId = JobId;
		Plan.Kind = TEXT("verify");
		Plan.SourceClassPath = BPGC->GetPathName();
		Plan.SourceAsset = SourceArg;
		Plan.BpName = BaseName;
		Plan.bClassifyIntentional = bClassify;
		Plan.bPerFunction = false;
		Plan.bAnimAllowed = bAllowAnim;

		GEditor->GetTimerManager()->SetTimerForNextTick(FTimerDelegate::CreateLambda([Plan]()
		{
			KrRunVerifyJob(Plan);
		}));

		Out->SetStringField(TEXT("jobId"), JobId);
		Out->SetStringField(TEXT("kind"), TEXT("verify"));
		Out->SetStringField(TEXT("state"), TEXT("queued"));
		Out->SetStringField(TEXT("sourceAsset"), SourceArg);
		Out->SetStringField(TEXT("sourceClassPath"), BPGC->GetPathName());
		Out->SetBoolField(TEXT("sourceCooked"), KrIsCooked(BPGC));
		Out->SetStringField(TEXT("bpName"), BaseName);
		Out->SetStringField(TEXT("mode"), TEXT("child"));
		Out->SetBoolField(TEXT("classifyIntentional"), bClassify);
		Out->SetNumberField(TEXT("functionsTotalEstimate"), FunctionsTotalEstimate);
		Out->SetBoolField(TEXT("deferred"), true);
		Out->SetStringField(TEXT("note"),
			TEXT("DEFERRED one tick and ATOMIC - this call did NOT do the work, and the job runs to completion inside a ")
			TEXT("single tick during which the HTTP listener (a game-thread ticker) is stalled, so a poll issued mid-job is ")
			TEXT("not read until the job ends. Poll kr_reconstruct_status. result.fidelity.score is null (never 1.000) when ")
			TEXT("nothing was scored, and the whole fidelity block is ABSENT when the copy failed to compile."));
	}

	// --- kr_classify_drift -------------------------------------------------------------------------
	//   in:  { sourceAsset [REQUIRED] (aliases: blueprint, bpName, path),
	//          function?: exact own-function name to report (aliases: functionName, func),
	//          classifyIntentional?: bool (default true; alias classify), allowAnim?: bool }
	//   out: as kr_verify_fidelity, kind:"classify"
	//   result: kr_verify_fidelity's payload PLUS functions[{name, verdict, reasons[], detail}],
	//           verdictCounts{}, reasonTally, consistent
	//
	// The drill-down kr_verify_fidelity's aggregate cannot give: a verdict PER FUNCTION, with the
	// classifier's claim reasons and - for real drift - the ROOT-CAUSE edit rather than the first raw
	// stream difference (one inserted statement re-ordinalises every later jump, so the first raw
	// difference is usually a cascade artefact).
	//
	// `function` FILTERS THE REPORT, it does not narrow the work: the pipeline is per-Blueprint, so the
	// whole verify runs regardless. Saying so matters - a caller who believes it scoped the run would
	// mis-read the timing.
	//
	// Bucket SELF-MANAGED (same full compile as kr_verify_fidelity).
	static void H_kr_classify_drift(const TSharedRef<FJsonObject>& In, const TSharedRef<FJsonObject>& Out)
	{
		if (KrRejectUnknownParams(In, Out,
			{ TEXT("sourceAsset"), TEXT("blueprint"), TEXT("bpName"), TEXT("path"),
			  TEXT("function"), TEXT("functionName"), TEXT("func"),
			  TEXT("classifyIntentional"), TEXT("classify"), TEXT("allowAnim") },
			TEXT("sourceAsset (aliases: blueprint, bpName, path), function (aliases: functionName, func), ")
			TEXT("classifyIntentional (alias: classify), allowAnim"),
			{{ TEXT("includeWindow"),
			   TEXT("not implemented - the +/-2 statement window needs the verifier's canonical cooked/recon streams, which exist only inside its own per-function loop and never cross the delegate boundary; disassemble the named function with kr_disassemble_function instead") },
			 { TEXT("window"),
			   TEXT("not implemented - same reason as includeWindow; use kr_disassemble_function on the function named in detail") },
			 { TEXT("variant"),
			   TEXT("does not exist here - classification is CHILD-ONLY for the same reason fidelity is: a sibling copy false-drifts on every component reference") }}))
		{
			return;
		}

		if (MifKr::Jobs::IsBusy())
		{
			const MifKr::Jobs::FJobRecord& Running = MifKr::Jobs::Get();
			KrFail(Out, MifKr::Jobs::BusyMessage());
			Out->SetStringField(TEXT("runningJobId"), Running.JobId);
			Out->SetStringField(TEXT("runningKind"), Running.Kind);
			Out->SetStringField(TEXT("runningState"), MifKr::Jobs::StateName(Running.State));
			return;
		}
		if (!GEditor)
		{
			KrFail(Out, TEXT("no GEditor - kr_classify_drift defers its work through the editor timer manager and cannot run in a commandlet"));
			return;
		}

		const FString SourceArg = KrJStrAny(In, { TEXT("sourceAsset"), TEXT("blueprint"), TEXT("bpName"), TEXT("path") });
		if (SourceArg.IsEmpty())
		{
			KrFail(Out, TEXT("sourceAsset required (the cooked Blueprint: its .<Name>_C class path, its asset path, or its exact name)"));
			return;
		}

		FString ResolveError;
		UBlueprintGeneratedClass* BPGC = KrResolveBPGC(SourceArg, ResolveError);
		if (!BPGC) { KrFail(Out, ResolveError); return; }

		const bool bAllowAnim = KrJBool(In, TEXT("allowAnim"), false);
		if (KrIsAnimBlueprintClass(BPGC) && !bAllowAnim)
		{
			KrFail(Out, FString::Printf(
				TEXT("'%s' is an Animation Blueprint: the engine mints an anim source as a PLAIN UBlueprint, so the copy has ")
				TEXT("no AnimGraph and per-function verdicts would describe a degraded copy, not the decompiler. ")
				TEXT("Pass allowAnim:true to classify it anyway - the result is then flagged degraded:true."),
				*BPGC->GetPathName()));
			Out->SetBoolField(TEXT("animBlueprint"), true);
			Out->SetStringField(TEXT("sourceClassPath"), BPGC->GetPathName());
			return;
		}

		const bool bClassify = KrJBoolAny(In, { TEXT("classifyIntentional"), TEXT("classify") }, true);
		const FString FunctionFilter = KrJStrAny(In, { TEXT("function"), TEXT("functionName"), TEXT("func") });

		FString BaseName = BPGC->GetName();
		BaseName.RemoveFromEnd(TEXT("_C"));

		int32 FunctionsTotalEstimate = 0;
		for (TFieldIterator<UFunction> It(BPGC, EFieldIteratorFlags::ExcludeSuper); It; ++It)
		{
			UFunction* Func = *It;
			if (!Func || Func->Script.Num() == 0) { continue; }
			if (Func->HasAnyFunctionFlags(FUNC_UbergraphFunction)) { continue; }
			++FunctionsTotalEstimate;
		}

		FString JobId, BeginError;
		if (!MifKr::Jobs::TryBegin(TEXT("classify"), JobId, BeginError)) { KrFail(Out, BeginError); return; }

		{
			MifKr::Jobs::FJobRecord& Job = MifKr::Jobs::Mutable();
			Job.SourceAsset = SourceArg;
			Job.SourceClassPath = BPGC->GetPathName();
			Job.BpName = BaseName;
			Job.Mode = TEXT("child");
			Job.FunctionName = FunctionFilter;
			Job.FunctionsTotalEstimate = FunctionsTotalEstimate;
		}

		FKrVerifyPlan Plan;
		Plan.JobId = JobId;
		Plan.Kind = TEXT("classify");
		Plan.SourceClassPath = BPGC->GetPathName();
		Plan.SourceAsset = SourceArg;
		Plan.BpName = BaseName;
		Plan.bClassifyIntentional = bClassify;
		Plan.bPerFunction = true;
		Plan.bAnimAllowed = bAllowAnim;
		Plan.FunctionFilter = FunctionFilter;

		GEditor->GetTimerManager()->SetTimerForNextTick(FTimerDelegate::CreateLambda([Plan]()
		{
			KrRunVerifyJob(Plan);
		}));

		Out->SetStringField(TEXT("jobId"), JobId);
		Out->SetStringField(TEXT("kind"), TEXT("classify"));
		Out->SetStringField(TEXT("state"), TEXT("queued"));
		Out->SetStringField(TEXT("sourceAsset"), SourceArg);
		Out->SetStringField(TEXT("sourceClassPath"), BPGC->GetPathName());
		Out->SetBoolField(TEXT("sourceCooked"), KrIsCooked(BPGC));
		Out->SetStringField(TEXT("bpName"), BaseName);
		Out->SetStringField(TEXT("mode"), TEXT("child"));
		Out->SetBoolField(TEXT("classifyIntentional"), bClassify);
		if (!FunctionFilter.IsEmpty()) { Out->SetStringField(TEXT("function"), FunctionFilter); }
		Out->SetNumberField(TEXT("functionsTotalEstimate"), FunctionsTotalEstimate);
		Out->SetBoolField(TEXT("deferred"), true);
		Out->SetStringField(TEXT("note"),
			TEXT("DEFERRED one tick and ATOMIC - poll kr_reconstruct_status. `function` filters the REPORT only: the ")
			TEXT("whole-Blueprint verify still runs, because the pipeline is per-Blueprint. This kind costs roughly TWICE ")
			TEXT("kr_verify_fidelity: the verifier runs once for the aggregate and once per function, which is what makes ")
			TEXT("result.consistent an independent cross-check rather than a tautology."));
	}

	// --- kr_drift_census ---------------------------------------------------------------------------
	//   in:  { pathFilter?: substring over package names, "*" = all (aliases: filter, pathSubstr; default "/Game/"),
	//          startIndex?: int >= 0 (default 0; crash-resume cursor),
	//          maxCount?: int (default 50, 0 = unbounded; aliases: limit),
	//          classifyIntentional?: bool (default true; alias classify) }
	//   out: { jobId, kind:"census", state:"queued", pathFilter, bpTotal, matched, animExcluded, csvPath, ... }
	//   result: { filter{}, bpTotal, bpDone, pass, fail, skip, skipTaxonomy{resolve,parent,mint},
	//             totals{}, corpusFidelity|null, corpusAdjusted|null, intentTally, censusCsvPath,
	//             corpusBaseline{}, resumeHint, ... }
	//
	// The fidelity verify across a path-filtered SET of cooked Blueprints with the classifier's census
	// instrument (mif.kr.DriftCensus) forced on for the job's duration, producing running corpus totals
	// over HTTP plus the on-disk DriftCensus CSV of every UNCLAIMED drift edit - the data a rule author
	// needs to decide which drift classes actually dominate, without babysitting a console for an hour.
	//
	// CHILD MODE ALWAYS, VERIFY ALWAYS: a census that measured siblings would report the mode, not the
	// decompiler. maxCount defaults to 50 because an accidental whole-corpus run must be opt-in
	// (maxCount:0 asks for it explicitly).
	//
	// COOKED-ONLY BY DESIGN: loose Blueprints are exactly what a corpus fidelity number must not dilute.
	// Bucket SELF-MANAGED: it compiles one throwaway Blueprint per slice.
	static void H_kr_drift_census(const TSharedRef<FJsonObject>& In, const TSharedRef<FJsonObject>& Out)
	{
		if (KrRejectUnknownParams(In, Out,
			{ TEXT("pathFilter"), TEXT("filter"), TEXT("pathSubstr"), TEXT("startIndex"), TEXT("start"),
			  TEXT("maxCount"), TEXT("limit"), TEXT("classifyIntentional"), TEXT("classify") },
			TEXT("pathFilter (aliases: filter, pathSubstr), startIndex (alias: start), maxCount (alias: limit), ")
			TEXT("classifyIntentional (alias: classify)"),
			{{ TEXT("mode"),
			   TEXT("not a parameter - a census is CHILD-ONLY: a sibling copy false-drifts on every component reference, so a sibling census would measure the mode instead of the decompiler. Use kr_batch_reconstruct for a sibling sweep") },
			 { TEXT("verify"),
			   TEXT("not a parameter - verification IS the census; use kr_batch_reconstruct for a pass/fail-only sweep") },
			 { TEXT("cookedOnly"),
			   TEXT("not a parameter - a census is cooked-only by design: loose Blueprints are exactly what a corpus fidelity number must not dilute") },
			 { TEXT("wait"),
			   TEXT("not implemented - the sweep is sliced one Blueprint per tick; poll kr_reconstruct_status") }}))
		{
			return;
		}

		if (MifKr::Jobs::IsBusy())
		{
			const MifKr::Jobs::FJobRecord& Running = MifKr::Jobs::Get();
			KrFail(Out, MifKr::Jobs::BusyMessage());
			Out->SetStringField(TEXT("runningJobId"), Running.JobId);
			Out->SetStringField(TEXT("runningKind"), Running.Kind);
			Out->SetStringField(TEXT("runningState"), MifKr::Jobs::StateName(Running.State));
			return;
		}

		const FString PathFilter = KrJStrAny(In, { TEXT("pathFilter"), TEXT("filter"), TEXT("pathSubstr") }, TEXT("/Game/"));
		const int32 StartIndex = KrJIntAny(In, { TEXT("startIndex"), TEXT("start") }, 0);
		const int32 MaxCount = KrJIntAny(In, { TEXT("maxCount"), TEXT("limit") }, 50);
		const bool bClassify = KrJBoolAny(In, { TEXT("classifyIntentional"), TEXT("classify") }, true);

		if (StartIndex < 0)
		{
			KrFail(Out, FString::Printf(TEXT("startIndex %d is invalid; pass 0 or greater (it is the crash-resume cursor)"), StartIndex));
			return;
		}
		if (MaxCount < 0)
		{
			KrFail(Out, FString::Printf(TEXT("maxCount %d is invalid; pass a positive count, or 0 for the whole filtered corpus"), MaxCount));
			return;
		}

		KrStartSweep(Out, TEXT("census"), PathFilter, StartIndex, MaxCount,
			/*bAsChild*/ true, /*bVerify*/ true, bClassify, /*bCensusCvar*/ true);
	}

	// --- kr_batch_reconstruct ----------------------------------------------------------------------
	//   in:  { pathFilter?: substring, "*" = all (aliases: filter, pathContains; default "/Game/"),
	//          mode?: "sibling" | "child" (alias variant; default "sibling"),
	//          verify?: bool (default false; REQUIRES mode:"child"),
	//          startIndex?: int >= 0 (default 0),
	//          maxBlueprints?: int (default 0 = every match; alias limit) }
	//   out: { jobId, kind:"batch", state:"queued", ... }
	//   result: { bpTotal, bpDone, pass, fail, skip, skipTaxonomy{}, csvPath, csvRows, ... }
	//
	// The regression sweep: reconstruct every matching cooked Blueprint into a throwaway copy, compile
	// it, tally PASS/FAIL/SKIP, and write the engine harness's exact CSV. This is mif.kr.ReconstructAll
	// over HTTP - except the console command blocks the editor for the entire run, and this one slices
	// one Blueprint per tick so the bridge keeps answering and the progress is observable.
	//
	// Bucket SELF-MANAGED: one full compile per slice.
	// COOKED: the target set IS the cooked corpus - the same exact-class-path gate that drives F3.
	static void H_kr_batch_reconstruct(const TSharedRef<FJsonObject>& In, const TSharedRef<FJsonObject>& Out)
	{
		if (KrRejectUnknownParams(In, Out,
			{ TEXT("pathFilter"), TEXT("filter"), TEXT("pathContains"), TEXT("mode"), TEXT("variant"),
			  TEXT("verify"), TEXT("startIndex"), TEXT("start"), TEXT("maxBlueprints"), TEXT("limit"),
			  TEXT("classifyIntentional"), TEXT("classify") },
			TEXT("pathFilter (aliases: filter, pathContains), mode (alias: variant), verify, ")
			TEXT("startIndex (alias: start), maxBlueprints (alias: limit), classifyIntentional (alias: classify)"),
			{{ TEXT("save"),
			   TEXT("not a parameter - a batch sweep NEVER saves: every copy is minted into the transient package and torn down. Use kr_reconstruct_request mode:'copy' to produce a persistent asset") },
			 { TEXT("targetPath"),
			   TEXT("not a parameter - nothing is written except the CSV report under <ProjectSaved>/MifKr/") },
			 { TEXT("wait"),
			   TEXT("not implemented - the sweep is sliced one Blueprint per tick; poll kr_reconstruct_status") }}))
		{
			return;
		}

		if (MifKr::Jobs::IsBusy())
		{
			const MifKr::Jobs::FJobRecord& Running = MifKr::Jobs::Get();
			KrFail(Out, MifKr::Jobs::BusyMessage());
			Out->SetStringField(TEXT("runningJobId"), Running.JobId);
			Out->SetStringField(TEXT("runningKind"), Running.Kind);
			Out->SetStringField(TEXT("runningState"), MifKr::Jobs::StateName(Running.State));
			return;
		}

		const FString PathFilter = KrJStrAny(In, { TEXT("pathFilter"), TEXT("filter"), TEXT("pathContains") }, TEXT("/Game/"));
		const FString ModeArg = KrJStrAny(In, { TEXT("mode"), TEXT("variant") }, TEXT("sibling")).ToLower();
		const bool bVerify = KrJBool(In, TEXT("verify"), false);
		const int32 StartIndex = KrJIntAny(In, { TEXT("startIndex"), TEXT("start") }, 0);
		const int32 MaxBlueprints = KrJIntAny(In, { TEXT("maxBlueprints"), TEXT("limit") }, 0);
		const bool bClassify = KrJBoolAny(In, { TEXT("classifyIntentional"), TEXT("classify") }, true);

		bool bAsChild = false;
		if (ModeArg == TEXT("child"))                                        { bAsChild = true; }
		else if (ModeArg == TEXT("sibling") || ModeArg == TEXT("uncooked"))  { bAsChild = false; }
		else
		{
			KrFail(Out, FString::Printf(
				TEXT("mode '%s' is not recognised; pass 'sibling' (parent-class copy, the default and what the console sweep does) ")
				TEXT("or 'child' (IS-A the cooked class, the only mode fidelity is measurable in)"), *ModeArg));
			return;
		}

		if (bVerify && !bAsChild)
		{
			// The engine harness refuses the same combination for the same reason, and refusing loudly is
			// the whole point: a sibling sweep with verify on would emit systematic FALSE drift on every
			// Blueprint and look like a decompiler regression.
			KrFail(Out, TEXT("verify requires mode:'child' - a SIBLING copy mints its components into the transient package, so ")
				TEXT("every component reference differs by object path and the drift would be an artefact of the mode, not of the ")
				TEXT("decompiler. Re-run with mode:'child', or drop verify for a pass/fail-only sweep."));
			return;
		}
		if (StartIndex < 0)
		{
			KrFail(Out, FString::Printf(TEXT("startIndex %d is invalid; pass 0 or greater (it is the crash-resume cursor)"), StartIndex));
			return;
		}
		if (MaxBlueprints < 0)
		{
			KrFail(Out, FString::Printf(TEXT("maxBlueprints %d is invalid; pass a positive count, or 0 for every match"), MaxBlueprints));
			return;
		}

		KrStartSweep(Out, TEXT("batch"), PathFilter, StartIndex, MaxBlueprints,
			bAsChild, bVerify, bClassify, /*bCensusCvar*/ false);
	}
}

// Called from FMifKismetReconstructorModule::StartupModule (MifKismetReconstructorModule.cpp).
// Legal there even though MifBridge's own StartupModule has not run yet: this module loads at
// "Default", MifBridge at "PostEngineInit", and RegisterExternalEndpoint touches only a
// function-local static (MifBridgeEndpointRegistry.h's hard rule).
void MifKr_RegisterBridgeEndpoints()
{
	using namespace MifBridge;
	using namespace MifKr::BridgeEndpoints;

	int32 Registered = 0;
	auto Reg = [&Registered](const TCHAR* Name, EEndpointBucket Bucket, const TCHAR* Summary, FExternalHandler H)
	{
		FExternalEndpointDesc D;
		D.Name = Name;
		D.Bucket = Bucket;
		D.Provider = GProvider;
		D.Summary = Summary;
		D.Handler = MoveTemp(H);

		FString Err;
		if (RegisterExternalEndpoint(MoveTemp(D), &Err))
		{
			++Registered;
		}
		else
		{
			// A false return means the endpoint does NOT exist. Never silent: an unregistered
			// endpoint answers 404 with nothing anywhere explaining why.
			UE_LOG(LogMifKismetReconstructor, Error, TEXT("kr endpoint '%s' NOT registered: %s"), Name, *Err);
		}
	};

	// Bucket policy, per endpoint and not by convention:
	//  - the six reads are ReadOnly, because a transacted read pushes an EMPTY undo entry per call and
	//    kr_reconstruct_status is polled in a loop, which would flood the undo stack;
	//  - kr_reconstruct_request is SelfManaged, because its deferred slice runs a full CompileBlueprint
	//    (and, in copy mode, a package save). A full compile inside a blanket transaction means
	//    reinstancing captured by an undo step, which means a dead CDO and a crash. SelfManaged also
	//    makes the endpoint compile-heavy, which fences it out of `batch`'s single open transaction for
	//    free.
	Reg(TEXT("kr_list_cooked_blueprints"), EEndpointBucket::ReadOnly,
		TEXT("Registry census of cooked Blueprint packages (PKG_Cooked, package-deduped, paged). Loads nothing."),
		&H_kr_list_cooked_blueprints);

	Reg(TEXT("kr_dump_blueprint"), EEndpointBucket::ReadOnly,
		TEXT("Structure of a cooked BlueprintGeneratedClass as JSON: own functions, properties, events, parent chain and counts. Bytecode only on request, page-limited."),
		&H_kr_dump_blueprint);

	Reg(TEXT("kr_disassemble_function"), EEndpointBucket::ReadOnly,
		TEXT("One cooked function's Kismet bytecode as a structured JSON statement stream, paginated by array index. Closes the run_console detour for reading cooked logic."),
		&H_kr_disassemble_function);

	Reg(TEXT("kr_list_events"), EEndpointBucket::ReadOnly,
		TEXT("Event census of a cooked class: every event thunk with kind, recovered ubergraph entry offset, param count and the authoritative frame->param map."),
		&H_kr_list_events);

	Reg(TEXT("kr_analyze_ubergraph"), EEndpointBucket::ReadOnly,
		TEXT("Ubergraph slice analysis for one Blueprint: prologue shape, per-event reachability, shared/unreached statement counts and the shared-latent split verdict."),
		&H_kr_analyze_ubergraph);

	Reg(TEXT("kr_pin_type_from_property"), EEndpointBucket::ReadOnly,
		TEXT("Any class property -> its FEdGraphPinType JSON plus the bridge type-grammar string that add_variable / add_pin / set_pin_type accept."),
		&H_kr_pin_type_from_property);

	Reg(TEXT("kr_reconstruct_request"), EEndpointBucket::SelfManaged,
		TEXT("Start the single kr job: decompile a cooked Blueprint into editable K2 graphs (mode copy or function). Deferred one tick, returns a jobId immediately."),
		&H_kr_reconstruct_request);

	Reg(TEXT("kr_reconstruct_status"), EEndpointBucket::ReadOnly,
		TEXT("Poll the single kr job slot: state, phase, function/event tallies, node and compile counts, and the result payload."),
		&H_kr_reconstruct_status);

	// Wave 3. All four are SELF-MANAGED for one reason: every one of them runs a full
	// FKismetEditorUtilities::CompileBlueprint on a throwaway transient copy (once, or once per slice).
	// A full compile inside a blanket undo transaction means reinstancing captured by an undo step, i.e.
	// a dead CDO and a crash. SelfManaged also makes them compile-heavy, which fences them out of
	// batch's single open transaction for free. They mutate NO persistent state — nothing is saved,
	// registered with the AssetRegistry, or opened — but "read-only" would be a lie about the compile.
	Reg(TEXT("kr_verify_fidelity"), EEndpointBucket::SelfManaged,
		TEXT("Reconstruct a throwaway transient CHILD of a cooked Blueprint, compile it, and diff every reconstructed function's recompiled bytecode against the cooked original. Deferred one tick; poll kr_reconstruct_status."),
		&H_kr_verify_fidelity);

	Reg(TEXT("kr_classify_drift"), EEndpointBucket::SelfManaged,
		TEXT("kr_verify_fidelity decomposed PER FUNCTION: identical/equivalent/intentional/drift/missing/uncomparable per function, the classifier's claim reasons, and the root-cause edit for real drift."),
		&H_kr_classify_drift);

	Reg(TEXT("kr_drift_census"), EEndpointBucket::SelfManaged,
		TEXT("Fidelity verify across a path-filtered set of cooked Blueprints with the drift-census instrument on: running corpus totals plus the on-disk CSV of every unclaimed drift edit. Sliced ONE Blueprint per tick."),
		&H_kr_drift_census);

	Reg(TEXT("kr_batch_reconstruct"), EEndpointBucket::SelfManaged,
		TEXT("Reconstruct every matching cooked Blueprint into a throwaway copy, compile, tally PASS/FAIL/SKIP with the three-way skip taxonomy and the engine harness's CSV. Sliced ONE Blueprint per tick."),
		&H_kr_batch_reconstruct);

	UE_LOG(LogMifKismetReconstructor, Log, TEXT("registered %d kr_* MifBridge endpoint(s)."), Registered);
}

void MifKr_UnregisterBridgeEndpoints()
{
	const int32 N = MifBridge::UnregisterExternalEndpoints(MifKr::BridgeEndpoints::GProvider);
	UE_LOG(LogMifKismetReconstructor, Log, TEXT("unregistered %d kr_* bridge endpoint(s)."), N);
}

#endif // WITH_MIFBRIDGE
