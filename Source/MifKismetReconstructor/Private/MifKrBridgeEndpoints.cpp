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
// Wave 3 (kr_verify_fidelity, kr_classify_drift, kr_drift_census, kr_batch_reconstruct) is blocked on
// an engine-side KISMET_API refactor and is deliberately absent rather than stubbed.
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
#include "Logging/TokenizedMessage.h"    // FTokenizedMessage::ToText for compile messages
#include "Misc/PackageName.h"            // DoesPackageExist — target-path uniquification
#include "Modules/ModuleManager.h"
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
			TEXT("single-Blueprint jobs are ATOMIC: the HTTP listener is a game-thread ticker, so while the job runs no ")
			TEXT("request is read off the socket at all - progress counters therefore advance on completion, never mid-job. ")
			TEXT("Job records are in-memory only: after an editor restart this answers found:false. ")
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

	UE_LOG(LogMifKismetReconstructor, Log, TEXT("registered %d kr_* MifBridge endpoint(s)."), Registered);
}

void MifKr_UnregisterBridgeEndpoints()
{
	const int32 N = MifBridge::UnregisterExternalEndpoints(MifKr::BridgeEndpoints::GProvider);
	UE_LOG(LogMifKismetReconstructor, Log, TEXT("unregistered %d kr_* bridge endpoint(s)."), N);
}

#endif // WITH_MIFBRIDGE
