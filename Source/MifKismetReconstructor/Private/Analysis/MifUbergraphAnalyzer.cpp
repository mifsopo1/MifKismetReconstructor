// PHASE 1 GO/NO-GO MEASUREMENT for the ubergraph → per-event split.
//
// READ-ONLY. This file builds NO graphs, mints NO Blueprints and compiles NOTHING. It disassembles cooked
// ubergraph bytecode, recovers each event's entry offset from its thunk, walks the CFG once per event, and
// reports statistics. Safe to run across all ~1256 DDS2 Blueprints.
//
//   mif.kr.AnalyzeUbergraph [pathSubstr=/Game/] [startIndex=0]
//
// The single decision-relevant number is SharedLatent: a latent node (Delay/timeline) reached by >1 event
// cannot be split faithfully — Delay dedupes on (CallbackTarget, UUID), so duplicating it into two event
// graphs yields two UUIDs and concurrent execution where the cooked original deduped. If that count is
// non-trivial across DDS2, §3.4's duplication moves from footnote to headline and the plan needs revisiting.
//
// -------------------------------------------------------------------------------------------------------
// PHASE 2: the ENGINE of this analyzer — prologue detection [A], entry recovery, and the entry-seeded
// per-event walk [B][C] — now lives in Analysis/MifUbergraphSlicer.{h,cpp}, UNGATED, because the event-body
// reconstructor needs the same code in shipping configurations. This file keeps ONLY the measurement:
// enumeration, tallying and CSV. There is one implementation of the slice; the numbers below and the graphs
// the reconstructor emits can never drift apart.
//
// The three false spec claims this code refuses to inherit ([A] prologue shape is data-dependent, [B] the
// stack at an event entry is [ReturnAddr] not empty, [C] a shared region's exit edge is entry-dependent) are
// documented at the head of MifUbergraphSlicer.h.
// -------------------------------------------------------------------------------------------------------

#include "MifReconstructorDebug.h"
#include "Analysis/MifUbergraphSlicer.h"
#include "Toolkit/KismetBytecodeDisassemblerJson.h"

#include "Engine/Blueprint.h"
#include "Engine/BlueprintGeneratedClass.h"
#include "Engine/LatentActionManager.h"       // FLatentActionInfo::StaticStruct() — the latent-call marker
#include "UObject/Class.h"
#include "UObject/GarbageCollection.h"        // FGCScopeGuard
#include "UObject/ObjectMacros.h"             // PKG_Cooked
#include "Dom/JsonValue.h"
#include "Misc/Paths.h"
#include "Misc/DateTime.h"
#include "HAL/FileManager.h"
#include "HAL/IConsoleManager.h"
#include "Modules/ModuleManager.h"
#include "AssetRegistry/AssetRegistryModule.h"
#include "AssetRegistry/IAssetRegistry.h"
#include "AssetRegistry/ARFilter.h"
#include "AssetRegistry/AssetData.h"

#if MIF_KR_DEBUG

namespace MifUberAnalysis
{
	static FString Csv(const FString& In)
	{
		FString Out = In;
		Out.ReplaceInline(TEXT(","), TEXT(";"));
		Out.ReplaceInline(TEXT("\r"), TEXT(" "));
		Out.ReplaceInline(TEXT("\n"), TEXT(" "));
		Out.ReplaceInline(TEXT("\""), TEXT("'"));
		return Out;
	}

	struct FAggregate
	{
		int32 BPs = 0, BPsWithUber = 0, BPsNoUber = 0, BPsNoBytecode = 0, BPsDisasmFailed = 0;
		int32 BPsResolveFail = 0, BPsWithEvents = 0, BPsEntryFailed = 0, BPsGuardHit = 0, BPsBadPrologue = 0;
		int32 Events = 0, EventsWithParams = 0, EventsNoParams = 0, EventsRecovered = 0, EventsFailed = 0;
		int32 BndEvts = 0, InpActEvts = 0, SeqEvts = 0;
		int32 Stmts = 0, Analysed = 0, Reached1 = 0, Shared = 0, Unreached = 0;
		int32 LatentStmts = 0, SharedLatent = 0, BPsWithSharedLatent = 0;
		int32 BadTargets = 0, ComputedHits = 0, MaxShareDegree = 0;
		int32 RawPtrHits = 0, IdentityCalls = 0;
	};
}

using namespace MifUberAnalysis;

static void MifKr_AnalyzeUbergraph(const TArray<FString>& Args)
{
	const FString PathFilter = Args.Num() >= 1 ? Args[0] : TEXT("/Game/");
	const bool bAllPaths = (PathFilter == TEXT("*"));
	const int32 StartIndex = Args.Num() >= 2 ? FCString::Atoi(*Args[1]) : 0;

	// 1) enumerate cooked BP assets (dedup by package — the registry lists both the UBlueprint and its BPGC).
	//    bRecursiveClasses covers UWidgetBlueprint(GeneratedClass) without dragging in a UMG module dependency.
	FAssetRegistryModule& ARM = FModuleManager::LoadModuleChecked<FAssetRegistryModule>(TEXT("AssetRegistry"));
	FARFilter Filter;
	Filter.ClassPaths.Add(UBlueprintGeneratedClass::StaticClass()->GetClassPathName());
	Filter.ClassPaths.Add(UBlueprint::StaticClass()->GetClassPathName());
	Filter.bRecursiveClasses = true;
	TArray<FAssetData> Assets;
	ARM.Get().GetAssets(Filter, Assets);

	TArray<FAssetData> Targets;
	TSet<FName> SeenPackages;
	for (const FAssetData& A : Assets)
	{
		if (!A.IsValid() || (A.PackageFlags & PKG_Cooked) == 0) continue;
		if (!bAllPaths && !A.PackageName.ToString().Contains(PathFilter)) continue;
		if (SeenPackages.Contains(A.PackageName)) continue;
		SeenPackages.Add(A.PackageName);
		Targets.Add(A);
	}
	Targets.Sort([](const FAssetData& L, const FAssetData& R) { return L.PackageName.ToString() < R.PackageName.ToString(); });

	// 2) open both CSVs, FLUSHED PER BP so a hard crash preserves partial results and names the culprit.
	const FString ReportDir = FPaths::ProjectSavedDir() / TEXT("MifKr");
	IFileManager::Get().MakeDirectory(*ReportDir, /*Tree*/ true);
	const FString Stamp = FDateTime::Now().ToString(TEXT("%Y%m%d_%H%M%S"));
	const FString BpPath = ReportDir / FString::Printf(TEXT("UbergraphAnalysis_%s.csv"), *Stamp);
	const FString EvPath = ReportDir / FString::Printf(TEXT("UbergraphEvents_%s.csv"), *Stamp);

	TUniquePtr<FArchive> BpReport(IFileManager::Get().CreateFileWriter(*BpPath, FILEWRITE_AllowRead));
	TUniquePtr<FArchive> EvReport(IFileManager::Get().CreateFileWriter(*EvPath, FILEWRITE_AllowRead));
	auto WriteTo = [](TUniquePtr<FArchive>& Ar, const FString& Line)
	{
		if (Ar) { const FString L = Line + LINE_TERMINATOR; FTCHARToUTF8 Conv(*L); Ar->Serialize((void*) Conv.Get(), Conv.Length()); Ar->Flush(); }
	};
	auto WriteBp = [&](const FString& Line) { WriteTo(BpReport, Line); };
	auto WriteEv = [&](const FString& Line) { WriteTo(EvReport, Line); };

	// 29 columns. A short-circuit row (RESOLVE_FAIL / NO_UBERGRAPH / NO_BYTECODE) fills the first 4 and is
	// padded out so it still lines up — hand-counted trailing commas are how CSVs silently skew.
	static const int32 NumBpColumns = 29;
	WriteBp(TEXT("Index,Package,Class,Status,Prologue,UberBytes,UberStmts,AnalysedStmts,Events,EventsRecovered,EventsFailed,")
		TEXT("EventsWithParams,EventsNoParams,BndEvt,InpActEvt,SeqEvt,Reached1,Shared,Unreached,MaxShareDegree,PctShared,")
		TEXT("LatentStmts,SharedLatent,BadTargets,ComputedHits,GuardHit,RawPtrHits,IdentityCalls,Notes"));

	// Row = the 4 leading fields, already comma-joined and unterminated.
	auto WriteBpShort = [&](const FString& Row) { WriteBp(Row + FString::ChrN(NumBpColumns - 4, TEXT(','))); };
	WriteEv(TEXT("Index,Package,Class,Event,Kind,EntryOffset,NumParams,FrameLets,FrameParamMap,FastCallCrossCheck,RawPtrHits,IdentityCalls,Reached,Status"));

	UE_LOG(LogMifKismetReconstructor, Display,
		TEXT("[uber] %d cooked Blueprints match '%s' (start=%d). READ-ONLY. Reports: %s | %s"),
		Targets.Num(), *PathFilter, StartIndex, *BpPath, *EvPath);

	FAggregate Agg;

	for (int32 i = StartIndex; i < Targets.Num(); ++i)
	{
		const FAssetData& A = Targets[i];
		const FString PkgName = A.PackageName.ToString();

		// Flushed BEGIN marker: if the sweep dies hard, the log names the exact culprit BP.
		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[uber] %d/%d BEGIN %s"), i, Targets.Num() - 1, *PkgName);
		if (GLog) { GLog->Flush(); }

		Agg.BPs++;

		UObject* Asset = A.GetAsset();
		UBlueprintGeneratedClass* BPGC = Cast<UBlueprintGeneratedClass>(Asset);
		if (!BPGC)
		{
			if (UBlueprint* BP = Cast<UBlueprint>(Asset)) { BPGC = Cast<UBlueprintGeneratedClass>(BP->GeneratedClass); }
		}
		if (!BPGC)
		{
			Agg.BPsResolveFail++;
			WriteBpShort(FString::Printf(TEXT("%d,%s,,RESOLVE_FAIL"), i, *Csv(PkgName)));
			continue;
		}

		// Hold GC for this BP only. We keep raw UFunction*/UStruct* pointers and read Script arrays; GC still
		// breathes BETWEEN Blueprints. (Asset is already loaded above — do not load inside the guard.)
		FGCScopeGuard GcLock;

		const FString ClassName = BPGC->GetName();
		UFunction* UberFunc = BPGC->UberGraphFunction;

		if (!UberFunc)
		{
			Agg.BPsNoUber++;
			WriteBpShort(FString::Printf(TEXT("%d,%s,%s,NO_UBERGRAPH"), i, *Csv(PkgName), *Csv(ClassName)));
			continue;
		}
		if (UberFunc->Script.Num() == 0)
		{
			Agg.BPsNoBytecode++;
			WriteBpShort(FString::Printf(TEXT("%d,%s,%s,NO_BYTECODE"), i, *Csv(PkgName), *Csv(ClassName)));
			continue;
		}

		// 3) Disassemble the ubergraph ONCE per BP. It is the single most expensive function in the asset —
		//    a per-event disassembly would be a 40x cost on a 40-event BP.
		FKismetBytecodeDisassemblerJson UberDis;
		const TArray<TSharedPtr<FJsonValue>> RawStmts = UberDis.SerializeFunction(UberFunc);

		TArray<MifUber::FUberStmt> Stmts;
		TMap<int32, int32> IndexByOffset;
		MifUber::BuildStatements(RawStmts, FLatentActionInfo::StaticStruct()->GetPathName(), UberFunc->GetName(),
			Stmts, IndexByOffset);

		const MifUber::FPrologue Prologue = MifUber::DetectPrologue(Stmts);   // [A]
		if (!Prologue.bSane) { Agg.BPsBadPrologue++; }

		// 4) Recover every event's entry offset from its thunk.
		TArray<MifUber::FEventEntry> Events;
		int32 BpRawPtrHits = 0, BpIdentityCalls = 0;
		for (TFieldIterator<UFunction> It(BPGC, EFieldIteratorFlags::ExcludeSuper); It; ++It)
		{
			UFunction* Func = *It;
			if (!Func || Func == UberFunc) continue;
			if (Func->HasAnyFunctionFlags(FUNC_Delegate | FUNC_UbergraphFunction)) continue;
			if (Func->Script.Num() == 0) continue;

			MifUber::FEventEntry Info;
			// A thunk that calls no ubergraph is simply a real function, not a failed event — only rows that
			// DID identity-match the ubergraph are events, so filter those out before recording a failure.
			const bool bOk = MifUber::RecoverEvent(Func, UberFunc, Info);
			if (!bOk && Info.Status == TEXT("no-ubergraph-call"))
			{
				// Real function (or a thunk we cannot see at all). Surface only the memcmp-would-have-matched
				// case: raw pointer hits with no confirmed call = the prefilter's false-positive class.
				if (Info.RawPtrHits > 0)
				{
					BpRawPtrHits += Info.RawPtrHits;
					UE_LOG(LogMifKismetReconstructor, Warning,
						TEXT("[uber] %s::%s — %d raw ubergraph-pointer byte hit(s) but NO identity-matched call. "
						     "The memcmp prefilter would have called this an event."),
						*ClassName, *Info.Name, Info.RawPtrHits);
				}
				continue;
			}

			BpRawPtrHits += Info.RawPtrHits;
			BpIdentityCalls += Info.IdentityCalls;
			Events.Add(MoveTemp(Info));
		}

		// 5) PER-EVENT reachability walk. [C] one walk per event, its own stack, no shared pop-target map —
		//    now structurally enforced: WalkEvent reports only THIS event's reached offsets and carries no
		//    cross-event state at all. The offset→events map is assembled HERE, by the measurement, and is
		//    never fed back into a walk.
		TMap<int32, TSet<int32>> Reached;   // statement offset → set of event indices
		TArray<int32> EventReachedCount;
		EventReachedCount.SetNumZeroed(Events.Num());
		int32 BadTargets = 0, ComputedHits = 0;
		bool bGuardHit = false;

		for (int32 e = 0; e < Events.Num(); ++e)
		{
			if (!Events[e].bRecovered) continue;

			TSet<int32> ThisEventReached;
			const MifUber::FWalkResult R =
				MifUber::WalkEvent(Stmts, IndexByOffset, Prologue, Events[e].EntryOffset, ThisEventReached);
			for (const int32 Off : ThisEventReached) { Reached.FindOrAdd(Off).Add(e); }

			EventReachedCount[e] = R.Reached;
			BadTargets += R.BadTargets;
			ComputedHits += R.ComputedHits;
			bGuardHit |= R.bHitGuard;
			if (R.bHitGuard)
			{
				UE_LOG(LogMifKismetReconstructor, Warning,
					TEXT("[uber] %s::%s hit the %d-iteration walk cap — this BP's counts are a LOWER BOUND."),
					*ClassName, *Events[e].Name, MifUber::GMaxWalkIterations);
			}
		}

		// 6) Tally. The prologue and EX_EndOfScript are structurally outside every slice — excluding them keeps
		//    Unreached honest (an unreached statement should mean a slicer bug or an entry-recovery miss).
		int32 Analysed = 0, Reached1 = 0, Shared = 0, Unreached = 0, MaxShare = 0;
		int32 LatentStmts = 0, SharedLatent = 0;

		for (const MifUber::FUberStmt& S : Stmts)
		{
			if (Prologue.Offsets.Contains(S.Offset)) continue;
			if (S.Inst == TEXT("EndOfScript")) continue;
			Analysed++;

			const TSet<int32>* E = Reached.Find(S.Offset);
			const int32 Degree = E ? E->Num() : 0;
			MaxShare = FMath::Max(MaxShare, Degree);

			if (Degree == 0)      { Unreached++; }
			else if (Degree == 1) { Reached1++; }
			else                  { Shared++; }

			if (S.bLatent)
			{
				LatentStmts++;
				if (Degree > 1) { SharedLatent++; }   // <<< THE go/no-go number
			}
		}

		int32 EvWithParams = 0, EvNoParams = 0, EvRecovered = 0, EvFailed = 0, NBnd = 0, NInp = 0, NSeq = 0;
		for (int32 e = 0; e < Events.Num(); ++e)
		{
			const MifUber::FEventEntry& E = Events[e];
			if (E.NumParams > 0) { EvWithParams++; } else { EvNoParams++; }
			if (E.bRecovered) { EvRecovered++; } else { EvFailed++; }
			if (E.Kind == MifUber::EEventKind::BndEvt)             { NBnd++; }
			else if (E.Kind == MifUber::EEventKind::InpActEvt)     { NInp++; }
			else if (E.Kind == MifUber::EEventKind::SequenceEvent) { NSeq++; }

			// The recovered frame→param map (§1.4), as the reconstructor will consume it. A param with no entry
			// here is a param the reconstructor will NOT rewire to an event pin — so surface it, don't hide it.
			FString ParamMap;
			for (const TPair<FName, FName>& KV : E.FrameParamMap)
			{
				ParamMap += FString::Printf(TEXT("%s=%s "), *KV.Key.ToString(), *KV.Value.ToString());
			}

			WriteEv(FString::Printf(TEXT("%d,%s,%s,%s,%s,%d,%d,%d,%s,%s,%d,%d,%d,%s"),
				i, *Csv(PkgName), *Csv(ClassName), *Csv(E.Name), MifUber::KindName(E.Kind),
				E.EntryOffset, E.NumParams, E.FrameLets, *Csv(ParamMap.TrimEnd()), *Csv(E.FastCall),
				E.RawPtrHits, E.IdentityCalls, EventReachedCount[e], *Csv(E.Status)));
		}

		const float PctShared = Analysed > 0 ? (100.0f * Shared / Analysed) : 0.0f;

		FString Notes;
		if (!Prologue.bSane)  { Notes += TEXT("UNEXPECTED-PROLOGUE "); }
		if (UberDis.bDisassemblyFailed)
		{
			Notes += FString::Printf(TEXT("UBER-DISASM-ABORT@%d(op=0x%02X) "), UberDis.FailedAtIndex, UberDis.FailedOpcode);
			Agg.BPsDisasmFailed++;
		}
		if (EvFailed > 0)     { Notes += TEXT("ENTRY-RECOVERY-FAILED "); Agg.BPsEntryFailed++; }
		if (bGuardHit)        { Notes += TEXT("WALK-CAP-HIT "); Agg.BPsGuardHit++; }
		if (SharedLatent > 0) { Notes += TEXT("SHARED-LATENT "); Agg.BPsWithSharedLatent++; }

		const TCHAR* Status = Events.Num() == 0 ? TEXT("NO_EVENTS") : TEXT("OK");

		WriteBp(FString::Printf(
			TEXT("%d,%s,%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.1f,%d,%d,%d,%d,%s,%d,%d,%s"),
			i, *Csv(PkgName), *Csv(ClassName), Status, *Csv(Prologue.Kind),
			UberFunc->Script.Num(), Stmts.Num(), Analysed,
			Events.Num(), EvRecovered, EvFailed, EvWithParams, EvNoParams, NBnd, NInp, NSeq,
			Reached1, Shared, Unreached, MaxShare, PctShared,
			LatentStmts, SharedLatent, BadTargets, ComputedHits,
			bGuardHit ? TEXT("yes") : TEXT("no"),
			BpRawPtrHits, BpIdentityCalls, *Csv(Notes.TrimEnd())));

		Agg.BPsWithUber++;
		if (Events.Num() > 0) { Agg.BPsWithEvents++; }
		Agg.Events += Events.Num();
		Agg.EventsRecovered += EvRecovered;
		Agg.EventsFailed += EvFailed;
		Agg.EventsWithParams += EvWithParams;
		Agg.EventsNoParams += EvNoParams;
		Agg.BndEvts += NBnd;
		Agg.InpActEvts += NInp;
		Agg.SeqEvts += NSeq;
		Agg.Stmts += Stmts.Num();
		Agg.Analysed += Analysed;
		Agg.Reached1 += Reached1;
		Agg.Shared += Shared;
		Agg.Unreached += Unreached;
		Agg.LatentStmts += LatentStmts;
		Agg.SharedLatent += SharedLatent;
		Agg.BadTargets += BadTargets;
		Agg.ComputedHits += ComputedHits;
		Agg.RawPtrHits += BpRawPtrHits;
		Agg.IdentityCalls += BpIdentityCalls;
		Agg.MaxShareDegree = FMath::Max(Agg.MaxShareDegree, MaxShare);
	}

	// 7) Console summary — the Phase-1 go/no-go read-out.
	const float PctSharedAgg = Agg.Analysed > 0 ? (100.0f * Agg.Shared / Agg.Analysed) : 0.0f;
	const float PctUnreached = Agg.Analysed > 0 ? (100.0f * Agg.Unreached / Agg.Analysed) : 0.0f;

	UE_LOG(LogMifKismetReconstructor, Display, TEXT("================ mif.kr.AnalyzeUbergraph — PHASE 1 GO/NO-GO ================"));
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("  Blueprints           : %d scanned | %d with ubergraph | %d none | %d no bytecode | %d resolve-fail"),
		Agg.BPs, Agg.BPsWithUber, Agg.BPsNoUber, Agg.BPsNoBytecode, Agg.BPsResolveFail);
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("  Events               : %d total | %d recovered | %d FAILED (%d BPs affected)"),
		Agg.Events, Agg.EventsRecovered, Agg.EventsFailed, Agg.BPsEntryFailed);
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("  Event params         : %d with params | %d no-param"),
		Agg.EventsWithParams, Agg.EventsNoParams);
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("  Filtered-out shapes  : %d BndEvt__ | %d InpActEvt_ | %d SequenceEvent__  (dropped by IsGeneratedFunctionName today)"),
		Agg.BndEvts, Agg.InpActEvts, Agg.SeqEvts);
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("  Statements           : %d total | %d analysed (prologue + EndOfScript excluded)"),
		Agg.Stmts, Agg.Analysed);
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("  Reachability         : %d single-event | %d SHARED (%.2f%%) | %d UNREACHED (%.2f%%) | max share degree %d"),
		Agg.Reached1, Agg.Shared, PctSharedAgg, Agg.Unreached, PctUnreached, Agg.MaxShareDegree);
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("  >>> SHARED LATENT    : %d statement(s) across %d BP(s)   [of %d latent statements]"),
		Agg.SharedLatent, Agg.BPsWithSharedLatent, Agg.LatentStmts);
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("      A latent node reached by >1 event CANNOT be split faithfully: Delay dedupes on"));
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("      (CallbackTarget, UUID); duplicating it mints two UUIDs => concurrent, not deduped."));
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("  Walk health          : %d bad targets | %d computed-jump hits | %d BP(s) hit the walk cap | %d BP(s) odd prologue"),
		Agg.BadTargets, Agg.ComputedHits, Agg.BPsGuardHit, Agg.BPsBadPrologue);
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("  Prefilter soundness  : %d raw pointer byte-hits vs %d identity-confirmed calls (gap = memcmp false positives)"),
		Agg.RawPtrHits, Agg.IdentityCalls);
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("  Ubergraph disasm     : %d BP(s) aborted mid-disassembly (their counts are partial)"),
		Agg.BPsDisasmFailed);
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("  UNREACHED is the cheapest correctness signal we have: a non-trivial count means a"));
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("  slicer bug or an entry-recovery miss, NOT dead code."));
	UE_LOG(LogMifKismetReconstructor, Display, TEXT("============================================================================"));
	if (GLog) { GLog->Flush(); }
}

static FAutoConsoleCommand GMifKrAnalyzeUbergraph(
	TEXT("mif.kr.AnalyzeUbergraph"),
	TEXT("READ-ONLY Phase-1 measurement: per-event ubergraph slicing statistics (sharing, shared-latent, unreached). "
	     "Usage: mif.kr.AnalyzeUbergraph [pathSubstr=/Game/ | *] [startIndex=0]"),
	FConsoleCommandWithArgsDelegate::CreateStatic(&MifKr_AnalyzeUbergraph));

#endif // MIF_KR_DEBUG
