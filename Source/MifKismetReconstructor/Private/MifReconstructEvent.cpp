// UBERGRAPH -> PER-EVENT SPLIT, Phase 2: reconstruct an EVENT'S BODY into the event graph, hanging it off the
// event node the host already spawned.
//
// The mechanism is simpler than it looks. The ubergraph is NOT a switch table: it is an EX_ComputedJump to a RAW
// BYTE OFFSET supplied by the caller, and each event thunk passes its own offset as an EX_IntConst. So "find the
// event's entry" is a direct read of the thunk's bytecode, not an inference. Everything hard is downstream:
// which statements belong to that event, and with what flow stack.
//
// ---------------------------------------------------------------------------------------------------------
// The shape of this file, and why:
//
//  * ENTRY RECOVERY + THE WALK are NOT implemented here. They live in Analysis/MifUbergraphSlicer.{h,cpp},
//    factored out of the Phase-1 analyzer that already PROVED them on 1277 cooked DDS2 Blueprints (5871/5871
//    events recovered, 0 of 122,638 ubergraph statements unreached, 0 bad targets, 0 walk-guard hits). Rebuilding
//    that logic here would mean two implementations and one of them silently wrong.
//
//  * PER-BP CACHE. The ubergraph is the most expensive function in the asset and is exactly where BP_BaseNPC
//    died. It is disassembled and transformed ONCE per Blueprint, never once per event: a 40-event BP would
//    otherwise pay 40x for it. See FUberCache for the lifetime guard that makes caching the IR safe.
//
//  * THE IR IS SHARED; THE WALK IS NOT. [C] A shared region's EXIT EDGE IS ENTRY-DEPENDENT — the same
//    EndOfThread pops a DIFFERENT continuation depending on which event entered. So the cached IR statements are
//    reused across events (they are just decoded bytecode), but every event gets its OWN walk, its OWN
//    entry-seeded stack, its OWN decompiler instance and therefore its OWN FlowStackPopTarget map. There is
//    deliberately no cross-event pop-target state anywhere in this pipeline; a single global one would be a
//    silent-wrong-wiring bug, and FKismetGraphDecompiler::FlowStackPopTarget is IR-statement-keyed and written
//    with TMap::Add (overwrite), so it would not even fail loudly.
//
//  * DEGRADE UNIT = ONE EVENT. A failing event leaves its stub node + a failure comment and the sweep continues.
//    Nothing here asserts on decoded data: every value out of cooked bytecode is untrusted input.
// ---------------------------------------------------------------------------------------------------------

#include "MifReconstructorDebug.h"
#include "MifReconstructPipeline.h"
#include "Analysis/MifUbergraphSlicer.h"
#include "Toolkit/KismetBytecodeDisassemblerJson.h"
#include "AssetGeneration/KismetBytecodeTransformer.h"
#include "AssetGeneration/KismetGraphDecompiler.h"
#include "AssetGeneration/KismetIntermediateFormat.h"

#include "Engine/Blueprint.h"
#include "Engine/BlueprintGeneratedClass.h"
#include "Engine/LatentActionManager.h"
#include "EdGraph/EdGraph.h"
#include "K2Node.h"
#include "UObject/GarbageCollection.h"
#include "HAL/IConsoleManager.h"
#include "Dom/JsonObject.h"
#include "Dom/JsonValue.h"

// Order of operations (crash-hardening): events are reconstructed AFTER the real functions, and behind this CVar,
// so a bad build degrades to EXACTLY today's measured behaviour (PASS 1228/1256, fidelity 54.65%) rather than
// regressing the working set. Default OFF until a full 1256-BP batch is green.
static TAutoConsoleVariable<int32> CVarMifKrEvents(
	TEXT("mif.kr.Events"),
	1,   // DEFAULT ON (2026-07-18): verified 85.9% event reconstruction, FAIL 10/481 (baseline 8). Children/standalones now show reconstructed event logic. Set 0 to restore bare stubs.
	TEXT("Reconstruct EVENT bodies by slicing the ubergraph (1 = on [default]; 0 = off: events stay bare stub nodes)."),
	ECVF_Default);

// Gate latent (Delay/timeline) resume reconstruction. Default 0 = refuse any latent-reaching event (the safe behaviour,
// since a mis-wired resume compiles but is silently wrong). 1 = attempt it now that the transformer resume patch-up is
// live for the source-ubergraph path (KismetBytecodeTransformer.cpp latent gate). Proven on a bridge testbed before
// the default flips. SHARED-latent (a) and incomplete-census (a0) stay refused regardless — those are unfixable/unsafe.
static TAutoConsoleVariable<int32> CVarMifKrLatentResume(
	TEXT("mif.kr.LatentResume"),
	1,   // DEFAULT ON (2026-07-18): latent-refused 45→0, FAIL stayed 8 (no silently-wrong resume). Set 0 to refuse latent-reaching events.
	TEXT("Reconstruct latent (Delay/timeline) event bodies with resume wiring (1 = on [default]; 0 = refuse)."),
	ECVF_Default);

namespace
{
	// -----------------------------------------------------------------------------------------------------
	// Per-Blueprint ubergraph cache.
	//
	// Holds the decoded ubergraph for the BP currently being copied. SINGLE SLOT on purpose: the host copies one
	// Blueprint at a time and calls us once per event, so a single slot is exactly the right scope and cannot
	// grow unbounded across a 1256-BP batch or leak one BP's decode into another's.
	//
	// LIFETIME — why keying on the skeleton is not paranoia. The IR holds RAW, UN-ROOTED UFunction*/UClass*
	// pointers. The COOKED side is safe: cooked script pointers are reported to GC by their own UStruct, and the
	// cooked class is alive as the copy's ParentClass. The COPY side is not: a self-call resolves against
	// OwnerBP->SkeletonGeneratedClass, and a skeleton recompile between events REPLACES that class, orphaning the
	// old one — GC then collects it and every cached pointer into it dangles. That is precisely the BP_BaseNPC
	// lifetime bug (crash after ~40 functions + an 8s GC stall), and it is why the FGCScopeGuard is PER EVENT and
	// cannot be stretched across the cache. So: cache the decode, but tie its validity to the exact skeleton it
	// was resolved against. A changed skeleton REBUILDS (a few ms) instead of dereferencing freed memory.
	// -----------------------------------------------------------------------------------------------------
	struct FUberCache
	{
		// Identity of what this cache is valid FOR. These pointers are ONLY ever COMPARED, never dereferenced —
		// between Blueprints the copy BP and its skeleton are collected, so the cached values may be stale
		// addresses. UberFuncName is carried alongside precisely because a stale address can be REUSED: identity
		// alone could then false-match and hand one Blueprint the other's decoded ubergraph. A name that also
		// matches on a reused address is not a coincidence worth reasoning about.
		const UFunction* UberFunc = nullptr;
		const UBlueprint* OwnerBP = nullptr;
		const UClass* SkeletonAtBuild = nullptr;
		FString UberFuncName;

		// decoded ubergraph (built once)
		TArray<MifUber::FUberStmt> Stmts;
		TMap<int32, int32> IndexByOffset;                                  // absolute byte offset -> index into Stmts
		MifUber::FPrologue Prologue;
		TArray<TSharedPtr<FKismetCompiledStatement>> IR;                   // 1:1 with Stmts, same order
		bool bUsable = false;

		// Offsets of LATENT statements reached by MORE THAN ONE event. §3.4's named limitation, resolved once per
		// BP because it needs every event's slice, not just this one's. THE genuinely-unfixable case.
		TSet<int32> SharedLatentOffsets;

		// Is SharedLatentOffsets a COMPLETE census, or only a lower bound? The scan walks every event; each walk is
		// iteration-capped. A capped walk returns a PARTIAL reach set, which can under-count a latent's reachers from
		// 2 to 1 and silently drop it out of the shared set — the one error this whole mechanism exists to prevent.
		// So the scan's FWalkResult is checked, not discarded, and an incomplete census is recorded as such rather
		// than passed off as an authoritative "nothing is shared".
		bool bSharedLatentCensusComplete = true;

		// Set once the decode has been ATTEMPTED for this key, whatever the outcome. A FAILED decode is cached
		// just as deliberately as a good one: without this, a BP whose ubergraph will not disassemble would
		// re-disassemble it — the most expensive operation in the asset — once per event, 40 times, to fail 40
		// times identically.
		bool bAttempted = false;

		// InUber / InBP are LIVE (passed in this call), so reading InUber->GetName() is safe; the cached side is
		// only ever compared.
		bool KeyMatches(const UFunction* InUber, const UBlueprint* InBP) const
		{
			return bAttempted && InUber && InBP
				&& UberFunc == InUber && OwnerBP == InBP
				&& SkeletonAtBuild == (const UClass*) InBP->SkeletonGeneratedClass
				&& UberFuncName == InUber->GetName();
		}
	};

	// Game-thread only, like the copy action that drives it. Single slot: the host copies one Blueprint at a time.
	FUberCache GUberCache;

	// Build (or rebuild) the cache for this BP's ubergraph. Returns false on any decode failure — the caller then
	// degrades this event to a stub, loudly.
	bool EnsureUberCache(UFunction* UberFunc, UBlueprint* OwnerBP, UBlueprintGeneratedClass* SourceBPGC)
	{
		if (GUberCache.KeyMatches(UberFunc, OwnerBP)) return GUberCache.bUsable;

		GUberCache = FUberCache();
		GUberCache.UberFunc = UberFunc;
		GUberCache.OwnerBP = OwnerBP;
		GUberCache.SkeletonAtBuild = (const UClass*) OwnerBP->SkeletonGeneratedClass;
		GUberCache.UberFuncName = UberFunc->GetName();
		GUberCache.bAttempted = true;

#if MIF_KR_DEBUG
		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[event] BEGIN ubergraph decode %s (%d bytes)"),
			*UberFunc->GetName(), UberFunc->Script.Num());
		if (GLog) { GLog->Flush(); }
#endif

		// --- 1) disassemble ONCE ---
		FKismetBytecodeDisassemblerJson Dis;
		const TArray<TSharedPtr<FJsonValue>> RawStmts = Dis.SerializeFunction(UberFunc);
		if (Dis.bDisassemblyFailed)
		{
			// A partial disassembly is NOT usable for slicing: statements past the abort simply do not exist, so
			// a walk would report a truncated slice as if it were complete — a silently amputated event body.
			// Refuse the whole BP's events instead.
#if MIF_KR_DEBUG
			UE_LOG(LogMifKismetReconstructor, Warning,
				TEXT("[event] ubergraph %s disassembly ABORTED at opcode 0x%02X (byte %d) → every event of this BP degrades to a stub."),
				*UberFunc->GetName(), Dis.FailedOpcode, Dis.FailedAtIndex);
#endif
			return false;
		}

		MifUber::BuildStatements(RawStmts, FLatentActionInfo::StaticStruct()->GetPathName(), UberFunc->GetName(),
			GUberCache.Stmts, GUberCache.IndexByOffset);

		GUberCache.Prologue = MifUber::DetectPrologue(GUberCache.Stmts);   // [A] read the shape; never assume it
		if (!GUberCache.Prologue.bSane)
		{
#if MIF_KR_DEBUG
			UE_LOG(LogMifKismetReconstructor, Warning,
				TEXT("[event] ubergraph %s has an unrecognised prologue ('%s') → every event of this BP degrades to a stub. "
				     "Expected EX_PushExecutionFlow+EX_ComputedJump or a bare EX_ComputedJump."),
				*UberFunc->GetName(), *GUberCache.Prologue.Kind);
#endif
			return false;
		}

		// --- 2) transform ONCE (JSON -> compiled-statement IR) ---
		// The IR array is 1:1 and in the same ORDER as Stmts. That correspondence is the load-bearing assumption
		// of expressing a slice as indices, so it is established deliberately, not hoped for:
		//   - SetSourceStatements emits exactly one entry per input object, in order (an unhandled opcode becomes
		//     a NULL entry rather than a dropped one — the driver already skips nulls), and
		//   - this filter is character-for-character the one BuildStatements applies (object-typed, StatementIndex
		//     present and >= 0), so both arrays drop exactly the same inputs.
		// Unlike the real-function path, EX_EndOfScript is NOT dropped here: dropping it on one side only would
		// shift every subsequent index by one. It transforms to a null entry and is excluded from slices below.
		TArray<TSharedPtr<FJsonObject>> StmtObjects;
		StmtObjects.Reserve(RawStmts.Num());
		for (const TSharedPtr<FJsonValue>& V : RawStmts)
		{
			if (!V.IsValid() || V->Type != EJson::Object) continue;
			const TSharedPtr<FJsonObject> O = V->AsObject();
			if (!O.IsValid()) continue;
			double StmtIndex = 0.0;
			if (!O->TryGetNumberField(FString(TEXT("StatementIndex")), StmtIndex) || (int32) StmtIndex < 0) continue;
			StmtObjects.Add(O);
		}

		// SourceClass MUST be the exact expression the disassembler used as its SelfScope so the "<SELF>" tokens it
		// wrote into pin types deserialize back to the SAME class object they were written for.
		FKismetBytecodeTransformer Xform(OwnerBP, UberFunc->GetTypedOuter<UClass>());
		Xform.SetSourceStatements(UberFunc->GetName(), StmtObjects);
		GUberCache.IR = Xform.FinishGeneration();

		// NOTE (deliberate): SetUberGraphTransformer() is NOT called. It is guarded by
		// `check(Transformer->IsUberGraphFunction())`, and IsUberGraphFunction() compares the transformed
		// function's name against "ExecuteUbergraph_" + OwnerBlueprint->GetName() — the COPY's name
		// ("MifKrBatch_BP_Foo" / "BP_Foo_Child"), never the cooked source's ("BP_Foo"). That check would FIRE.
		// It is not needed here either: it exists to resolve a THUNK's call into the ubergraph, and we decode the
		// thunk ourselves. The same name mismatch also keeps the transformer's dormant latent patch-up dark — see
		// the latent degrade below, which is why that is not a silent problem today.

		if (GUberCache.IR.Num() != GUberCache.Stmts.Num())
		{
			// The 1:1 correspondence is the load-bearing assumption of the whole slice-as-indices design. If it
			// ever fails, every index below would address the WRONG statement — a plausible-looking, totally wrong
			// graph. Refuse rather than emit that.
#if MIF_KR_DEBUG
			UE_LOG(LogMifKismetReconstructor, Warning,
				TEXT("[event] ubergraph %s: IR/statement count mismatch (%d vs %d) → every event of this BP degrades to a stub."),
				*UberFunc->GetName(), GUberCache.IR.Num(), GUberCache.Stmts.Num());
#endif
			return false;
		}

		// --- 3) shared-latent detection (§3.4) — needs EVERY event's slice, so it is done once, here ---
		// Walk every event of this BP and count, per latent statement, how many events reach it. A latent node
		// reached by >1 event CANNOT be split faithfully: Delay dedupes on (CallbackTarget, UUID), so duplicating
		// it into two event graphs mints TWO UUIDs and yields concurrent execution where the cooked original
		// deduped. Phase 1 measured this as RARE but REAL — 20 statements across 18 BPs.
		TMap<int32, int32> LatentReachCount;
		for (TFieldIterator<UFunction> It(SourceBPGC, EFieldIteratorFlags::ExcludeSuper); It; ++It)
		{
			UFunction* Func = *It;
			if (!Func || Func == UberFunc) continue;
			if (Func->HasAnyFunctionFlags(FUNC_Delegate | FUNC_UbergraphFunction)) continue;
			if (Func->Script.Num() == 0) continue;

			MifUber::FEventEntry Info;
			if (!MifUber::RecoverEvent(Func, UberFunc, Info)) continue;   // real function, or unrecoverable

			TSet<int32> Reached;
			const MifUber::FWalkResult ScanWalk = MifUber::WalkEvent(GUberCache.Stmts, GUberCache.IndexByOffset,
				GUberCache.Prologue, Info.EntryOffset, Reached);
			if (ScanWalk.bHitGuard)
			{
				// A LOWER-BOUND reach set. Counting it would under-count sharing, so the census is no longer
				// authoritative for this Blueprint. Keep scanning (a later event may still prove sharing — the set
				// only ever grows), but never let the result be read as "proven not shared".
				GUberCache.bSharedLatentCensusComplete = false;
#if MIF_KR_DEBUG
				UE_LOG(LogMifKismetReconstructor, Warning,
					TEXT("[event] shared-latent scan: walk of '%s' hit the %d-iteration cap → the shared-latent census for "
					     "ubergraph %s is a LOWER BOUND; every latent-reaching event of this BP will be refused."),
					*Info.Name, MifUber::GMaxWalkIterations, *UberFunc->GetName());
#endif
			}
			for (const int32 Off : Reached)
			{
				const int32* Idx = GUberCache.IndexByOffset.Find(Off);
				if (Idx && GUberCache.Stmts.IsValidIndex(*Idx) && GUberCache.Stmts[*Idx].bLatent)
				{
					++LatentReachCount.FindOrAdd(Off);
				}
			}
		}
		for (const TPair<int32, int32>& KV : LatentReachCount)
		{
			if (KV.Value > 1) { GUberCache.SharedLatentOffsets.Add(KV.Key); }
		}

		GUberCache.bUsable = true;

#if MIF_KR_DEBUG
		UE_LOG(LogMifKismetReconstructor, Warning,
			TEXT("[event] ubergraph %s decoded: %d stmts | prologue=%s | initialStack=%d | sharedLatent=%d"),
			*UberFunc->GetName(), GUberCache.Stmts.Num(), *GUberCache.Prologue.Kind,
			GUberCache.Prologue.InitialStack.Num(), GUberCache.SharedLatentOffsets.Num());
		if (GLog) { GLog->Flush(); }
#endif
		return true;
	}

	// Failure comment ON THE EVENT NODE. This is the whole point of degrading loudly, and the comment — not the
	// log — is the load-bearing part, so it is emitted in EVERY configuration: the modder opens the graph and is
	// TOLD the body is missing and why, instead of finding a bare event node and reasonably concluding the event
	// was empty in the original. A silently empty event is the worst output this tool can produce; it is
	// indistinguishable from a correct one.
	void MarkEventDegraded(UK2Node* EventNode, const FString& Reason)
	{
		if (EventNode)
		{
			EventNode->NodeComment = FString::Printf(TEXT("[reconstruct] event body NOT reconstructed: %s"), *Reason);
			EventNode->bCommentBubblePinned = true;
			EventNode->bCommentBubbleVisible = true;
		}
#if MIF_KR_DEBUG
		UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[reconstruct:event] %s"), *Reason);
#endif
	}
}

void MifKr_ResetUbergraphCache()
{
	GUberCache = FUberCache();
}

bool MifReconstructEventIntoGraph(UFunction* EventThunk, UEdGraph* EventGraph, UK2Node* EventNode, UBlueprint* OwnerBP)
{
	if (CVarMifKrEvents.GetValueOnAnyThread() == 0) return false;   // off: the node stays a bare stub (today's behaviour)
	if (!EventThunk || !EventGraph || !EventNode || !OwnerBP) return false;
	if (EventThunk->Script.Num() == 0) return false;

	// The ubergraph is derivable from the thunk, which is exactly why it is not in the delegate's signature: the
	// engine fork never has to reason about ubergraph identity.
	UBlueprintGeneratedClass* SourceBPGC = Cast<UBlueprintGeneratedClass>(EventThunk->GetOwnerClass());
	if (!SourceBPGC) return false;
	UFunction* UberFunc = SourceBPGC->UberGraphFunction;
	if (!UberFunc || UberFunc->Script.Num() == 0) return false;

	// PER EVENT, not per BP. The IR holds raw un-rooted pointers and a NewObject inside SpawnNode can tick
	// incremental GC mid-reconstruction and collect one. Locking GC for THIS event keeps everything alive while
	// the graph is wired — and letting it go between events is the point: one guard held across a 40-event BP
	// reintroduces the exact BP_BaseNPC 8s-GC-stall failure.
	FGCScopeGuard MifEventGCLock;

#if MIF_KR_DEBUG
	UE_LOG(LogMifKismetReconstructor, Warning, TEXT("[event] BEGIN %s"), *EventThunk->GetName());
	if (GLog) { GLog->Flush(); }
#endif

	// --- 1) the ubergraph, decoded once per BP ---
	if (!EnsureUberCache(UberFunc, OwnerBP, SourceBPGC))
	{
		MarkEventDegraded(EventNode, FString::Printf(TEXT("ubergraph %s could not be decoded"), *UberFunc->GetName()));
		return false;
	}

	// --- 2) this event's entry offset + param map, straight out of its own thunk ---
	MifUber::FEventEntry Entry;
	if (!MifUber::RecoverEvent(EventThunk, UberFunc, Entry))
	{
		MarkEventDegraded(EventNode, FString::Printf(TEXT("entry recovery failed for %s (%s)"),
			*EventThunk->GetName(), *Entry.Status));
		return false;
	}

	// --- 3) this event's slice: its OWN walk, its OWN entry-seeded stack [B][C] ---
	TSet<int32> ReachedOffsets;
	const MifUber::FWalkResult Walk = MifUber::WalkEvent(GUberCache.Stmts, GUberCache.IndexByOffset,
		GUberCache.Prologue, Entry.EntryOffset, ReachedOffsets);

	if (Walk.bHitGuard)
	{
		// The slice is a LOWER BOUND — an amputated body would compile and be silently wrong. Refuse it.
		MarkEventDegraded(EventNode, FString::Printf(
			TEXT("%s: slice walk hit the %d-iteration cap → slice is incomplete"),
			*Entry.Name, MifUber::GMaxWalkIterations));
		return false;
	}
	if (ReachedOffsets.Num() == 0)
	{
		MarkEventDegraded(EventNode, FString::Printf(TEXT("%s: empty slice at entry offset %d"),
			*Entry.Name, Entry.EntryOffset));
		return false;
	}

	// --- 4) the two shapes this phase refuses, LOUDLY ---
	//
	// Note the layering: in THIS phase (b) refuses every latent statement, so it already subsumes (a) as a safety
	// net — which also means an unreliable shared-latent set (e.g. one built from a walk that hit the cap) cannot
	// produce a wrong graph here. (a) is kept in front of it for two reasons: it gives the modder the SPECIFIC and
	// permanent truth ("this cannot be split faithfully, ever") instead of the temporary one ("latent is deferred"),
	// and it is the check that must survive into Phase 4, when (b) goes away and (a) becomes the only thing
	// standing between a shared Delay and a silently-concurrent reconstruction.

	// (a) SHARED LATENT — the genuinely unfixable case (§3.4). Duplication changes latent dedup semantics
	//     (two Delay copies = two UUIDs = concurrent where the cooked original ignored the second call), and
	//     extraction into a helper function does not compile at all (latent actions only ever resume into the
	//     ubergraph). There is no correct output, so there must not be a quiet one.
	TArray<int32> SharedLatentHits;
	int32 FirstLatentOffset = -1;
	for (const int32 Off : ReachedOffsets)
	{
		if (GUberCache.SharedLatentOffsets.Contains(Off)) { SharedLatentHits.Add(Off); }
		if (FirstLatentOffset < 0)
		{
			const int32* LIdx = GUberCache.IndexByOffset.Find(Off);
			if (LIdx && GUberCache.Stmts.IsValidIndex(*LIdx) && GUberCache.Stmts[*LIdx].bLatent) { FirstLatentOffset = Off; }
		}
	}
	// (a0) The census that (a) consults is INCOMPLETE — a capped scan walk means "not in SharedLatentOffsets" no
	//      longer means "not shared". An empty SharedLatentHits is then an absence of evidence, not evidence of
	//      absence, so a latent-reaching event must be refused on the census's word alone. This check has no effect
	//      while (b) below refuses every latent; it exists so that removing (b) in Phase 4 cannot quietly promote an
	//      unproven latent to "safe to duplicate", which is the exact silent-concurrency bug (a) guards against.
	if (!GUberCache.bSharedLatentCensusComplete && FirstLatentOffset >= 0)
	{
		MarkEventDegraded(EventNode, FString::Printf(
			TEXT("%s reaches a LATENT statement (offset %d) and this Blueprint's shared-latent census is INCOMPLETE (a "
			     "scan walk hit the %d-iteration cap). Whether that latent is shared with another event is UNKNOWN, and "
			     "duplicating a shared latent silently changes Delay dedup into concurrent execution. Refused rather "
			     "than guessed."),
			*Entry.Name, FirstLatentOffset, MifUber::GMaxWalkIterations));
		return false;
	}
	if (SharedLatentHits.Num() > 0)
	{
		MarkEventDegraded(EventNode, FString::Printf(
			TEXT("%s reaches %d LATENT statement(s) SHARED with another event (offset %d, ...). A shared latent region "
			     "cannot be split faithfully: Delay dedupes on (CallbackTarget, UUID), so duplicating it into per-event "
			     "graphs mints two UUIDs and runs concurrently where the cooked original deduped. Body left out rather "
			     "than reconstructed wrong."),
			*Entry.Name, SharedLatentHits.Num(), SharedLatentHits[0]));
		return false;
	}

	// (b) ANY LATENT — a Phase-2 scope limit, not a limitation of the approach. The transformer's latent resume
	//     patch-up (KismetBytecodeTransformer.cpp:1100) is gated on IsUberGraphFunction(), which compares against
	//     "ExecuteUbergraph_" + the COPY Blueprint's name and therefore never matches a cooked source ubergraph.
	//     With it dark, a Delay's Completed exec pin would simply never be wired — and the graph would still
	//     compile, i.e. the failure is silent. Refuse until that patch-up is genuinely live — UNLESS mif.kr.LatentResume is on (then reconstruct).
	if (CVarMifKrLatentResume.GetValueOnAnyThread() == 0)
	for (const int32 Off : ReachedOffsets)
	{
		const int32* Idx = GUberCache.IndexByOffset.Find(Off);
		if (Idx && GUberCache.Stmts.IsValidIndex(*Idx) && GUberCache.Stmts[*Idx].bLatent)
		{
			MarkEventDegraded(EventNode, FString::Printf(
				TEXT("%s contains a LATENT call (Delay/timeline) at offset %d. Latent resume wiring is deferred: the "
				     "transformer's linkage patch-up is gated on IsUberGraphFunction(), which tests the COPY's name and "
				     "never matches a cooked ubergraph — so the resume edge would be silently dropped."),
				*Entry.Name, Off));
			return false;
		}
	}

	// --- 5) materialise the slice: reached statements only, in ASCENDING OFFSET order ---
	// Offset order is what makes array adjacency mean bytecode fall-through, which the decompiler relies on. That
	// survives slicing: if a reached statement falls through, its fall-through target IS the immediately-next
	// statement and is therefore also reached — so no dropped statement can ever separate two slice neighbours
	// that fall through to each other. Statements dropped from between two neighbours are only ever ones reached
	// exclusively via a jump, and jumps are followed by TargetLabel, not by adjacency.
	TArray<int32> SliceIdx;                 // indices into GUberCache.Stmts / .IR, ascending
	SliceIdx.Reserve(ReachedOffsets.Num());
	for (const int32 Off : ReachedOffsets)
	{
		if (GUberCache.Prologue.Offsets.Contains(Off)) continue;   // the dispatch head is in no event's body
		const int32* Idx = GUberCache.IndexByOffset.Find(Off);
		if (!Idx || !GUberCache.Stmts.IsValidIndex(*Idx)) continue;
		if (GUberCache.Stmts[*Idx].Inst == TEXT("EndOfScript")) continue;   // the script terminator, not a statement
		SliceIdx.Add(*Idx);
	}
	SliceIdx.Sort();

	TArray<TSharedPtr<FKismetCompiledStatement>> SliceIR;
	TMap<int32, int32> SlicePosByUberIdx;   // ubergraph statement index -> position within SliceIR
	SliceIR.Reserve(SliceIdx.Num());
	for (const int32 Idx : SliceIdx)
	{
		if (!GUberCache.IR.IsValidIndex(Idx)) continue;
		SlicePosByUberIdx.Add(Idx, SliceIR.Num());
		// The SAME IR statement object is handed to every event that reaches it — [C]: the IR is shared (it is
		// just decoded bytecode), the WALK and the wiring are not. Each event runs its own decompiler instance
		// with its own maps, so a duplicated statement becomes a separate node per event, re-walked per event.
		SliceIR.Add(GUberCache.IR[Idx]);
	}
	if (SliceIR.Num() == 0)
	{
		MarkEventDegraded(EventNode, FString::Printf(TEXT("%s: slice is empty after excluding the prologue"), *Entry.Name));
		return false;
	}

	// The event's entry, as a position within the slice. NOT assumed to be 0.
	const int32* EntryUberIdx = GUberCache.IndexByOffset.Find(Entry.EntryOffset);
	const int32* EntryPos = EntryUberIdx ? SlicePosByUberIdx.Find(*EntryUberIdx) : nullptr;
	if (!EntryPos)
	{
		MarkEventDegraded(EventNode, FString::Printf(TEXT("%s: entry offset %d is not in its own slice"),
			*Entry.Name, Entry.EntryOffset));
		return false;
	}

	// [B] The flow stack AS IT IS at the entry: the prologue's return address, translated to slice positions. An
	// address that no EndOfThread in this slice ever pops is simply absent from the slice; dropping it is exact
	// (an unpopped continuation has no effect) — the alternative, an index into nothing, would not be.
	TArray<int32> InitialStack;
	for (const int32 Off : GUberCache.Prologue.InitialStack)
	{
		const int32* UIdx = GUberCache.IndexByOffset.Find(Off);
		const int32* Pos = UIdx ? SlicePosByUberIdx.Find(*UIdx) : nullptr;
		if (Pos) { InitialStack.Add(*Pos); }
	}

	// --- 6) frame property -> event node output pin (§1.4) ---
	// Read from the thunk's own EX_LetValueOnPersistentFrame statements. Event params are NOT ubergraph params:
	// the thunk copies each one into an ubergraph FRAME property and the body reads THAT, so every read has to be
	// rewired to the event node's pin. The frame name is generated + uniquified — never reconstruct it.
	TMap<FName, FName> FrameParamMap;
	for (const TPair<FName, FName>& KV : Entry.FrameParamMap)
	{
		FrameParamMap.Add(KV.Key, KV.Value);
	}

	// --- 7) reconstruct the slice off the EVENT NODE's exec output ---
	FKismetGraphDecompiler Decomp(UberFunc, EventGraph);
	Decomp.SetEventContext(EventNode, FrameParamMap, *EntryPos, InitialStack);
	const bool bOk = Decomp.Run(UberFunc, SliceIR, EventGraph, OwnerBP);

#if MIF_KR_DEBUG
	UE_LOG(LogMifKismetReconstructor, Warning,
		TEXT("[event] %s → %s | entry=%d (slicePos %d) | slice=%d/%d stmts | params=%d | nodes=%d"),
		*Entry.Name, bOk ? TEXT("ok") : TEXT("degraded"), Entry.EntryOffset, *EntryPos,
		SliceIR.Num(), GUberCache.Stmts.Num(), FrameParamMap.Num(), Decomp.GetNodesCreated());
	if (GLog) { GLog->Flush(); }
#endif

	if (!bOk)
	{
		// Degraded, not failed: the decompiler leaves whatever it managed to build. Say so on the node — a
		// PARTIAL body that looks complete is the most dangerous output this tool can produce.
		MarkEventDegraded(EventNode, FString::Printf(
			TEXT("%s: body reconstructed PARTIALLY (some statements degraded) — do not trust it as complete"), *Entry.Name));
	}
	return bOk;
}
