#pragma once

// The ubergraph slicer: entry recovery + per-event CFG reachability, factored VERBATIM out of
// MifUbergraphAnalyzer.cpp (the Phase-1 read-only sweep that PROVED this logic on 1277 cooked DDS2
// Blueprints: 5871/5871 events recovered, 0 failures, 0 of 122,638 statements unreached, 0 bad targets).
//
// It lived inside `#if MIF_KR_DEBUG` there. Phase 2 reconstructs event bodies in ALL configurations, so the
// proven core moves HERE (ungated) and the analyzer now consumes it. There is exactly ONE implementation of
// prologue detection / entry recovery / the walk; the analyzer's measured numbers and the reconstructor's
// slices can never drift apart.
//
// -------------------------------------------------------------------------------------------------------
// THREE SPEC CLAIMS THAT ARE FALSE — this code does not inherit them (kept verbatim from the analyzer).
//
// [A] "Statement 0 is EX_ComputedJump" is FALSE. PushReturnAddress (EX_PushExecutionFlow + a 4-byte
//     placeholder = 5 bytes) is emitted BEFORE the linear execution list whenever bUseFlowStack — which is
//     true for any non-trivial merged event graph. Phase 1 measured BOTH layouts at ~50/50 (Push+ComputedJump
//     459 BPs, bare ComputedJump 404). DetectPrologue() READS the shape; it never assumes.
//
// [B] "The flow stack is empty at an event's entry offset" is FALSE, and inverts the soundness argument. The
//     stack is fresh-empty at FUNCTION entry (offset 0); execution passes THROUGH the prologue push before the
//     computed jump, so the true stack at every event entry is [ReturnAddr] when that push exists. Seeding a
//     walk with an empty stack DROPS the return address and mis-resolves every EndOfThread. Every walk here is
//     seeded with FMifPrologue::InitialStack. A latent RESUME is likewise a fresh FFrame entering at offset 0,
//     so it gets the SAME seed.
//
// [C] A shared region's EXIT EDGE IS ENTRY-DEPENDENT: the same EndOfThread pops a DIFFERENT continuation
//     depending on which event entered. Reachability is therefore keyed on (statement, event): each event gets
//     its OWN walk with its OWN stack, and pop targets are resolved inside that walk, never cached across
//     events. WalkEvent() deliberately exposes no cross-event state — a single global pop-target map would be
//     a silent-wrong-wiring bug.
// -------------------------------------------------------------------------------------------------------

#include "CoreMinimal.h"

class FJsonObject;
class FJsonValue;
class UFunction;

namespace MifUber
{
	// Bound every walk — cooked bytecode may be corrupt or adversarial; an unbounded walk on a cyclic CFG hangs
	// the editor, which is strictly worse than a stub. Mirrors ResolveFlowStackTargets' 200k.
	extern const int32 GMaxWalkIterations;
	extern const int32 GMaxJsonDepth;

	// ---------------------------------------------------------------------------------------------------
	// Statement model — the CFG-relevant projection of one top-level disassembled statement.
	// ---------------------------------------------------------------------------------------------------
	struct FUberStmt
	{
		int32   Offset = 0;             // absolute byte offset into UberFunc->Script (the disassembler's StatementIndex)
		FString Inst;

		bool  bUncondJump = false;      // Jump
		bool  bCondJump = false;        // JumpIfNot  (both edges walked)
		int32 JumpTarget = -1;

		bool  bPush = false;            // PushExecutionFlow   → push continuation
		int32 PushTarget = -1;

		bool  bPop = false;             // PopExecutionFlow    → pop + goto (KCST_EndOfThread)
		bool  bPopIfNot = false;        // PopExecutionFlowIfNot → pop+goto on !cond, fall through on cond

		bool  bComputedJump = false;    // dynamic target — NOT an intra-slice edge; terminates the path
		bool  bTerminal = false;        // Return / EndOfScript

		bool  bLatent = false;          // carries an FLatentActionInfo
		int32 LatentLinkage = -1;       // absolute resume offset, or -1
	};

	struct FPrologue
	{
		FString       Kind;             // "Push+ComputedJump" | "ComputedJump" | "Unexpected:<Inst>" | "Empty"
		TSet<int32>   Offsets;          // statements that are prologue, never part of any event slice
		TArray<int32> InitialStack;     // [B] the stack as it IS at an event entry — NOT empty when the push exists
		bool          bSane = false;
	};

	struct FWalkResult
	{
		int32 Reached = 0;
		int32 BadTargets = 0;      // a jump/push/linkage target that lands on no statement boundary
		int32 ComputedHits = 0;    // an event walk reaching a computed jump — unexpected, worth surfacing
		bool  bHitGuard = false;   // iteration cap tripped → the results are a LOWER BOUND, i.e. an INCOMPLETE slice
	};

	// Project the disassembler's JSON statement list into the CFG model + an offset→index map.
	// LatentStructPath = FLatentActionInfo::StaticStruct()->GetPathName(); UberFuncName = UberFunc->GetName()
	// (a linkage is only followed when the latent action's ExecutionFunction names THIS ubergraph).
	void BuildStatements(const TArray<TSharedPtr<FJsonValue>>& RawStmts, const FString& LatentStructPath,
		const FString& UberFuncName, TArray<FUberStmt>& OutStmts, TMap<int32, int32>& OutIndexByOffset);

	// [A] Read the prologue shape out of the disassembly. Never assume it.
	FPrologue DetectPrologue(const TArray<FUberStmt>& Stmts);

	// Walk one event's slice from EntryOffset, adding every reached statement's OFFSET to OutReached.
	// Follows: linear fall-through, Jump, JumpIfNot (both edges), PushExecutionFlow (push), PopExecutionFlow /
	// PopExecutionFlowIfNot (pop + goto), latent resume linkages (intra-slice — a resume is NOT an entry point;
	// enumerating linkages as roots would mint phantom events), and terminates on Return / EndOfScript /
	// ComputedJump. Seeded with Prologue.InitialStack [B]. Cycle-guarded on (offset, stack depth, stack top).
	//
	// [C] Own walk, own stack, own visited set, per event. Nothing is carried between calls.
	FWalkResult WalkEvent(const TArray<FUberStmt>& Stmts, const TMap<int32, int32>& IndexByOffset,
		const FPrologue& Prologue, int32 EntryOffset, TSet<int32>& OutReached);

	// ---------------------------------------------------------------------------------------------------
	// Entry recovery.
	// ---------------------------------------------------------------------------------------------------
	enum class EEventKind : uint8 { Event, BndEvt, InpActEvt, SequenceEvent };
	EEventKind ClassifyEvent(const FString& Name);
	const TCHAR* KindName(EEventKind K);

	struct FEventEntry
	{
		FString    Name;
		EEventKind Kind = EEventKind::Event;
		int32      EntryOffset = -1;
		int32      NumParams = 0;       // CPF_Parm properties on the thunk (return parm excluded)
		int32      FrameLets = 0;       // EX_LetValueOnPersistentFrame statements preceding the call
		int32      RawPtrHits = 0;      // the memcmp prefilter's hit count on this thunk
		int32      IdentityCalls = 0;   // confirmed top-level final-function calls whose target IS UberFunc
		FString    FastCall;            // "match" | "mismatch:<n>" | "n/a"
		FString    Status;              // "OK" | a failure reason
		bool       bRecovered = false;

		// §1.4 — the AUTHORITATIVE event-param map, read straight out of the thunk's own
		// EX_LetValueOnPersistentFrame statements, in thunk-parameter order:
		//   Key = the ubergraph FRAME property the event body reads
		//   Value = the thunk's parameter (i.e. the event NODE's output pin name)
		// The generated frame name is <DescriptiveCompiledName>_<PinName> uniquified with numeric postfixes —
		// NEVER reconstruct it; read it.
		TArray<TPair<FName, FName>> FrameParamMap;
	};

	// Recover an event's entry offset by DISASSEMBLING ITS THUNK — the only method that works for all event
	// shapes. Returns false and fills Out.Status on any failure (never asserts: every value out of the bytecode
	// is untrusted input). A thunk with Status=="no-ubergraph-call" is simply a real function, not a failure.
	bool RecoverEvent(UFunction* Thunk, UFunction* UberFunc, FEventEntry& Out);

	// The host's FunctionCallsIntoUbergraph is a raw byte scan for the ubergraph pointer — a SOUND PREFILTER but
	// an UNSOUND ORACLE (any 8 bytes that happen to equal the pointer match). Exposed so the gap between it and
	// the identity match is measured rather than assumed. (Phase 1: gap == 0 across all 1277 BPs.)
	int32 CountRawPointerHits(const TArray<uint8>& Script, const UFunction* UberFunc);
}
