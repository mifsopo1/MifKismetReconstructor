// Splits the flat DRIFT bucket into INTENTIONAL (a deliberate, PERMANENT shape choice we will never "fix") and REAL
// drift (the number a release gates on). Design: scratchpad spec-drift-classifier.md.
//
// CONSERVATIVE BY CONSTRUCTION. A rule must POSITIVELY CLAIM every edit between the two statement streams; anything
// unclaimed, ambiguous, or over a cap is REAL. Misfiling a real bug as INTENTIONAL re-creates the exact flattering-liar
// failure the verifier exists to prevent (it already caught a genuine silent behaviour change: SetCollisionEnabled(3)
// reconstructed as (0) — compiles clean, breaks NPC collision). So every rule keys off statement SHAPE, never a
// function-name/BP-name allowlist, and compares every value it calls "the same" byte-for-byte.
//
// CONTAINMENT. The classifier runs ONLY on the existing ++Drift path and can only ever SUBDIVIDE that bucket: it can
// never manufacture an Identical or an Equivalent. `mif.kr.ClassifyIntentional 0` disables it and restores bit-identical
// pre-classifier counts — that cvar is the audit instrument, not a convenience.
//
// INDEPENDENCE (hard rule, spec 2.6). This unit must NEVER include KismetGraphDecompiler.h nor read decompiler state
// (FlowStackPopTarget / OutParamAssignCount / ...). It re-derives everything from the disassembly of the two COMPILED
// functions. Justifying a drift with the decompiler's own conclusion would bless that conclusion including its bugs —
// the verifier marking its own homework. The flow-stack simulation in the .cpp is a DELIBERATE independent
// re-implementation of the same idea. The duplication is the point: do NOT "DRY" it against ResolveFlowStackTargets.
//
// DEGRADE SOFTLY. No assert, no hang, no crash: every cap/ambiguity/exception declines to REAL.

#pragma once

#include "CoreMinimal.h"

namespace MifKr::DriftClassify
{
	struct FVerdict
	{
		// true iff EVERY edit was positively claimed by a rule. Default false — silence is never consent.
		bool  bIntentional = false;
		// Deduped + sorted claim reasons, e.g. {"flowstack","outparam"}. Only meaningful when bIntentional.
		TArray<FString> Reasons;

		// The ROOT of a REAL drift: the first UNCLAIMED edit in cooked-ordinal order. This is deliberately NOT the
		// first raw stream difference — one extra/missing statement re-ordinalises every later jump, so the first raw
		// difference is usually a DERIVED cascade artefact (BigTabWorldMap::QuickTravelActorSelected reports
		// "@ stmt 6: Jump #31 vs #38" when the real signal is "32 vs 39 stmts"), and on a flow-stack function it is
		// the known-intentional PushExecutionFlow at stmt 0 with the actual bug buried behind it.
		// bHasRoot == false => the classifier declined; the caller must fall back to its own first-diff.
		bool  bHasRoot = false;
		int32 RootCookedOrdinal = INDEX_NONE;   // INDEX_NONE for a recon-only (Insert) edit
		int32 RootReconOrdinal  = INDEX_NONE;   // INDEX_NONE for a cooked-only (Delete) edit
		FString RootCooked;                     // canonical lossy text, or "<no counterpart>"
		FString RootRecon;
	};

	// mif.kr.ClassifyIntentional (default 1). Callers do NOT need to check this — Classify() returns a default-declined
	// verdict when off — but the batch/console reporters use it to label the run.
	bool IsEnabled();

	// Call ONLY on the drift path (the lossy streams provably differ). CookedLossy/ReconLossy are the verifier's
	// canonical LOSSY statement streams: drift is DEFINED by lossy inequality, and anything a lossy rule already folded
	// scored EQUIVALENT and never reaches here.
	FVerdict Classify(const FString& BPName, const FString& FuncName,
	                  const TArray<FString>& CookedLossy, const TArray<FString>& ReconLossy);
}
