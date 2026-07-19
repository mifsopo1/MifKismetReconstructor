// Intentional-vs-REAL drift classifier. Read MifDriftClassifier.h first — the safety contract lives there.
//
// MECHANISM (spec 2): ALIGN FIRST, THEN CLASSIFY.
//   The verifier's R3 rewrites byte offsets to statement ORDINALS. One extra/missing statement therefore
//   re-ordinalises every later jump, so `Jump Offset=#7` (cooked) and `Jump Offset=#6` (recon) differ AS STRINGS even
//   when both jump to the same logical statement. A pointwise classifier reading CookedLossy[i] vs ReconLossy[i] past
//   the first insertion is reading noise. So:
//     1. SHAPE  — the lossy stream with every code offset blanked to `Offset=#?`. An ALIGNMENT KEY ONLY; it never
//                 produces a verdict. LCS over SHAPE pairs (Jump Offset=#?) with (Jump Offset=#?) across a cascade
//                 instead of substituting every post-root jump.
//     2. SLOTS  — every Match(i,j) gives both sides the same fresh SlotId; every Delete/Insert gets a private one.
//                 `Offset=#N` then resolves to `Offset=@Slot(side,N)`. Two matched statements' offsets agree IFF they
//                 resolve to the same slot, so a ±1 wholly explained by an edit elsewhere is DERIVED — attributed to
//                 that root edit, never counted or reported on its own.
//     3. EDITS  — Delete(i), Insert(j), and Match(i,j) whose slot-resolved text still differs. Nothing else can appear:
//                 SHAPE equality already forced every non-offset field equal.
//     4. RULES  — each must positively CLAIM an edit. Every edit claimed => INTENTIONAL. Otherwise REAL, and the root
//                 is the first UNCLAIMED edit in cooked order. A function with one intentional drift AND one real bug
//                 is REAL, and FirstDrift names the BUG.
//
// SOUNDNESS OF SLOT EQUALITY: a slot is shared only by a Match, and a Match requires BYTE-EQUAL SHAPE strings — i.e.
// two statements identical in everything except code offsets. That is strictly finer than the raw-ordinal comparison
// it replaces (which asserts nothing about the target at all). Residual risk: LCS maximises matches, so a mis-alignment
// could in principle pair the wrong two identical-shaped statements and let two genuinely different jump targets share
// a slot. Bounded by (i) mis-alignment generally yields MORE edits, and more edits means more chances to fail the claim
// gauntlet — the conservative direction; (ii) the verdict is never "the alignment says so": every edit must still be
// positively claimed by a rule that re-verifies expressions byte-for-byte.
//
// DEVIATION FROM THE SPEC (deliberate, equivalent, cheaper): spec 2.1 threads a THIRD emission through the verifier's
// Normalize() to produce SHAPE. We derive SHAPE textually from the lossy string instead (ShapeOf, below). The only
// difference between the LOSSY and SHAPE emissions is EmitValue's IsCodeOffsetField branch, and that branch is the
// sole producer of the `Offset=#` token — so the textual fold is byte-identical to the third pass, costs nothing on
// the 1235 non-drifting functions, and keeps MifFidelityVerifier.cpp's Normalize() untouched.

#include "MifDriftClassifier.h"

#include "MifReconstructorDebug.h"

#include "HAL/FileManager.h"
#include "HAL/IConsoleManager.h"
#include "HAL/CriticalSection.h"
#include "Misc/DateTime.h"
#include "Misc/Paths.h"
#include "Misc/ScopeLock.h"
#include "Serialization/Archive.h"   // FArchive::Serialize/Flush on the census file writer

namespace MifKr::DriftClassify
{
	// ---------------------------------------------------------------------------------------------------------------
	// cvars
	// ---------------------------------------------------------------------------------------------------------------

	// MANDATORY kill switch (spec 1.3). 0 => the classifier never runs, Intentional stays 0, every drift stays Drift,
	// and the published numbers are bit-identical to the pre-classifier build. This is the audit instrument for the
	// containment invariant (spec 6.1: Drift_off == Intentional_on + Drift_on) and the escape hatch if a rule is ever
	// found unsound.
	static TAutoConsoleVariable<int32> CVarClassifyIntentional(
		TEXT("mif.kr.ClassifyIntentional"),
		1,
		TEXT("1 = split the DRIFT bucket into INTENTIONAL (proven deliberate shape choices) + REAL drift.\n")
		TEXT("0 = classifier never runs; output is bit-identical to the pre-classifier build (audit baseline)."),
		ECVF_Default);

	// Spec 4 — rules must be written FROM DATA, not guessed. With this on, every UNCLAIMED edit is dumped so the
	// shape-signature histogram can say which drift classes actually dominate, and whether each is intentional or a bug.
	static TAutoConsoleVariable<int32> CVarDriftCensus(
		TEXT("mif.kr.DriftCensus"),
		0,
		TEXT("1 = append every UNCLAIMED drift edit to <ProjectSaved>/MifKr/DriftCensus_<ts>.csv (rule discovery).\n")
		TEXT("Diagnostic only — it never changes a verdict."),
		ECVF_Default);

	bool IsEnabled() { return CVarClassifyIntentional.GetValueOnAnyThread() != 0; }

	// ---------------------------------------------------------------------------------------------------------------
	// caps — every one of them declines to REAL, never asserts
	// ---------------------------------------------------------------------------------------------------------------

	// The LCS table is O(N*M). Measured corpus statement counts are far below this; the cap exists so a pathological BP
	// cannot stall the editor. A decompiler that hangs the editor is worse than one that emits a stub.
	static constexpr int32 GMaxStatements   = 2000;
	static constexpr int64 GMaxLcsCells     = 4200000;   // (2000+1)^2, ~16MB of int32 — transient, drift path only
	static constexpr int32 GSimIterationCap = 200000;

	// ---------------------------------------------------------------------------------------------------------------
	// canonical-string surgery
	//
	// The rules operate on the verifier's canonical statement strings, which have an exact, mechanical grammar:
	//   "(" Inst " " (Key "=" Value " ")* ")"    with sub-expressions parenthesised recursively and KEYS SORTED.
	// Everything below is EXACT prefix/suffix/token surgery — never a nested-paren parse. That is deliberate: a value
	// can legitimately contain "(" or "'" (a text literal's SourceString, an apostrophe in a display name), so a
	// depth-tracking parser would be silently wrong on exactly the statements it must not be wrong on. Anchoring on
	// tokens whose position is forced by the sorted-key emission has no such failure mode.
	// ---------------------------------------------------------------------------------------------------------------

	static FString TopInst(const FString& S)
	{
		if (S.Len() < 2 || S[0] != TEXT('(')) { return FString(); }
		int32 i = 1;
		while (i < S.Len() && S[i] != TEXT(' ') && S[i] != TEXT(')')) { ++i; }
		return S.Mid(1, i - 1);
	}

	// Walk every R3 code-offset token in a canonical string. `Fn(Ordinal, RawToken) -> FString` supplies the
	// replacement. Ordinal is INDEX_NONE for the `Offset=#unaligned(<n>)` form (R3 surfaces an off-boundary jump target
	// rather than dropping it — it means the jump lands mid-statement, which is a REAL signal).
	template <typename FnT>
	static FString RewriteOffsets(const FString& S, FnT&& Fn)
	{
		static const FString Tok = TEXT("Offset=#");
		FString Out;
		int32 From = 0;
		for (;;)
		{
			const int32 At = S.Find(Tok, ESearchCase::CaseSensitive, ESearchDir::FromStart, From);
			if (At == INDEX_NONE) { Out += S.Mid(From); break; }
			Out += S.Mid(From, At - From);

			int32 P = At + Tok.Len();
			const int32 DigitsStart = P;
			while (P < S.Len() && FChar::IsDigit(S[P])) { ++P; }
			if (P > DigitsStart)
			{
				Out += Fn(FCString::Atoi(*S.Mid(DigitsStart, P - DigitsStart)), S.Mid(At, P - At));
			}
			else
			{
				// "unaligned(<n>)" — no ordinal to resolve.
				int32 Q = P;
				while (Q < S.Len() && S[Q] != TEXT(')')) { ++Q; }
				if (Q < S.Len()) { ++Q; }
				Out += Fn(INDEX_NONE, S.Mid(At, Q - At));
				P = Q;
			}
			From = P;
		}
		return Out;
	}

	// SHAPE — alignment key only, never a verdict (see the file header for why this is not a third emission pass).
	static FString ShapeOf(const FString& Lossy)
	{
		return RewriteOffsets(Lossy, [](int32, const FString&) { return FString(TEXT("Offset=#?")); });
	}

	// Resolve ordinals through the alignment. An unresolvable offset (unaligned / out of range) is kept VERBATIM, so it
	// can only ever MISMATCH — it is never folded into agreement. Conservative direction by construction.
	static FString ResolveOffsets(const FString& Lossy, const TArray<int32>& SlotOf)
	{
		return RewriteOffsets(Lossy, [&SlotOf](int32 Ord, const FString& Raw) -> FString
		{
			if (Ord != INDEX_NONE && SlotOf.IsValidIndex(Ord) && SlotOf[Ord] != INDEX_NONE)
			{
				return FString::Printf(TEXT("Offset=@%d"), SlotOf[Ord]);
			}
			return Raw;
		});
	}

	// The ONE code offset a flow/jump statement carries. >1 (a nested opcode that also writes an Offset) or an
	// unaligned target => we cannot account for the edge => the caller declines. Never a guess.
	static bool TryTopOffset(const FString& Lossy, int32& Out)
	{
		int32 Count = 0;
		int32 Found = INDEX_NONE;
		RewriteOffsets(Lossy, [&Count, &Found](int32 Ord, const FString& Raw) -> FString
		{
			++Count; Found = Ord; return Raw;
		});
		if (Count != 1 || Found == INDEX_NONE) { return false; }
		Out = Found;
		return true;
	}

	// FString::IsNumeric accepts '+', '-' and '.', which would make "%L1.5" parse. The alpha-rename only ever emits
	// digits, so anything else means we are not looking at what we think we are => decline.
	static bool IsAllDigits(const FString& S)
	{
		if (S.IsEmpty()) { return false; }
		for (const TCHAR C : S) { if (!FChar::IsDigit(C)) { return false; } }
		return true;
	}

	static int32 CountOccurrences(const FString& Hay, const FString& Needle)
	{
		if (Needle.IsEmpty()) { return 0; }
		int32 N = 0, From = 0;
		for (;;)
		{
			const int32 At = Hay.Find(Needle, ESearchCase::CaseSensitive, ESearchDir::FromStart, From);
			if (At == INDEX_NONE) { break; }
			++N; From = At + Needle.Len();
		}
		return N;
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Independent flow-stack simulation  (spec 2.6 — a DELIBERATE re-implementation; do NOT DRY against the decompiler)
	//
	// Verified against the VM itself (CoreUObject/Private/UObject/ScriptCore.cpp):
	//   execPushExecutionFlow  (:2595) pushes a code offset, falls through.
	//   execPopExecutionFlow   (:2603) pops+gotos; an EMPTY stack logs "Tried to pop from an empty flow stack" and
	//                                   falls through — degenerate, so we decline rather than model it.
	//   execPopExecutionFlowIfNot (:2622) pops+gotos on !cond, falls through on cond.
	// ---------------------------------------------------------------------------------------------------------------

	struct FSim
	{
		bool bOk = false;                        // false => declined; the caller must claim nothing
		bool bExitReachable = false;             // an EXIT (Return opcode OR fall-off-end) was reached (D6)
		TSet<int32> Reachable;
		TMap<int32, int32> PopTop;               // pop ordinal -> its ONE target ordinal (A1: else we decline)
		TMap<int32, TSet<int32>> PushPoppedBy;   // push ordinal -> the pops that pop it
	};

	// A1 — a pop whose stack top is PATH-DEPENDENT is never claimable. (Note the decompiler's own walk simply
	// overwrites its FlowStackPopTarget entry on a second visit; blessing that silently is precisely what this
	// independent sim exists to refuse.)
	static bool RecordPop(FSim& R, int32 PopIdx, const TPair<int32, int32>& Top)
	{
		if (const int32* Prev = R.PopTop.Find(PopIdx))
		{
			if (*Prev != Top.Key) { return false; }
		}
		else
		{
			R.PopTop.Add(PopIdx, Top.Key);
		}
		R.PushPoppedBy.FindOrAdd(Top.Value).Add(PopIdx);
		return true;
	}

	// DFS from statement 0 maintaining a stack of (target ordinal, push ordinal). Visited key (index, depth, top).
	// Barrier != INDEX_NONE cuts that statement out of the CFG entirely (rule D6's post-dominance test).
	static FSim Simulate(const TArray<FString>& S, int32 Barrier)
	{
		FSim R;
		if (S.Num() == 0) { return R; }

		TArray<FString> Inst;
		Inst.Reserve(S.Num());
		for (const FString& X : S) { Inst.Add(TopInst(X)); }

		using FStack = TArray<TPair<int32, int32>>;

		// EXACT visited key over the FULL stack (index + every (target,push) level), so no two genuinely different
		// states ever collapse. The earlier key folded only (index, depth, top): at depth >= 2 two states whose DEEPER
		// levels differ by path shared a key, one path was pruned, and a later pop of that deeper level escaped
		// RecordPop's A1 path-dependence guard — the one way this sim could emit a false-INTENTIONAL. With the whole
		// stack in the key every distinct state is explored, so A1 sees every genuinely-distinct pop context and nested
		// push/pop (depth > 1) is claimable AND sound. Keys are strings (exact, collision-free, unlike a hash); this
		// runs on the drift path only and stays bounded by GSimIterationCap, which declines any pathological blow-up.
		auto MakeKey = [](int32 Index, const FStack& St) -> FString
		{
			FString K = FString::FromInt(Index);
			for (const TPair<int32, int32>& E : St) { K += FString::Printf(TEXT("|%d,%d"), E.Key, E.Value); }
			return K;
		};
		TSet<FString> Visited;
		TArray<TPair<int32, FStack>> Work;
		Work.Add(TPair<int32, FStack>(0, FStack()));

		int32 Guard = 0;
		while (Work.Num() > 0)
		{
			TPair<int32, FStack> Item = Work.Pop(false);
			int32 i = Item.Key;
			FStack Stack = MoveTemp(Item.Value);

			for (;;)
			{
				// Falling off the end of the stream is an IMPLICIT return — an EXIT, exactly like a Return
				// statement. D6's post-dominance hinges on catching this: a branch that jumps past the copy to
				// the end returns WITHOUT writing the out-param; looking only for a (Return) opcode would miss it
				// and wrongly claim the drift. This is the dangerous defect D6 exists to stop.
				if (!S.IsValidIndex(i)) { R.bExitReachable = true; break; }
				if (i == Barrier) { break; }                    // cut out of the CFG (not an exit)
				if (++Guard > GSimIterationCap) { return R; }   // bOk stays false => decline

				const FString Key = MakeKey(i, Stack);
				if (Visited.Contains(Key)) { break; }
				Visited.Add(Key);
				R.Reachable.Add(i);

				const FString& T = Inst[i];
				if (T == TEXT("PushExecutionFlow"))
				{
					int32 Tgt = INDEX_NONE;
					if (!TryTopOffset(S[i], Tgt)) { return R; }
					Stack.Add(TPair<int32, int32>(Tgt, i));
					++i; continue;
				}
				if (T == TEXT("PopExecutionFlow"))
				{
					if (Stack.Num() == 0) { return R; }         // VM error path — degenerate, never claim it
					const TPair<int32, int32> Top = Stack.Pop(false);
					if (!RecordPop(R, i, Top)) { return R; }
					i = Top.Key; continue;
				}
				if (T == TEXT("PopExecutionFlowIfNot"))
				{
					if (Stack.Num() == 0) { return R; }
					const TPair<int32, int32> Top = Stack.Last();
					if (!RecordPop(R, i, Top)) { return R; }
					FStack Popped = Stack;
					Popped.Pop(false);
					Work.Add(TPair<int32, FStack>(Top.Key, MoveTemp(Popped)));   // !cond: pop + goto
					++i; continue;                                               // cond: fall through
				}
				if (T == TEXT("Jump"))
				{
					int32 Tgt = INDEX_NONE;
					if (!TryTopOffset(S[i], Tgt)) { return R; }
					i = Tgt; continue;
				}
				if (T == TEXT("JumpIfNot"))
				{
					int32 Tgt = INDEX_NONE;
					if (!TryTopOffset(S[i], Tgt)) { return R; }
					Work.Add(TPair<int32, FStack>(Tgt, Stack));                  // !cond branch
					++i; continue;                                               // cond: fall through
				}
				if (T == TEXT("Return")) { R.bExitReachable = true; break; }

				// EX_ComputedJump's target is DYNAMIC (event dispatch reads it from a parameter) and EX_AutoRtfmTransact
				// carries its own code offset. Neither has a static edge to follow, so the stack past them is
				// unknowable — decline the whole function rather than walk on with a wrong stack.
				if (T == TEXT("ComputedJump") || T == TEXT("AutoRtfmTransact")) { return R; }
				++i;
			}
		}
		// A completed walk under the cap is provably sound now that the visited key is EXACT over the full stack
		// (see MakeKey): no distinct state is pruned, so every path-dependent pop is caught by RecordPop's A1 guard.
		// A cap hit or an unfollowable edge already did `return R` with bOk=false (decline). Nested push/pop is now
		// claimable — both Rule A and Rule D6 get a sound answer at any depth instead of a wholesale depth>1 decline.
		R.bOk = true;
		return R;
	}

	// ---------------------------------------------------------------------------------------------------------------
	// census (spec 4) — diagnostic only, never touches a verdict
	// ---------------------------------------------------------------------------------------------------------------

	static FCriticalSection GCensusLock;
	static TUniquePtr<FArchive> GCensusFile;

	static FString CensusCell(const FString& S)
	{
		return S.Replace(TEXT(","), TEXT(";")).Replace(TEXT("\n"), TEXT(" ")).Replace(TEXT("\r"), TEXT(" "));
	}

	static void CensusWrite(const FString& Row)
	{
		FScopeLock Lock(&GCensusLock);
		if (!GCensusFile)
		{
			const FString Dir = FPaths::ProjectSavedDir() / TEXT("MifKr");
			IFileManager::Get().MakeDirectory(*Dir, /*Tree*/ true);
			const FString Path = Dir / FString::Printf(TEXT("DriftCensus_%s.csv"), *FDateTime::Now().ToString(TEXT("%Y%m%d_%H%M%S")));
			GCensusFile.Reset(IFileManager::Get().CreateFileWriter(*Path, FILEWRITE_AllowRead));
			if (!GCensusFile) { return; }
			UE_LOG(LogMifKismetReconstructor, Display, TEXT("[census] drift census -> %s"), *Path);
			const FString Hdr = TEXT("Blueprint,Function,EditKind,CookedOrdinal,ReconOrdinal,CookedShape,ReconShape,CookedLossy,ReconLossy") LINE_TERMINATOR;
			FTCHARToUTF8 H(*Hdr);
			GCensusFile->Serialize((void*)H.Get(), H.Length());
		}
		const FString L = Row + LINE_TERMINATOR;
		FTCHARToUTF8 Conv(*L);
		GCensusFile->Serialize((void*)Conv.Get(), Conv.Length());
		GCensusFile->Flush();   // per row: a hard crash must preserve partial results (mirrors the batch CSV)
	}

	// ---------------------------------------------------------------------------------------------------------------
	// the classifier
	// ---------------------------------------------------------------------------------------------------------------

	enum class EOp : uint8 { Match, Del, Ins };
	struct FOp { EOp K; int32 C; int32 R; };

	enum class EEdit : uint8 { Del, Ins, OffsetMismatch };
	struct FEdit
	{
		EEdit K = EEdit::Del;
		int32 C = INDEX_NONE;
		int32 R = INDEX_NONE;
		int32 Hunk = INDEX_NONE;    // maximal run of Del/Ins between two Matches; OffsetMismatch belongs to none
		bool bClaimed = false;
		FString Reason;
	};

	static const TCHAR* EditKindName(EEdit K)
	{
		switch (K)
		{
		case EEdit::Del: return TEXT("Delete");
		case EEdit::Ins: return TEXT("Insert");
		default:         return TEXT("OffsetMismatch");
		}
	}

	FVerdict Classify(const FString& BPName, const FString& FuncName,
	                  const TArray<FString>& CookedLossy, const TArray<FString>& ReconLossy)
	{
		FVerdict V;
		if (!IsEnabled()) { return V; }   // kill switch: declined verdict => the caller keeps today's exact output

		const int32 N = CookedLossy.Num();
		const int32 M = ReconLossy.Num();
		if (N > GMaxStatements || M > GMaxStatements)
		{
#if MIF_KR_DEBUG
			UE_LOG(LogMifKismetReconstructor, Verbose, TEXT("[classify] %s::%s declined: %d/%d statements over the %d cap"),
				*BPName, *FuncName, N, M, GMaxStatements);
#endif
			return V;
		}

		// --- 1. SHAPE + intern ------------------------------------------------------------------------------------
		TMap<FString, int32> Ids;
		TArray<int32> A, B;
		A.Reserve(N); B.Reserve(M);
		auto Intern = [&Ids](const FString& S) -> int32
		{
			if (const int32* P = Ids.Find(S)) { return *P; }
			const int32 Id = Ids.Num();
			Ids.Add(S, Id);
			return Id;
		};
		for (const FString& S : CookedLossy) { A.Add(Intern(ShapeOf(S))); }
		for (const FString& S : ReconLossy)  { B.Add(Intern(ShapeOf(S))); }

		// --- 2. alignment: deterministic LCS over SHAPE ------------------------------------------------------------
		// Common prefix/suffix are trimmed first — cheap, deterministic, and it keeps the DP tiny in practice.
		int32 Pre = 0;
		while (Pre < N && Pre < M && A[Pre] == B[Pre]) { ++Pre; }
		int32 Suf = 0;
		while (Suf < (N - Pre) && Suf < (M - Pre) && A[N - 1 - Suf] == B[M - 1 - Suf]) { ++Suf; }
		const int32 n = N - Pre - Suf;
		const int32 m = M - Pre - Suf;

		if ((int64)(n + 1) * (int64)(m + 1) > GMaxLcsCells)
		{
#if MIF_KR_DEBUG
			UE_LOG(LogMifKismetReconstructor, Verbose, TEXT("[classify] %s::%s declined: LCS table %dx%d over cap"), *BPName, *FuncName, n, m);
#endif
			return V;
		}

		TArray<FOp> Ops;
		Ops.Reserve(N + M);
		for (int32 k = 0; k < Pre; ++k) { Ops.Add(FOp{ EOp::Match, k, k }); }
		{
			// Dp[i][j] = LCS length of A[Pre+i .. Pre+n) and B[Pre+j .. Pre+m).
			TArray<int32> Dp;
			Dp.SetNumZeroed((n + 1) * (m + 1));
			for (int32 i = n - 1; i >= 0; --i)
			{
				for (int32 j = m - 1; j >= 0; --j)
				{
					Dp[i * (m + 1) + j] = (A[Pre + i] == B[Pre + j])
						? Dp[(i + 1) * (m + 1) + (j + 1)] + 1
						: FMath::Max(Dp[(i + 1) * (m + 1) + j], Dp[i * (m + 1) + (j + 1)]);
				}
			}
			int32 i = 0, j = 0;
			while (i < n || j < m)
			{
				if (i < n && j < m && A[Pre + i] == B[Pre + j])
				{
					Ops.Add(FOp{ EOp::Match, Pre + i, Pre + j }); ++i; ++j;
				}
				else if (j < m && (i == n || Dp[i * (m + 1) + (j + 1)] >= Dp[(i + 1) * (m + 1) + j]))
				{
					Ops.Add(FOp{ EOp::Ins, INDEX_NONE, Pre + j }); ++j;   // fixed tie-break => deterministic alignment
				}
				else
				{
					Ops.Add(FOp{ EOp::Del, Pre + i, INDEX_NONE }); ++i;
				}
			}
		}
		for (int32 k = 0; k < Suf; ++k) { Ops.Add(FOp{ EOp::Match, N - Suf + k, M - Suf + k }); }

		// --- 3. slots ---------------------------------------------------------------------------------------------
		TArray<int32> SlotC, SlotR;
		SlotC.Init(INDEX_NONE, N + 1);
		SlotR.Init(INDEX_NONE, M + 1);
		int32 NextSlot = 0;
		for (const FOp& O : Ops)
		{
			if (O.K == EOp::Match)      { const int32 s = NextSlot++; SlotC[O.C] = s; SlotR[O.R] = s; }
			else if (O.K == EOp::Del)   { SlotC[O.C] = NextSlot++; }
			else                        { SlotR[O.R] = NextSlot++; }
		}
		// END sentinel. R3's backward walk resolves a jump past the last statement to ordinal Num() — "fall out of the
		// function", which is the SAME logical place on both sides, so both get the same slot.
		const int32 EndSlot = NextSlot++;
		SlotC[N] = EndSlot;
		SlotR[M] = EndSlot;

		TArray<FString> RC, RR;
		RC.Reserve(N); RR.Reserve(M);
		for (const FString& S : CookedLossy) { RC.Add(ResolveOffsets(S, SlotC)); }
		for (const FString& S : ReconLossy)  { RR.Add(ResolveOffsets(S, SlotR)); }

		// --- 4. edit list -----------------------------------------------------------------------------------------
		TArray<FEdit> Edits;
		TMap<int32, int32> HunkNextSlot;   // hunk -> slot of the statement exec falls into after it (A4 fall-through)
		{
			int32 Hunk = 0;
			bool bInHunk = false;
			for (const FOp& O : Ops)
			{
				if (O.K == EOp::Match)
				{
					if (bInHunk) { HunkNextSlot.Add(Hunk, SlotC[O.C]); ++Hunk; bInHunk = false; }
					// The ONLY thing SHAPE equality left free is the code offsets, so this is the whole of case (3).
					if (RC[O.C] != RR[O.R])
					{
						FEdit E; E.K = EEdit::OffsetMismatch; E.C = O.C; E.R = O.R;
						Edits.Add(MoveTemp(E));
					}
				}
				else
				{
					bInHunk = true;
					FEdit E; E.K = (O.K == EOp::Del) ? EEdit::Del : EEdit::Ins; E.C = O.C; E.R = O.R; E.Hunk = Hunk;
					Edits.Add(MoveTemp(E));
				}
			}
			if (bInHunk) { HunkNextSlot.Add(Hunk, EndSlot); }
		}

		if (Edits.Num() == 0)
		{
			// Unreachable by construction (the lossy streams differ, and with no Del/Ins the slots are 1:1 in order, so
			// some Match must resolve-mismatch). Defensive: log and stay REAL, never claim.
			UE_LOG(LogMifKismetReconstructor, Warning,
				TEXT("[classify] %s::%s: lossy streams differ but the alignment produced no edits — REAL (defensive)."),
				*BPName, *FuncName);
			return V;
		}

		// --- 5. RULE A — flowstack --------------------------------------------------------------------------------
		// Cooked: PushExecutionFlow Offset=#T ... PopExecutionFlow (pop+goto T).
		// Recon:  the decompiler wires exec STRAIGHT to T, so the recompiled bytecode has a direct Jump to T (or nothing
		//         at all, when T is simply where exec already falls through) and NO push. Deliberate and permanent.
		//
		// WHY IT CANNOT SWALLOW A GENUINE DEFECT:
		//  * It matches ONLY the three literal flow opcodes on the cooked side. It is NOT a statement-count rule: a
		//    missing/extra CallFunction, Let, Jump — anything else — is invisible to it and stays REAL.
		//  * A WRONG REWIRE is the defect it could plausibly hide, and the SLOT check is aimed straight at it: the
		//    inserted jump must land on the same SLOT as the push target. Wire exec to the wrong statement and the
		//    slots differ => unclaimed => REAL.
		//  * A5 compares the condition BYTE-FOR-BYTE and requires JumpIfNot (never Jump), so a mangled or inverted
		//    branch can never be claimed.
		//  * A non-deterministic stack declines wholesale (A1). We never guess.
		//  * A6 (no leftover Insert in a claimed hunk) needs no separate check: an unclaimed Insert already forces REAL
		//    via the composition rule below — same outcome, one less way to be wrong.
		{
			bool bAnyFlowDelete = false;
			for (const FEdit& E : Edits)
			{
				if (E.K != EEdit::Del) { continue; }
				const FString T = TopInst(CookedLossy[E.C]);
				// A2 — no other opcode is touchable by this rule.
				if (T == TEXT("PushExecutionFlow") || T == TEXT("PopExecutionFlow") || T == TEXT("PopExecutionFlowIfNot"))
				{
					bAnyFlowDelete = true; break;
				}
			}
			if (bAnyFlowDelete)
			{
				const FSim Sim = Simulate(CookedLossy, INDEX_NONE);
				if (Sim.bOk)
				{
					// pass 1 — pops (A4 / A5). Claim each pop together with its counterpart Insert in the SAME hunk.
					TSet<int32> ClaimedPops;
					for (int32 e = 0; e < Edits.Num(); ++e)
					{
						if (Edits[e].K != EEdit::Del || Edits[e].bClaimed) { continue; }
						const int32 Ci = Edits[e].C;
						const FString T = TopInst(CookedLossy[Ci]);
						const bool bPop  = (T == TEXT("PopExecutionFlow"));
						const bool bPopN = (T == TEXT("PopExecutionFlowIfNot"));
						if (!bPop && !bPopN) { continue; }

						// A1 — no recorded top means the pop is unreachable or path-dependent: cannot account => REAL.
						const int32* Tgt = Sim.PopTop.Find(Ci);
						if (!Tgt || !SlotC.IsValidIndex(*Tgt) || SlotC[*Tgt] == INDEX_NONE) { continue; }
						const int32 S = SlotC[*Tgt];

						FString Want;
						if (bPop)
						{
							Want = FString::Printf(TEXT("(Jump Offset=@%d )"), S);
						}
						else
						{
							// PopExecutionFlowIfNot's only field is Condition; JumpIfNot's are Condition + Offset, and
							// keys are emitted SORTED, so the expected recon statement is exactly the cooked condition
							// re-headed as a JumpIfNot with the slot-resolved target appended.
							static const FString Px = TEXT("(PopExecutionFlowIfNot ");
							const FString& C = RC[Ci];
							if (!C.StartsWith(Px, ESearchCase::CaseSensitive) || !C.EndsWith(TEXT(")"), ESearchCase::CaseSensitive)) { continue; }
							const FString Inner = C.Mid(Px.Len(), C.Len() - Px.Len() - 1);   // "Condition=(...) "
							Want = TEXT("(JumpIfNot ") + Inner + FString::Printf(TEXT("Offset=@%d )"), S);
						}

						int32 Counterpart = INDEX_NONE;
						for (int32 f = 0; f < Edits.Num(); ++f)
						{
							if (Edits[f].K == EEdit::Ins && !Edits[f].bClaimed
								&& Edits[f].Hunk == Edits[e].Hunk && RR[Edits[f].R] == Want)
							{
								Counterpart = f; break;
							}
						}
						if (Counterpart != INDEX_NONE)
						{
							Edits[Counterpart].bClaimed = true; Edits[Counterpart].Reason = TEXT("flowstack");
							Edits[e].bClaimed = true;           Edits[e].Reason = TEXT("flowstack");
							ClaimedPops.Add(Ci);
							continue;
						}
						// A4 only: no counterpart Jump is correct IFF the push target is where exec falls through
						// anyway ("goto next" == fall through). A5 has no such variant — a conditional branch must be
						// present as a JumpIfNot or it is not claimable.
						if (bPop)
						{
							const int32* NextS = HunkNextSlot.Find(Edits[e].Hunk);
							if (NextS && *NextS == S)
							{
								Edits[e].bClaimed = true; Edits[e].Reason = TEXT("flowstack");
								ClaimedPops.Add(Ci);
							}
						}
					}

					// pass 2 — pushes (A3). A push is claimable only once EVERY pop that pops it is itself claimed.
					for (FEdit& Ed : Edits)
					{
						if (Ed.K != EEdit::Del || Ed.bClaimed) { continue; }
						if (TopInst(CookedLossy[Ed.C]) != TEXT("PushExecutionFlow")) { continue; }
						if (!Sim.Reachable.Contains(Ed.C)) { continue; }   // cannot account for it => REAL
						const TSet<int32>* Pops = Sim.PushPoppedBy.Find(Ed.C);
						bool bAll = true;
						if (Pops)
						{
							for (const int32 P : *Pops) { if (!ClaimedPops.Contains(P)) { bAll = false; break; } }
						}
						// No pops at all => the simulation shows the push is never popped on any reachable path: dead.
						if (bAll) { Ed.bClaimed = true; Ed.Reason = TEXT("flowstack"); }
					}
				}
#if MIF_KR_DEBUG
				else
				{
					UE_LOG(LogMifKismetReconstructor, Verbose,
						TEXT("[classify] %s::%s: rule A declined (cooked flow simulation is not deterministic)"), *BPName, *FuncName);
				}
#endif
			}
		}

		// --- 6. RULE D — outparam ---------------------------------------------------------------------------------
		// An out-param assigned EXACTLY ONCE collapses to a direct Result-pin link and recompiles byte-for-byte.
		// Assigned 2+ times, the reconstruction keeps a real synthesized local written at each site and copied into the
		// out-param once. That copy is one extra statement — permanent, and CORRECT: collapsing it would lose the value
		// on some branch. The local exists for branch CORRECTNESS, so this drift must never be "fixed".
		//
		// WHY IT CANNOT SWALLOW A GENUINE DEFECT:
		//  * Every write's RHS must be BYTE-IDENTICAL (D3 is exact prefix/suffix surgery — only the variable
		//    sub-expression's head may differ), so a wrong value stays REAL.
		//  * ONE shared temp across all sites, written k times and read exactly once (D5) — a crossed-wires temp stays REAL.
		//  * D6 catches the dangerous failure: if the copy is missing on a branch, a Return is reachable without it and
		//    the out-param is left unwritten. That is a REAL defect and D6 is what stops this rule excusing it.
		//  * D2 refuses ANY read of the out-param, killing the read-before-write hazard class outright: an out-param is
		//    caller-allocated, so a read before the first write yields the CALLER's value where the recon local yields
		//    its default. Not equivalent, and no shape match makes it so.
		//  * D1 refuses k==1 UNCONDITIONALLY — that case is exactly what the single-assign collapse claims to make
		//    byte-identical, so a k==1 drift is a BUG IN THE COLLAPSE. This rule deliberately refuses to cover the case
		//    its own feature owns.
		{
			// A cooked out-param WRITE site: "(<Let*> Expression=<E> Variable=(LocalOutVariable VariableName='P' VariableType=<T> ) )".
			// Keys are emitted SORTED, so Variable is the LAST field of a Let — which is what makes the exact
			// prefix/suffix split below unambiguous without ever parsing nested parens.
			// Out-params carry CPF_Parm, so R6 never alpha-renames them: they compare literally.
			auto SplitWrite = [](const FString& S, FString& OutName, FString& OutPre, FString& OutPost) -> bool
			{
				if (!TopInst(S).StartsWith(TEXT("Let"), ESearchCase::CaseSensitive)) { return false; }
				static const FString Tok = TEXT("(LocalOutVariable VariableName='");
				const int32 At = S.Find(Tok, ESearchCase::CaseSensitive);
				if (At == INDEX_NONE) { return false; }
				if (S.Find(Tok, ESearchCase::CaseSensitive, ESearchDir::FromStart, At + 1) != INDEX_NONE) { return false; }
				const int32 NameStart = At + Tok.Len();
				const int32 Quote = S.Find(TEXT("'"), ESearchCase::CaseSensitive, ESearchDir::FromStart, NameStart);
				if (Quote == INDEX_NONE || Quote == NameStart) { return false; }
				if (Quote + 1 >= S.Len() || S[Quote + 1] != TEXT(' ')) { return false; }
				OutName = S.Mid(NameStart, Quote - NameStart);
				OutPre  = S.Left(At);              // "(Let Expression=<E> Variable="
				OutPost = S.Mid(Quote + 2);        // "VariableType=<T> ) )"
				return OutPre.EndsWith(TEXT("Variable="), ESearchCase::CaseSensitive)
					&& OutPost.EndsWith(TEXT(" )"), ESearchCase::CaseSensitive);
			};

			// Everything below reads the SLOT-RESOLVED streams (RC/RR), so any code offset inside a claimed statement is
			// compared through the alignment exactly like every other edit — never as a raw ordinal.
			//
			// Candidates: every out-param name written by a cooked statement the alignment DELETED.
			TSet<FString> Names;
			for (const FEdit& E : Edits)
			{
				if (E.K != EEdit::Del) { continue; }
				FString P, Pre2, Post2;
				if (SplitWrite(RC[E.C], P, Pre2, Post2)) { Names.Add(P); }
			}

			for (const FString& P : Names)
			{
				// D1 — every cooked write site for P, across the WHOLE stream.
				TArray<int32> Writes;
				FString Inst0, TypeStr;
				bool bShapeOk = true;
				for (int32 i = 0; i < N; ++i)
				{
					FString Name, Pre2, Post2;
					if (!SplitWrite(RC[i], Name, Pre2, Post2) || Name != P) { continue; }
					const FString ThisInst = TopInst(RC[i]);
					// Post2 is "VariableType=<T> ) )"; drop the Let's trailing " )" → "VariableType=<T> )", the exact
					// tail a LocalVariable / LocalOutVariable sub-expression ends with (its own closing paren kept).
					const FString ThisType = Post2.LeftChop(2);
					if (Writes.Num() == 0) { Inst0 = ThisInst; TypeStr = ThisType; }
					else if (ThisInst != Inst0 || ThisType != TypeStr) { bShapeOk = false; break; }
					Writes.Add(i);
				}
				if (!bShapeOk || Writes.Num() < 2) { continue; }   // k==0/1 => decline (see D1)

				// D2 — ZERO reads: every mention of P anywhere in the cooked stream must be one of the k write sites
				// (each write site is guaranteed by SplitWrite to contain exactly one).
				const FString Mention = FString::Printf(TEXT("(LocalOutVariable VariableName='%s' "), *P);
				int32 Mentions = 0;
				for (const FString& S : RC) { Mentions += CountOccurrences(S, Mention); }
				if (Mentions != Writes.Num()) { continue; }

				// Every write site must be a DELETE with a counterpart INSERT in the same hunk. A write site the
				// alignment MATCHED means recon still writes the out-param there — a mixed shape we will not guess at.
				TMap<int32, int32> WriteEdit;   // cooked ordinal -> edit index
				for (int32 e = 0; e < Edits.Num(); ++e)
				{
					if (Edits[e].K == EEdit::Del && Writes.Contains(Edits[e].C)) { WriteEdit.Add(Edits[e].C, e); }
				}
				if (WriteEdit.Num() != Writes.Num()) { continue; }

				// D3 — the recon write is the cooked write with the out-param swapped for ONE shared local, and
				// EVERYTHING else byte-identical. Exact prefix/suffix surgery: Pre + "(LocalVariable VariableName=%Lk " + Post.
				int32 LocalId = INDEX_NONE;
				TArray<int32> PairEdits;   // edit indices to claim (writes + their inserts)
				bool bOk = true;
				for (const int32 Ci : Writes)
				{
					FString Name, CPre, CPost;
					SplitWrite(RC[Ci], Name, CPre, CPost);

					const int32 We = WriteEdit[Ci];
					int32 Found = INDEX_NONE;
					for (int32 f = 0; f < Edits.Num(); ++f)
					{
						if (Edits[f].K != EEdit::Ins || Edits[f].bClaimed || Edits[f].Hunk != Edits[We].Hunk) { continue; }
						const FString& R = RR[Edits[f].R];
						if (R.Len() <= CPre.Len() + CPost.Len()) { continue; }
						if (!R.StartsWith(CPre, ESearchCase::CaseSensitive) || !R.EndsWith(CPost, ESearchCase::CaseSensitive)) { continue; }
						const FString Mid = R.Mid(CPre.Len(), R.Len() - CPre.Len() - CPost.Len());
						static const FString LPx = TEXT("(LocalVariable VariableName=%L");
						if (!Mid.StartsWith(LPx, ESearchCase::CaseSensitive) || !Mid.EndsWith(TEXT(" "), ESearchCase::CaseSensitive)) { continue; }
						const FString Digits = Mid.Mid(LPx.Len(), Mid.Len() - LPx.Len() - 1);
						if (!IsAllDigits(Digits)) { continue; }
						const int32 Id = FCString::Atoi(*Digits);
						if (LocalId != INDEX_NONE && Id != LocalId) { continue; }   // D3: the SAME %L at all k sites
						LocalId = Id; Found = f; break;
					}
					if (Found == INDEX_NONE) { bOk = false; break; }
					PairEdits.Add(We);
					PairEdits.Add(Found);
					Edits[Found].bClaimed = true;   // provisional: reverted below if any later condition fails
				}
				auto Rollback = [&Edits, &PairEdits]()
				{
					for (const int32 e : PairEdits) { Edits[e].bClaimed = false; Edits[e].Reason.Empty(); }
				};
				if (!bOk || LocalId == INDEX_NONE) { Rollback(); continue; }

				// D4 — exactly ONE additional Insert: the copy of the local into the out-param, of the exact shape
				//   "(<Inst0> Expression=(LocalVariable VariableName=%L<LocalId> <TypeStr> ) Variable=(LocalOutVariable VariableName='P' <TypeStr> ) )".
				// Verified by re-using SplitWrite (so the LocalOutVariable half and the enclosing Let are parsed by the
				// SAME tested surgery, never a hand-built string that could silently drift from the emitter's spacing):
				//   * the out-param written is exactly P, and its type equals the write sites' type;
				//   * the expression is a LocalVariable of the SAME %L id and the SAME type.
				// A mistyped copy, a wrong local, or a wrong out-param can none of them match => stays REAL.
				// TypeStr already carries the LocalVariable sub-expression's own closing paren ("VariableType=<T> )"),
				// so it is followed directly by " Variable=" — no extra paren.
				const FString ExpectPre = FString::Printf(TEXT("(%s Expression=(LocalVariable VariableName=%%L%d %s Variable="),
					*Inst0, LocalId, *TypeStr);
				int32 CopyEdit = INDEX_NONE;
				int32 CopyCount = 0;
				for (int32 f = 0; f < Edits.Num(); ++f)
				{
					if (Edits[f].K != EEdit::Ins || Edits[f].bClaimed) { continue; }
					FString CName, CPre, CPost;
					if (!SplitWrite(RR[Edits[f].R], CName, CPre, CPost)) { continue; }
					if (CName != P) { continue; }
					if (CPost.LeftChop(2) != TypeStr) { continue; }   // the out-param's own type
					if (CPre != ExpectPre) { continue; }              // Inst0 + the %L<LocalId> LocalVariable expression
					++CopyCount; if (CopyEdit == INDEX_NONE) { CopyEdit = f; }
				}
				if (CopyCount != 1) { Rollback(); continue; }

				// D5 — the local is written only at the k sites and read only by D4's copy. The trailing space makes the
				// token exact: "%L1 " can never match "%L12 ".
				const FString LocalTok = FString::Printf(TEXT("VariableName=%%L%d "), LocalId);
				int32 LocalUses = 0;
				for (const FString& S : ReconLossy) { LocalUses += CountOccurrences(S, LocalTok); }
				if (LocalUses != Writes.Num() + 1) { Rollback(); continue; }

				// D6 — POST-DOMINANCE. With the copy cut out of the recon CFG, no EXIT may be reachable: a path that
				// returns without executing the copy leaves the out-param unwritten. "Exit" is a Return opcode OR
				// falling off the end (implicit return) — Simulate tracks BOTH in bExitReachable, because a branch that
				// jumps past the copy to the end is exactly the missing-copy-on-a-branch bug and it produces no Return
				// opcode. The write sites must also still be reachable, ruling out a degenerate "nothing is reachable,
				// so nothing exits" pass.
				const int32 CopyOrdinal = Edits[CopyEdit].R;
				const FSim RSim = Simulate(ReconLossy, CopyOrdinal);
				if (!RSim.bOk) { Rollback(); continue; }
				bool bPostDom = !RSim.bExitReachable;
				if (bPostDom)
				{
					for (int32 idx = 1; idx < PairEdits.Num(); idx += 2)   // the Insert of each write pair
					{
						if (!RSim.Reachable.Contains(Edits[PairEdits[idx]].R)) { bPostDom = false; break; }
					}
				}
				if (!bPostDom) { Rollback(); continue; }

				for (const int32 e : PairEdits) { Edits[e].bClaimed = true; Edits[e].Reason = TEXT("outparam"); }
				Edits[CopyEdit].bClaimed = true; Edits[CopyEdit].Reason = TEXT("outparam");
			}
		}

		// --- 7. composition (spec 2.5) — the conservative core -----------------------------------------------------
		// A rule must POSITIVELY claim an edit; the default is REAL. A function with one intentional drift and one real
		// bug is REAL — the bug is never masked by the intentional one. Silence is never consent.
		int32 FirstUnclaimed = INDEX_NONE;
		for (int32 e = 0; e < Edits.Num(); ++e)
		{
			if (!Edits[e].bClaimed) { FirstUnclaimed = e; break; }
		}

		if (FirstUnclaimed == INDEX_NONE)
		{
			V.bIntentional = true;
			for (const FEdit& E : Edits) { V.Reasons.AddUnique(E.Reason); }
			V.Reasons.Sort();
			// One audit sample per BP is surfaced by the caller (FirstIntentional) — spec 6.3 hand-verification.
			V.RootCookedOrdinal = Edits[0].C;
			V.RootReconOrdinal  = Edits[0].R;
			V.RootCooked = CookedLossy.IsValidIndex(Edits[0].C) ? CookedLossy[Edits[0].C] : FString(TEXT("<no counterpart>"));
			V.RootRecon  = ReconLossy.IsValidIndex(Edits[0].R)  ? ReconLossy[Edits[0].R]  : FString(TEXT("<no counterpart>"));
			return V;
		}

		// REAL. The root is the first UNCLAIMED edit in cooked-ordinal order — never a derived offset shift.
		const FEdit& Rt = Edits[FirstUnclaimed];
		V.bHasRoot = true;
		V.RootCookedOrdinal = Rt.C;
		V.RootReconOrdinal  = Rt.R;
		V.RootCooked = CookedLossy.IsValidIndex(Rt.C) ? CookedLossy[Rt.C] : FString(TEXT("<no counterpart>"));
		V.RootRecon  = ReconLossy.IsValidIndex(Rt.R)  ? ReconLossy[Rt.R]  : FString(TEXT("<no counterpart>"));

		if (CVarDriftCensus.GetValueOnAnyThread() != 0)
		{
			for (const FEdit& E : Edits)
			{
				if (E.bClaimed) { continue; }
				const FString CookedS = CookedLossy.IsValidIndex(E.C) ? CookedLossy[E.C] : FString();
				const FString ReconS  = ReconLossy.IsValidIndex(E.R)  ? ReconLossy[E.R]  : FString();
				CensusWrite(FString::Printf(TEXT("%s,%s,%s,%d,%d,%s,%s,%s,%s"),
					*CensusCell(BPName), *CensusCell(FuncName), EditKindName(E.K), E.C, E.R,
					*CensusCell(CookedS.IsEmpty() ? FString() : ShapeOf(CookedS)),
					*CensusCell(ReconS.IsEmpty()  ? FString() : ShapeOf(ReconS)),
					*CensusCell(CookedS), *CensusCell(ReconS)));
			}
		}

#if MIF_KR_DEBUG
		int32 NumClaimed = 0;
		for (const FEdit& E : Edits) { if (E.bClaimed) { ++NumClaimed; } }
		// Runtime state is never a guess: this says exactly how much of the drift a rule DID account for, so a
		// near-miss (claimed 9 of 10 edits) is visible rather than looking identical to "no rule fired at all".
		UE_LOG(LogMifKismetReconstructor, Verbose, TEXT("[classify] %s::%s REAL — root %s @ cooked=%d recon=%d (%d edits, %d claimed)"),
			*BPName, *FuncName, EditKindName(Rt.K), Rt.C, Rt.R, Edits.Num(), NumClaimed);
#endif
		return V;
	}
}
