// Implementation of the ubergraph slicer. Moved VERBATIM out of MifUbergraphAnalyzer.cpp's `#if MIF_KR_DEBUG`
// block (see MifUbergraphSlicer.h for why). Behaviour is unchanged from the Phase-1 sweep that proved it; the
// only edits are the ones the extraction forced:
//   - WalkEvent reports reached OFFSETS into a plain TSet instead of writing an analyzer-owned
//     offset→event-set map. The analyzer now merges that set into its own map, so [C] (per-event walk, own
//     stack, no shared pop-target state) is now structurally enforced rather than merely obeyed: this function
//     has no cross-event parameter to misuse.
//   - RecoverEvent additionally records the thunk's frame→param map (§1.4), which the analyzer never needed.
//     It is read from the SAME LetValueOnPersistentFrame statements the analyzer already counted as FrameLets.

#include "Analysis/MifUbergraphSlicer.h"
#include "MifReconstructorDebug.h"
#include "Toolkit/KismetBytecodeDisassemblerJson.h"

#include "Engine/LatentActionManager.h"   // FLatentActionInfo::StaticStruct() — the latent-call marker
#include "UObject/Class.h"
#include "UObject/Script.h"               // EExprToken
#include "Dom/JsonObject.h"
#include "Dom/JsonValue.h"

namespace MifUber
{
	const int32 GMaxWalkIterations = 200000;
	const int32 GMaxJsonDepth = 64;

	// ---------------------------------------------------------------------------------------------------
	// JSON helpers — every read is total. A missing/mistyped field degrades to a default, never asserts.
	// ---------------------------------------------------------------------------------------------------

	static FString GetStr(const TSharedPtr<FJsonObject>& Obj, const TCHAR* Field)
	{
		FString Out;
		if (Obj.IsValid()) { Obj->TryGetStringField(FString(Field), Out); }
		return Out;
	}

	static int32 GetNum(const TSharedPtr<FJsonObject>& Obj, const TCHAR* Field, int32 Default)
	{
		double Out = 0.0;
		if (Obj.IsValid() && Obj->TryGetNumberField(FString(Field), Out)) { return (int32) Out; }
		return Default;
	}

	// The compiler's ubergraph-call entry literal. KismetCompilerVMBackend.cpp:775-777 always emits EX_IntConst
	// (there is an un-actioned TODO about the smaller encodings), but accept the smaller forms anyway — cheap,
	// and immune to a differently-built third-party cook.
	static bool DecodeIntLiteral(const TSharedPtr<FJsonObject>& Expr, int32& OutValue)
	{
		if (!Expr.IsValid()) return false;
		const FString Inst = GetStr(Expr, TEXT("Inst"));
		if (Inst == TEXT("IntConst") || Inst == TEXT("IntConstByte") || Inst == TEXT("SkipOffsetConst"))
		{
			double Value = 0.0;
			if (!Expr->TryGetNumberField(FString(TEXT("Value")), Value)) return false;
			OutValue = (int32) Value;
			return true;
		}
		if (Inst == TEXT("IntZero")) { OutValue = 0; return true; }
		if (Inst == TEXT("IntOne"))  { OutValue = 1; return true; }
		return false;
	}

	// First element of a StructConst's per-property array (the disassembler emits ArrayDim elements per prop).
	static TSharedPtr<FJsonObject> GetStructProp(const TSharedPtr<FJsonObject>& Properties, const TCHAR* Name)
	{
		if (!Properties.IsValid()) return nullptr;
		const TArray<TSharedPtr<FJsonValue>>* Arr = nullptr;
		if (!Properties->TryGetArrayField(FString(Name), Arr) || !Arr || Arr->Num() == 0) return nullptr;
		const TSharedPtr<FJsonValue>& V = (*Arr)[0];
		return (V.IsValid() && V->Type == EJson::Object) ? V->AsObject() : nullptr;
	}

	// ---------------------------------------------------------------------------------------------------
	// Latent detection.
	//
	// EmitLatentInfoTerm (KismetCompilerVMBackend.cpp:1179-1226) emits the LatentInfo parameter as an
	// EX_StructConst of FLatentActionInfo, and — for the property tagged MD_NeedsLatentFixup, i.e. Linkage —
	// an EX_SkipOffsetConst routed through the SAME JumpTargetFixupMap as an ordinary jump. So Linkage is an
	// ABSOLUTE ubergraph byte offset, in the same coordinate space as EntryPoint. It is only emitted when
	// bIsUbergraph (:1386-1389), which is exactly why Delay cannot live in a plain function graph.
	//
	// Detected by the struct's PATH, not by any function-name heuristic.
	// ---------------------------------------------------------------------------------------------------

	struct FLatentHit
	{
		bool  bFound = false;
		int32 Linkage = -1;
		bool  bLinkageDecoded = false;
		bool  bTargetsThisFunction = false;
	};

	static void ScanForLatent(const TSharedPtr<FJsonObject>& Node, const FString& LatentStructPath,
		const FString& UberFuncName, int32 Depth, FLatentHit& InOut)
	{
		if (!Node.IsValid() || Depth > GMaxJsonDepth || InOut.bFound) return;

		if (GetStr(Node, TEXT("Inst")) == TEXT("StructConst") && GetStr(Node, TEXT("Struct")) == LatentStructPath)
		{
			InOut.bFound = true;

			const TSharedPtr<FJsonObject>* Props = nullptr;
			if (Node->TryGetObjectField(FString(TEXT("Properties")), Props) && Props)
			{
				const TSharedPtr<FJsonObject> ExecFn = GetStructProp(*Props, TEXT("ExecutionFunction"));
				InOut.bTargetsThisFunction = ExecFn.IsValid() && (GetStr(ExecFn, TEXT("Value")) == UberFuncName);

				const TSharedPtr<FJsonObject> Linkage = GetStructProp(*Props, TEXT("Linkage"));
				InOut.bLinkageDecoded = DecodeIntLiteral(Linkage, InOut.Linkage);
			}
			return;
		}

		// Generic recursion — the LatentInfo StructConst is a call PARAMETER, nested arbitrarily deep inside
		// Context/Let wrappers depending on the call shape. Walk every child value rather than guess a path.
		for (const TPair<FString, TSharedPtr<FJsonValue>>& KV : Node->Values)
		{
			if (InOut.bFound) return;
			const TSharedPtr<FJsonValue>& V = KV.Value;
			if (!V.IsValid()) continue;

			if (V->Type == EJson::Object)
			{
				ScanForLatent(V->AsObject(), LatentStructPath, UberFuncName, Depth + 1, InOut);
			}
			else if (V->Type == EJson::Array)
			{
				for (const TSharedPtr<FJsonValue>& E : V->AsArray())
				{
					if (InOut.bFound) return;
					if (E.IsValid() && E->Type == EJson::Object)
					{
						ScanForLatent(E->AsObject(), LatentStructPath, UberFuncName, Depth + 1, InOut);
					}
				}
			}
		}
	}

	// ---------------------------------------------------------------------------------------------------
	// Statement projection
	// ---------------------------------------------------------------------------------------------------

	void BuildStatements(const TArray<TSharedPtr<FJsonValue>>& RawStmts, const FString& LatentStructPath,
		const FString& UberFuncName, TArray<FUberStmt>& OutStmts, TMap<int32, int32>& OutIndexByOffset)
	{
		OutStmts.Reset();
		OutIndexByOffset.Reset();
		OutStmts.Reserve(RawStmts.Num());

		for (const TSharedPtr<FJsonValue>& V : RawStmts)
		{
			if (!V.IsValid() || V->Type != EJson::Object) continue;
			const TSharedPtr<FJsonObject> J = V->AsObject();

			FUberStmt S;
			S.Offset = GetNum(J, TEXT("StatementIndex"), -1);
			S.Inst = GetStr(J, TEXT("Inst"));
			if (S.Offset < 0) continue;

			if (S.Inst == TEXT("Jump"))                        { S.bUncondJump = true; S.JumpTarget = GetNum(J, TEXT("Offset"), -1); }
			else if (S.Inst == TEXT("JumpIfNot"))              { S.bCondJump = true;   S.JumpTarget = GetNum(J, TEXT("Offset"), -1); }
			else if (S.Inst == TEXT("PushExecutionFlow"))      { S.bPush = true;       S.PushTarget = GetNum(J, TEXT("Offset"), -1); }
			else if (S.Inst == TEXT("PopExecutionFlow"))       { S.bPop = true; }
			else if (S.Inst == TEXT("PopExecutionFlowIfNot"))  { S.bPopIfNot = true; }
			else if (S.Inst == TEXT("ComputedJump"))           { S.bComputedJump = true; }
			else if (S.Inst == TEXT("Return") || S.Inst == TEXT("EndOfScript")) { S.bTerminal = true; }

			FLatentHit Hit;
			ScanForLatent(J, LatentStructPath, UberFuncName, 0, Hit);
			if (Hit.bFound)
			{
				S.bLatent = true;
				// Only follow a resume that targets THIS ubergraph (mirrors the transformer's guard at :1110).
				if (Hit.bTargetsThisFunction && Hit.bLinkageDecoded) { S.LatentLinkage = Hit.Linkage; }
			}

			OutIndexByOffset.Add(S.Offset, OutStmts.Num());
			OutStmts.Add(MoveTemp(S));
		}
	}

	FPrologue DetectPrologue(const TArray<FUberStmt>& Stmts)
	{
		FPrologue P;
		if (Stmts.Num() == 0) { P.Kind = TEXT("Empty"); return P; }

		if (Stmts[0].bPush)
		{
			// PushReturnAddress (KismetCompilerVMBackend.cpp:2126-2132) — EX_PushExecutionFlow + placeholder
			// skip, patched to the ReturnStatement's label. Execution passes through it before the computed
			// jump, so this continuation IS on the stack at every event entry. [B]
			P.Offsets.Add(Stmts[0].Offset);
			if (Stmts[0].PushTarget >= 0) { P.InitialStack.Add(Stmts[0].PushTarget); }

			if (Stmts.Num() > 1 && Stmts[1].bComputedJump)
			{
				P.Offsets.Add(Stmts[1].Offset);
				P.Kind = TEXT("Push+ComputedJump");
				P.bSane = true;
			}
			else
			{
				P.Kind = FString::Printf(TEXT("Unexpected:Push+%s"),
					Stmts.Num() > 1 ? *Stmts[1].Inst : TEXT("<eof>"));
			}
			return P;
		}

		if (Stmts[0].bComputedJump)
		{
			// No flow stack anywhere in the merged graph → no return-address push. Stack really is empty here.
			P.Offsets.Add(Stmts[0].Offset);
			P.Kind = TEXT("ComputedJump");
			P.bSane = true;
			return P;
		}

		P.Kind = FString::Printf(TEXT("Unexpected:%s"), *Stmts[0].Inst);
		return P;
	}

	// ---------------------------------------------------------------------------------------------------
	// Per-event reachability walk.  [B] seeded with the real post-prologue stack.  [C] one walk per event, its
	// own stack, no shared pop-target map.
	// ---------------------------------------------------------------------------------------------------

	struct FWalkKey
	{
		int32 Offset = 0;
		int32 Depth = 0;
		int32 Top = 0;
		bool operator==(const FWalkKey& O) const { return Offset == O.Offset && Depth == O.Depth && Top == O.Top; }
	};
	FORCEINLINE uint32 GetTypeHash(const FWalkKey& K)
	{
		return HashCombine(HashCombine(::GetTypeHash(K.Offset), ::GetTypeHash(K.Depth)), ::GetTypeHash(K.Top));
	}

	struct FWalkState
	{
		int32 Offset = 0;
		TArray<int32> Stack;   // flow stack of absolute continuation offsets
	};

	FWalkResult WalkEvent(const TArray<FUberStmt>& Stmts, const TMap<int32, int32>& IndexByOffset,
		const FPrologue& Prologue, int32 EntryOffset, TSet<int32>& OutReached)
	{
		FWalkResult R;

		const int32* EntryIdx = IndexByOffset.Find(EntryOffset);
		if (!EntryIdx) { R.BadTargets++; return R; }

		TSet<FWalkKey> Visited;
		TArray<FWalkState> Work;
		Work.Add(FWalkState{ EntryOffset, Prologue.InitialStack });   // [B]

		int32 Guard = 0;
		while (Work.Num() > 0)
		{
			FWalkState State = Work.Pop();
			int32 Offset = State.Offset;
			TArray<int32> Stack = MoveTemp(State.Stack);

			while (true)
			{
				if (Guard++ >= GMaxWalkIterations) { R.bHitGuard = true; return R; }

				const int32* PIdx = IndexByOffset.Find(Offset);
				if (!PIdx) { R.BadTargets++; break; }
				const int32 Idx = *PIdx;
				if (!Stmts.IsValidIndex(Idx)) { R.BadTargets++; break; }

				const FWalkKey Key{ Offset, Stack.Num(), Stack.Num() > 0 ? Stack.Last() : -1 };
				if (Visited.Contains(Key)) break;
				Visited.Add(Key);

				bool bAlreadyReached = false;
				OutReached.Add(Offset, &bAlreadyReached);
				if (!bAlreadyReached) { R.Reached++; }

				const FUberStmt& S = Stmts[Idx];

				// A latent call's resume region belongs to THIS event's slice — the LatentActionManager
				// re-enters via ExecuteUbergraph_X(Linkage), i.e. a NEW FFrame that runs the prologue and
				// computed-jumps to Linkage. Same seed as an event entry. [B]
				if (S.bLatent && S.LatentLinkage >= 0)
				{
					if (IndexByOffset.Contains(S.LatentLinkage))
					{
						Work.Add(FWalkState{ S.LatentLinkage, Prologue.InitialStack });
					}
					else
					{
						R.BadTargets++;
					}
				}

				if (S.bTerminal) break;

				if (S.bComputedJump)
				{
					// Dynamic target. The prologue's computed jump is not in any slice; one reached from an
					// event body would be a genuine surprise, so count it rather than guess an edge.
					R.ComputedHits++;
					break;
				}

				if (S.bPush)
				{
					if (S.PushTarget >= 0 && IndexByOffset.Contains(S.PushTarget)) { Stack.Add(S.PushTarget); }
					else { R.BadTargets++; }
					// fall through to the next statement
				}
				else if (S.bPop)
				{
					if (Stack.Num() == 0) break;          // empty stack → thread ends
					Offset = Stack.Pop();                  // [C] resolved from THIS event's stack only
					continue;
				}
				else if (S.bPopIfNot)
				{
					if (Stack.Num() > 0)
					{
						TArray<int32> Popped = Stack;
						const int32 Top = Popped.Pop();
						Work.Add(FWalkState{ Top, MoveTemp(Popped) });   // !cond edge: pop + goto
					}
					// cond edge: fall through
				}
				else if (S.bUncondJump)
				{
					if (S.JumpTarget < 0 || !IndexByOffset.Contains(S.JumpTarget)) { R.BadTargets++; break; }
					Offset = S.JumpTarget;
					continue;
				}
				else if (S.bCondJump)
				{
					if (S.JumpTarget >= 0 && IndexByOffset.Contains(S.JumpTarget))
					{
						Work.Add(FWalkState{ S.JumpTarget, Stack });     // !cond edge
					}
					else
					{
						R.BadTargets++;
					}
					// cond edge: fall through
				}

				// linear fall-through
				if (!Stmts.IsValidIndex(Idx + 1)) break;
				Offset = Stmts[Idx + 1].Offset;
			}
		}
		return R;
	}

	// ---------------------------------------------------------------------------------------------------
	// Entry recovery.
	// ---------------------------------------------------------------------------------------------------

	// Reads the UFunction* operand of a final-function call at an EXACT statement boundary.
	// KismetCompilerVMBackend.cpp:1355-1358 emits `Writer << EX_FinalFunction; Writer << FunctionToCall;` and
	// FScriptBytecodeWriter::operator<<(UObject*&) (:86-93) widens it to ScriptPointerType (8 bytes, LE).
	// NOTE: the returned pointer is ONLY ever compared for identity — never dereferenced. A garbage value
	// therefore cannot crash us.
	static UFunction* ReadCallTargetAt(const TArray<uint8>& Script, int32 Offset)
	{
		if (!Script.IsValidIndex(Offset)) return nullptr;
		const uint8 Op = Script[Offset];
		if (Op != (uint8) EX_FinalFunction && Op != (uint8) EX_LocalFinalFunction) return nullptr;
		if (!Script.IsValidIndex(Offset + 8)) return nullptr;

		uint64 Ptr = 0;
		for (int32 b = 0; b < 8; ++b) { Ptr |= ((uint64) Script[Offset + 1 + b]) << (b * 8); }
		return (UFunction*) Ptr;
	}

	int32 CountRawPointerHits(const TArray<uint8>& Script, const UFunction* UberFunc)
	{
		const uint64 Needle = (uint64) (UPTRINT) UberFunc;
		int32 Hits = 0;
		for (int32 i = 0; i + 8 <= Script.Num(); ++i)
		{
			uint64 V = 0;
			for (int32 b = 0; b < 8; ++b) { V |= ((uint64) Script[i + b]) << (b * 8); }
			if (V == Needle) { ++Hits; }
		}
		return Hits;
	}

	EEventKind ClassifyEvent(const FString& Name)
	{
		if (Name.StartsWith(TEXT("BndEvt__")))                  return EEventKind::BndEvt;
		if (Name.StartsWith(TEXT("InpActEvt_")))                return EEventKind::InpActEvt;
		if (Name.StartsWith(TEXT("SequenceEvent__ENTRYPOINT"))) return EEventKind::SequenceEvent;
		return EEventKind::Event;
	}

	const TCHAR* KindName(EEventKind K)
	{
		switch (K)
		{
		case EEventKind::BndEvt:        return TEXT("BndEvt");
		case EEventKind::InpActEvt:     return TEXT("InpActEvt");
		case EEventKind::SequenceEvent: return TEXT("SequenceEvent");
		default:                        return TEXT("Event");
		}
	}

	// Recover an event's entry offset by DISASSEMBLING ITS THUNK — the only method that works for all event
	// shapes (KismetCompiler.cpp:3553-3742 builds the same stub for every one of them).
	//
	// UFunction::EventGraphCallOffset (Class.h:1806-1811) is real, serialized, and survives cooking — but it is
	// only populated under bIsSimpleStubGraphWithNoParams (KismetCompilerVMBackend.cpp:1277-1288), i.e. no-param
	// events only, and a fork built with UE_BLUEPRINT_EVENTGRAPH_FASTCALLS off discards it into throwaway locals
	// (Class.cpp:6690-6694). CROSS-CHECK ONLY. Never primary.
	bool RecoverEvent(UFunction* Thunk, UFunction* UberFunc, FEventEntry& Out)
	{
		if (!Thunk || !UberFunc) { Out.Status = TEXT("null-function"); return false; }

		Out.Name = Thunk->GetName();
		Out.Kind = ClassifyEvent(Out.Name);
		Out.FastCall = TEXT("n/a");

		// Thunk parameter names in declaration order — the zip target for the frame map (§1.4).
		TArray<FName> ThunkParams;
		for (TFieldIterator<FProperty> It(Thunk); It && (It->PropertyFlags & CPF_Parm); ++It)
		{
			if (!It->HasAnyPropertyFlags(CPF_ReturnParm)) { Out.NumParams++; ThunkParams.Add(It->GetFName()); }
		}

		Out.RawPtrHits = CountRawPointerHits(Thunk->Script, UberFunc);

		FKismetBytecodeDisassemblerJson Dis;
		const TArray<TSharedPtr<FJsonValue>> Stmts = Dis.SerializeFunction(Thunk);

		int32 DecodedOffset = -1;
		bool bFoundCall = false;
		bool bLiteralDecoded = false;

		for (const TSharedPtr<FJsonValue>& V : Stmts)
		{
			if (!V.IsValid() || V->Type != EJson::Object) continue;
			const TSharedPtr<FJsonObject> S = V->AsObject();
			const FString Inst = GetStr(S, TEXT("Inst"));

			if (Inst == TEXT("LetValueOnPersistentFrame") && !bFoundCall)
			{
				Out.FrameLets++;

				// §1.4 — the thunk's own authoritative param map:
				//   EX_LetValueOnPersistentFrame(<FrameProp>, EX_LocalVariable(<ThunkParam>))
				// Take the pair the bytecode states. If the inner expression is not a plain LocalVariable (an
				// event shape we have not seen), record NOTHING for it rather than guess — a missing entry
				// degrades that one pin to a variable read; a WRONG entry silently mis-wires the event.
				const FName FrameProp(*GetStr(S, TEXT("PropertyName")));
				const TSharedPtr<FJsonObject>* Expr = nullptr;
				if (FrameProp != NAME_None && S->TryGetObjectField(FString(TEXT("Expression")), Expr) && Expr
					&& GetStr(*Expr, TEXT("Inst")) == TEXT("LocalVariable"))
				{
					const FName ThunkParam(*GetStr(*Expr, TEXT("VariableName")));
					if (ThunkParam != NAME_None && ThunkParams.Contains(ThunkParam))
					{
						Out.FrameParamMap.Add(TPair<FName, FName>(FrameProp, ThunkParam));
					}
				}
				continue;
			}
			if (Inst != TEXT("FinalFunction") && Inst != TEXT("LocalFinalFunction")) continue;

			// IDENTITY match on the resolved pointer — not the name, not the memcmp. This is the
			// authoritative confirmation that Thunk is an event thunk for THIS ubergraph.
			const int32 StmtOffset = GetNum(S, TEXT("StatementIndex"), -1);
			if (ReadCallTargetAt(Thunk->Script, StmtOffset) != UberFunc) continue;

			Out.IdentityCalls++;
			if (bFoundCall) continue;   // keep the FIRST call; extras are counted, not merged
			bFoundCall = true;

			const TArray<TSharedPtr<FJsonValue>>* Params = nullptr;
			if (S->TryGetArrayField(FString(TEXT("Parameters")), Params) && Params && Params->Num() > 0)
			{
				const TSharedPtr<FJsonValue>& P0 = (*Params)[0];
				if (P0.IsValid() && P0->Type == EJson::Object)
				{
					bLiteralDecoded = DecodeIntLiteral(P0->AsObject(), DecodedOffset);
				}
			}
		}

		if (!bFoundCall)
		{
			Out.Status = Dis.bDisassemblyFailed ? TEXT("thunk-disasm-failed") : TEXT("no-ubergraph-call");
			return false;
		}
		if (!bLiteralDecoded)
		{
			Out.Status = TEXT("entry-literal-not-an-int-const");
			return false;
		}

		Out.EntryOffset = DecodedOffset;

		// The VM itself asserts this range (ScriptCore.cpp:2541), so anything outside it is corrupt.
		if (DecodedOffset < 0 || DecodedOffset >= UberFunc->Script.Num())
		{
			Out.Status = FString::Printf(TEXT("entry-out-of-range:%d/%d"), DecodedOffset, UberFunc->Script.Num());
			return false;
		}
		// [A] Offset 0 is the prologue push (or, with no flow stack, the computed jump) — never an event body.
		// A still-zero offset means the compiler's patchup never ran (KismetCompiler.cpp:3718-3721 defaults it
		// to "0"): a failed unit, not "entry at 0".
		if (DecodedOffset == 0)
		{
			Out.Status = TEXT("entry-is-zero(unpatched)");
			return false;
		}

#if UE_BLUEPRINT_EVENTGRAPH_FASTCALLS
		if (Thunk->EventGraphFunction == UberFunc)
		{
			Out.FastCall = (Thunk->EventGraphCallOffset == DecodedOffset)
				? FString(TEXT("match"))
				: FString::Printf(TEXT("mismatch:%d"), Thunk->EventGraphCallOffset);
		}
#endif

		Out.Status = TEXT("OK");
		Out.bRecovered = true;
		return true;
	}
}
